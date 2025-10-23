"""
High-level SWu controller built on top of the original `swu_emulator` utilities.

The module exposes two classes:

- :class:`ePDGIKEv2` orchestrates the IKEv2 control plane with the ePDG.  It reuses
  the proven implementation from ``swu_emulator`` but strips out the legacy user-
  plane handling based on raw ESP sockets.
- :class:`ePDGIPSec` manages the IPsec data plane using an XFRM virtual interface
  (xfrmi) so the kernel encrypts user traffic instead of the Python
  helpers.

The classes are intentionally thin - the goal is to keep the complex IKEv2
negotiation logic in one place while exposing a cleaner API for future tooling.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional, Sequence
import ipaddress
from socket import AF_INET, AF_UNSPEC, SOCK_DGRAM, gaierror, getaddrinfo, IPPROTO_UDP

from swu_emulator import (
    AUTH_HMAC_MD5_96,
    AUTH_HMAC_SHA1_96,
    AUTH_HMAC_SHA2_256_128,
    AUTH_HMAC_SHA2_384_192,
    AUTH_HMAC_SHA2_512_256,
    CFG_REQUEST,
    CREATE_CHILD_SA,
    D_H,
    ENCR,
    ENCR_NULL,
    ENCR_AES_CBC,
    ENCR_AES_GCM_8,
    ENCR_AES_GCM_12,
    ENCR_AES_GCM_16,
    ESP,
    ESP_PROTOCOL,
    ESN,
    ESN_NO_ESN,
    DEFAULT_IKE_PORT,
    DEFAULT_IKE_NAT_TRAVERSAL_PORT,
    IKE,
    INTERNAL_IP4_ADDRESS,
    INTERNAL_IP4_DNS,
    INTERNAL_IP6_ADDRESS,
    INTERNAL_IP6_DNS,
    P_CSCF_IP4_ADDRESS,
    P_CSCF_IP6_ADDRESS,
    INFORMATIONAL,
    KEY_LENGTH,
    MODP_768_bit,
    MODP_1024_bit,
    MODP_1536_bit,
    MODP_2048_bit,
    MODP_3072_bit,
    MODP_4096_bit,
    MODP_6144_bit,
    MODP_8192_bit,
    NONE,
    NAT_TRAVERSAL,
    OK,
    PRF,
    PRF_HMAC_SHA1,
    REPEAT_STATE,
    REPEAT_STATE_COOKIE,
    TSI,
    TSR,
    TS_IPV4_ADDR_RANGE,
    TS_IPV6_ADDR_RANGE,
    ANY,
    INTEG,
    TIMEOUT,
    swu,
)


logger = logging.getLogger(__name__)


class _NullPipe:
    """Simple stand-in for the legacy inter-process pipe."""

    def send(self, *_args, **_kwargs) -> None:
        logger.debug("NullPipe: discard payload")


@dataclass
class ChildSAParams:
    """Relevant pieces of information for programming the XFRM dataplane."""

    spi_out: int  # SPI used when UE sends traffic to ePDG (responder SPI)
    spi_in: int  # SPI expected when ePDG sends traffic to UE (initiator SPI)
    encr_alg: int
    encr_key_out: bytes
    encr_key_in: bytes
    integ_alg: int
    integ_key_out: bytes
    integ_key_in: bytes


@dataclass
class SessionConfig:
    """Data returned by :class:`ePDGIKEv2` once the control plane is up."""

    local_public_ip: str
    remote_public_ip: str
    local_inner_ipv4: Sequence[str]
    local_inner_ipv6: Sequence[str]
    dns_servers_v4: Sequence[str]
    dns_servers_v6: Sequence[str]
    pcscf_servers_v4: Sequence[str]
    pcscf_servers_v6: Sequence[str]
    child_sa: ChildSAParams
    userplane_mode: int
    ts_local: Sequence[tuple]
    ts_remote: Sequence[tuple]
    xfrm_if_id: Optional[int] = None
    xfrm_ifname: Optional[str] = None
    nat_src_port: Optional[int] = None
    nat_dst_port: Optional[int] = None


def _to_hex(data: bytes) -> str:
    return "0x" + data.hex()


def _spi_bytes_to_int(spi: bytes) -> int:
    return int.from_bytes(spi, byteorder="big", signed=False)


def _resolve_epdg_address(hostname: str) -> str:
    """
    Resolve the ePDG FQDN to an IPv4 address using the system resolver.

    Prefer IPv4 addresses (AF_INET); fall back to whatever the resolver returns.
    """

    def _query(family: int) -> list[tuple]:
        try:
            return getaddrinfo(hostname, None, family, SOCK_DGRAM)
        except gaierror:
            return []

    candidates = _query(AF_INET) or _query(AF_UNSPEC)
    if not candidates:
        raise RuntimeError(f"Unable to resolve ePDG hostname '{hostname}' via system resolver")
    # getaddrinfo returns tuples: (family, type, proto, canonname, sockaddr)
    for family, _type, _proto, _canon, sockaddr in candidates:
        if family == AF_INET:
            return sockaddr[0]
    # fallback - return the first address as a string
    return candidates[0][4][0]


class ePDGIKEv2:
    """
    Thin wrapper around :class:`swu_emulator.swu` that exposes a friendlier API.

    The class intentionally reuses the proven IKEv2 implementation.  The only
    responsibility here is to drive the state machine, capture the resulting
    parameters, and keep the SA alive until the application shuts down.
    """

    _SUPPORTED_DH_GROUPS = {
        1: MODP_768_bit,
        2: MODP_1024_bit,
        5: MODP_1536_bit,
        14: MODP_2048_bit,
        15: MODP_3072_bit,
        16: MODP_4096_bit,
        17: MODP_6144_bit,
        18: MODP_8192_bit,
    }

    def __init__(
        self,
        *,
        source_address: str,
        epdg_address: str,
        apn: str,
        imsi: str,
        ki: str,
        op: Optional[str] = None,
        opc: Optional[str] = None,
        mcc: Optional[str] = None,
        mnc: Optional[str] = None,
        ip_versions: Optional[Sequence[int]] = None,
        dh_groups: Optional[Sequence[int]] = None,
    ) -> None:
        if not (op or opc):
            raise ValueError("Either OP or OPC must be provided for Milenage.")

        resolved_epdg = _resolve_epdg_address(epdg_address)

        if mcc is None or mnc is None:
            derived_mcc = imsi[:3] if len(imsi) >= 3 else "001"
            remaining = imsi[3:] if len(imsi) > 3 else ""
            if len(remaining) >= 3:
                derived_mnc = remaining[:3]
            elif len(remaining) >= 2:
                derived_mnc = remaining[:2]
            else:
                derived_mnc = "01"
            if mcc is None:
                mcc = derived_mcc
            if mnc is None:
                mnc = derived_mnc
        mcc = str(mcc)
        mnc = str(mnc).zfill(3)

        self._ip_versions = self._normalise_ip_versions(ip_versions)
        self._dh_groups = self._normalise_dh_groups(dh_groups)

        # Instantiate the legacy helper but neutralise user-plane assumptions.
        self._ike = swu(
            source_address,
            resolved_epdg,
            apn,
            modem=None,
            default_gateway=None,
            mcc=mcc,
            mnc=mnc,
            imsi=imsi,
            ki=ki,
            op=op,
            opc=opc,
            sqn=None,
            netns=None,
        )
        self._ike.ike_to_ipsec_encoder = _NullPipe()
        self._ike.ike_to_ipsec_decoder = _NullPipe()
        self._ike.set_sa_list(self._build_ike_sa_list())
        self._ike.set_sa_list_child(self._default_child_sa_list())
        self._ike.set_ts_list(TSI, self._build_ts_initiator())
        self._ike.set_ts_list(TSR, self._build_ts_responder())
        self._ike.set_cp_list(self._build_cp_list())
        self._assign_dynamic_ports()
        self._enable_udp_encap()
        self._session: Optional[SessionConfig] = None
        self._running = False
        self._epdg_hostname = epdg_address
        self._epdg_ip = resolved_epdg
        self._mcc = mcc
        self._mnc = mnc

    # ------------------------------------------------------------------ helpers

    def _enable_udp_encap(self) -> None:
        """
        Ensure UDP encapsulation is enabled when operating in NAT-T mode.

        The legacy helper always opens the NAT socket; enabling the option here
        keeps inbound ESP-in-UDP packets properly decapsulated by the kernel.
        """

        udp_encap = getattr(socket, "UDP_ENCAP", 100)
        udp_encap_espinudp = getattr(socket, "UDP_ENCAP_ESPINUDP", 2)
        sock = getattr(self._ike, "socket_nat", None)
        if not sock:
            logger.debug("IKE helper does not expose socket_nat - skipping UDP_ENCAP setup")
            return
        try:
            sock.setsockopt(IPPROTO_UDP, udp_encap, udp_encap_espinudp)
            logger.debug("Enabled UDP_ENCAP_ESPINUDP on NAT-T socket")
        except OSError as exc:  # pragma: no cover - depends on kernel support
            logger.warning("Failed to enable UDP_ENCAP_ESPINUDP on NAT-T socket: %s", exc)

    def _assign_dynamic_ports(self) -> None:
        """Bind IKE and NAT sockets to ephemeral local ports to allow parallel runs."""

        ike = self._ike

        def _bind_unique(exclude: set[int]) -> tuple[socket.socket, int]:
            for _ in range(16):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.bind((ike.source_address, 0))
                except OSError as exc:
                    logger.debug("Failed to bind UDP socket for dynamic port (ignored): %s", exc)
                    sock.close()
                    continue
                port = sock.getsockname()[1]
                if port in exclude:
                    sock.close()
                    continue
                sock.settimeout(ike.timeout)
                return sock, port
            raise RuntimeError("Unable to allocate UDP port for IKE sockets")

        # Rebind main IKE socket
        try:
            ike.socket.close()
        except Exception:  # pragma: no cover - best effort
            pass
        ike_socket, ike_port = _bind_unique(set())
        ike.port = ike_port
        ike.client_address = (ike.source_address, ike_port)
        ike.server_address = (ike.epdg_address, DEFAULT_IKE_PORT)
        ike.socket = ike_socket

        # Rebind NAT-T socket - avoid reusing the same port if possible
        try:
            ike.socket_nat.close()
        except Exception:  # pragma: no cover - best effort
            pass
        nat_socket, nat_port = _bind_unique({ike_port})
        ike.port_nat = nat_port
        ike.client_address_nat = (ike.source_address, nat_port)
        ike.server_address_nat = (ike.epdg_address, DEFAULT_IKE_NAT_TRAVERSAL_PORT)
        ike.socket_nat = nat_socket

        logger.info(
            "Using dynamic IKE ports: main=%s, nat=%s",
            ike_port,
            nat_port,
        )

    @staticmethod
    def _default_child_sa_list() -> list:
        return [
            [
                [ESP, 4],
                [ENCR, ENCR_AES_GCM_8, [KEY_LENGTH, 256]],
                [INTEG, NONE],
                [ESN, ESN_NO_ESN],
            ],
            [
                [ESP, 4],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 128]],
                [INTEG, AUTH_HMAC_SHA2_256_128],
                [ESN, ESN_NO_ESN],
            ],
            [
                [ESP, 4],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 256]],
                [INTEG, AUTH_HMAC_SHA2_384_192],
                [ESN, ESN_NO_ESN],
            ],
            [
                [ESP, 4],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 256]],
                [INTEG, AUTH_HMAC_SHA2_512_256],
                [ESN, ESN_NO_ESN],
            ],
            [
                [ESP, 4],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 256]],
                [INTEG, AUTH_HMAC_MD5_96],
                [ESN, ESN_NO_ESN],
            ],
            [
                [ESP, 4],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 128]],
                [INTEG, AUTH_HMAC_SHA1_96],
                [ESN, ESN_NO_ESN],
            ],
            [
                [ESP, 4],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 256]],
                [INTEG, AUTH_HMAC_SHA1_96],
                [ESN, ESN_NO_ESN],
            ],
        ]

    def _normalise_ip_versions(self, ip_versions: Optional[Sequence[int]]) -> tuple[int, ...]:
        if ip_versions is None:
            versions = {4, 6}
        else:
            try:
                versions = {int(ver) for ver in ip_versions}
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid --ip value(s): {ip_versions}") from exc
        if not versions:
            raise ValueError("At least one IP version must be requested.")
        if not versions.issubset({4, 6}):
            invalid = versions - {4, 6}
            raise ValueError(f"Unsupported IP version(s) requested: {sorted(invalid)}")
        return tuple(sorted(versions))

    def _normalise_dh_groups(self, dh_groups: Optional[Sequence[int]]) -> tuple[int, ...]:
        if dh_groups is None:
            groups = (14,)
        else:
            try:
                provided = [int(group) for group in dh_groups]
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid --dh value(s): {dh_groups}") from exc
            if not provided:
                raise ValueError("At least one Diffie-Hellman group must be provided.")
            groups = tuple(dict.fromkeys(provided))
        invalid = [group for group in groups if group not in self._SUPPORTED_DH_GROUPS]
        if invalid:
            raise ValueError(f"Unsupported Diffie-Hellman group(s): {invalid}")
        return tuple(self._SUPPORTED_DH_GROUPS[group] for group in groups)

    def _build_ike_sa_list(self) -> list:
        proposals: list[list[list]] = []
        for group in self._dh_groups:
            proposals.append(
                [
                    [IKE, 0],
                    [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 128]],
                    [PRF, PRF_HMAC_SHA1],
                    [INTEG, AUTH_HMAC_SHA1_96],
                    [D_H, group],
                ]
            )
        return proposals

    def _build_ts_initiator(self) -> list:
        ts_entries: list[list] = []
        if 4 in self._ip_versions:
            ts_entries.append([TS_IPV4_ADDR_RANGE, ANY, 0, 65535, "0.0.0.0", "255.255.255.255"])
        if 6 in self._ip_versions:
            ts_entries.append([TS_IPV6_ADDR_RANGE, ANY, 0, 65535, "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"])
        return ts_entries

    def _build_ts_responder(self) -> list:
        ts_entries: list[list] = []
        if 4 in self._ip_versions:
            ts_entries.append([TS_IPV4_ADDR_RANGE, ANY, 0, 65535, "0.0.0.0", "255.255.255.255"])
        if 6 in self._ip_versions:
            ts_entries.append([TS_IPV6_ADDR_RANGE, ANY, 0, 65535, "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"])
        return ts_entries

    def _build_cp_list(self) -> list:
        cp_items: list[list] = [CFG_REQUEST]
        if 4 in self._ip_versions:
            cp_items.extend(
                [
                    [INTERNAL_IP4_ADDRESS],
                    [INTERNAL_IP4_DNS],
                    [P_CSCF_IP4_ADDRESS],
                ]
            )
        if 6 in self._ip_versions:
            cp_items.extend(
                [
                    [INTERNAL_IP6_ADDRESS],
                    [INTERNAL_IP6_DNS],
                    [P_CSCF_IP6_ADDRESS],
                ]
            )
        return cp_items

    def _drive_state_machine(self) -> None:
        ike = self._ike
        iterations = 2
        ike.cookie = False

        while iterations > 0:
            iterations -= 1

            result = ike.state_1()
            if result[0] in (REPEAT_STATE, TIMEOUT):
                logger.warning("STATE 1 retry (reason: %s)", result[1])
                result = ike.state_1(retry=True)
            elif result[0] == REPEAT_STATE_COOKIE:
                logger.warning("STATE 1 cookie retry")
                result = ike.state_1(retry=True, cookie=True)

            if result[0] in (REPEAT_STATE, TIMEOUT):
                logger.warning("STATE 1 final retry")
                if ike.cookie:
                    result = ike.state_1(retry=True, cookie=True)
                else:
                    result = ike.state_1(retry=True)

            if result[0] != OK:
                logger.error("IKE_SA_INIT failed: %s", result[1])
                continue

            result = ike.state_2()
            if result[0] == REPEAT_STATE:
                logger.info("STATE 2 repeat requested - re-sending")
                result = ike.state_2(retry=True)
            if result[0] != OK:
                logger.error("IKE_AUTH (EAP step 1) failed: %s", result[1])
                continue

            result = ike.state_3()
            if result[0] == REPEAT_STATE:
                logger.info("STATE 3 repeat requested - re-sending")
                result = ike.state_3()
            if result[0] != OK:
                logger.error("IKE_AUTH (EAP step 2) failed: %s", result[1])
                continue

            result = ike.state_4()
            if result[0] != OK:
                logger.error("IKE_AUTH (final) failed: %s", result[1])
                continue

            # We are connected - gather parameters and leave.
            self._session = self._collect_session()
            logger.info("IKEv2 session established with %s", ike.server_address[0])
            return

        raise RuntimeError("IKEv2 negotiation failed after all retries.")

    def _collect_session(self) -> SessionConfig:
        ike = self._ike
        child = ChildSAParams(
            spi_out=_spi_bytes_to_int(ike.spi_resp_child),
            spi_in=_spi_bytes_to_int(ike.spi_init_child),
            encr_alg=ike.negotiated_encryption_algorithm_child,
            encr_key_out=ike.SK_IPSEC_EI,
            encr_key_in=ike.SK_IPSEC_ER,
            integ_alg=ike.negotiated_integrity_algorithm_child,
            integ_key_out=ike.SK_IPSEC_AI,
            integ_key_in=ike.SK_IPSEC_AR,
        )

        local_inner_ipv4 = list(ike.ip_address_list or [])
        local_inner_ipv6 = list(getattr(ike, "ipv6_address_list", []) or [])
        dns_v4 = list(ike.dns_address_list or [])
        dns_v6 = list(getattr(ike, "dnsv6_address_list", []) or [])
        pcscf_v4 = list(getattr(ike, "pcscf_address_list", []) or [])
        pcscf_v6 = list(getattr(ike, "pcscfv6_address_list", []) or [])
        ts_local = list(getattr(ike, "ts_list_initiator_negotiated", []) or [])
        ts_remote = list(getattr(ike, "ts_list_responder_negotiated", []) or [])
        if_name = getattr(ike, "xfrm_interface_name", None)
        if_id = getattr(ike, "xfrm_if_id", None)
        nat_src_port = getattr(ike, "port_nat", None)
        nat_dst_port = None
        if getattr(ike, "server_address_nat", None):
            nat_dst_port = ike.server_address_nat[1]
        return SessionConfig(
            local_public_ip=ike.source_address,
            remote_public_ip=ike.epdg_address,
            local_inner_ipv4=local_inner_ipv4,
            local_inner_ipv6=local_inner_ipv6,
            dns_servers_v4=dns_v4,
            dns_servers_v6=dns_v6,
            pcscf_servers_v4=pcscf_v4,
            pcscf_servers_v6=pcscf_v6,
            child_sa=child,
            userplane_mode=ike.userplane_mode,
            ts_local=ts_local,
            ts_remote=ts_remote,
            xfrm_if_id=if_id,
            xfrm_ifname=if_name,
            nat_src_port=nat_src_port,
            nat_dst_port=nat_dst_port,
        )

    # ----------------------------------------------------------------- public API

    @property
    def session(self) -> SessionConfig:
        if not self._session:
            raise RuntimeError("IKE session is not established yet.")
        return self._session

    def connect(self) -> SessionConfig:
        """Run the complete IKEv2 exchange and return negotiated parameters."""
        self._drive_state_machine()
        return self.session

    def keep_alive(self) -> None:
        """
        Minimal event loop that keeps the IKE SA alive.

        The loop tolerates timeouts and simply logs unsolicited CREATE_CHILD_SA
        attempts as unsupported for the simplified helper.
        """
        ike = self._ike
        self._running = True
        sock = ike.socket if ike.userplane_mode == ESP_PROTOCOL else ike.socket_nat

        logger.info("Entering keep-alive loop - press Ctrl+C to terminate.")
        while self._running:
            try:
                sock.settimeout(5.0)
                packet, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                logger.debug("Socket closed: %s", exc)
                break

            if addr[0] != ike.server_address[0]:
                logger.debug("Ignoring packet from unexpected peer %s", addr)
                continue

            if ike.userplane_mode == NAT_TRAVERSAL and packet.startswith(b"\x00\x00\x00\x00"):
                ike.decode_ike(packet[4:])
            else:
                ike.decode_ike(packet)

            if not ike.ike_decoded_ok:
                logger.warning("Failed to decode inbound IKE packet")
                continue

            exch = ike.ike_decoded_header.get("exchange_type")
            if exch == INFORMATIONAL:
                logger.info("Received INFORMATIONAL request - sending delete ack")
                response = ike.answer_INFORMATIONAL_delete()
                ike.send_data(response)
                self._running = False
            elif exch == CREATE_CHILD_SA:
                logger.info("CREATE_CHILD_SA not supported in helper - sending NO_PROPOSAL_CHOSEN")
                notify = ike.answer_NOTIFY_NO_PROPOSAL_CHOSEN()
                ike.send_data(notify)
            else:
                logger.info("Ignoring unsupported exchange type %s", exch)

    def shutdown(self) -> None:
        """Attempt to gracefully remove the IKE SA without killing the process."""
        ike = self._ike
        try:
            ike.message_id_request += 1
            packet = ike.create_INFORMATIONAL_delete(IKE)
            if ike.userplane_mode == NAT_TRAVERSAL:
                sock = getattr(ike, "socket_nat", None)
                if sock:
                    sock.sendto(b"\x00" * 4 + packet, ike.server_address_nat)
                else:
                    logger.debug("Skipping INFORMATIONAL delete (NAT socket unavailable).")
            else:
                sock = getattr(ike, "socket", None)
                if sock:
                    sock.sendto(packet, ike.server_address)
                else:
                    logger.debug("Skipping INFORMATIONAL delete (IKE socket unavailable).")
        except (OSError, AttributeError) as exc:
            logger.debug("Skipping INFORMATIONAL delete (socket unavailable): %s", exc)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to send DELETE INFORMATIONAL")
        finally:
            try:
                ike.socket.close()
            except Exception:  # pylint: disable=broad-except
                pass
            else:
                ike.socket = None
            try:
                ike.socket_nat.close()
            except Exception:  # pylint: disable=broad-except
                pass
            else:
                ike.socket_nat = None


class ePDGIPSec:
    """
    Configure a tunnel-mode ESP SA pair via Linux XFRM and an xfrmi interface.

    The dataplane programs per-SA state bound to the interface (route-based)
    and avoids legacy VTI/policy usage. All operations are idempotent.
    """

    AUTH_ALG_MAP = {
        AUTH_HMAC_SHA1_96: ("hmac(sha1)", 96),
        AUTH_HMAC_SHA2_256_128: ("hmac(sha256)", 128),
        AUTH_HMAC_SHA2_384_192: ("hmac(sha384)", 192),
        AUTH_HMAC_SHA2_512_256: ("hmac(sha512)", 256),
    }

    ENCR_ALG_MAP = {
        ENCR_AES_CBC: ("block", "aes"),
        ENCR_AES_GCM_8: ("aead", "rfc4106(gcm(aes))", 64),
        ENCR_AES_GCM_12: ("aead", "rfc4106(gcm(aes))", 96),
        ENCR_AES_GCM_16: ("aead", "rfc4106(gcm(aes))", 128),
    }

    DEFAULT_REPLAY_WINDOW = 64

    def __init__(
        self,
        *,
        interface: str,
        if_id: int,
        mtu: int = 1380,
        ping_target: Optional[str] = None,
        monitor_interval: float = 0.0,
        monitor_fail_threshold: int = 3,
        replay_window: int = DEFAULT_REPLAY_WINDOW,
    ) -> None:
        self.interface = interface
        self.if_id = if_id
        self.mtu = mtu
        self.ping_target_override = ping_target
        self.ping_interval = max(0.0, monitor_interval)
        self.ping_fail_threshold = monitor_fail_threshold
        self.replay_window = replay_window
        self.active = False
        self._session: Optional[SessionConfig] = None
        self._assigned_ipv4: list[str] = []
        self._assigned_ipv6: list[str] = []
        self._installed_routes_v4: list[str] = []
        self._installed_routes_v6: list[str] = []
        self._installed_policies: list[tuple[str, str, str]] = []
        self._routing_rules: list[tuple[str, str, int]] = []
        self._routing_tables: set[tuple[str, int]] = set()
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_stop = threading.Event()
        self._monitor_target: Optional[str] = None
        self._monitor_source: Optional[str] = None
        self._monitor_failures = 0

    # ---------------------------------------------------------------- utilities

    def _run(
        self,
        command: Sequence[str],
        *,
        ignore_errors: Sequence[str] = (),
        ignore_returncodes: Sequence[int] = (),
        suppress_error_log: bool = False,
    ) -> subprocess.CompletedProcess:
        cmd = list(command)
        cmd_str = " ".join(cmd)
        logger.debug("Running command: %s", cmd_str)
        result = subprocess.run(cmd, capture_output=True, text=True)
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        if stdout:
            logger.debug("stdout: %s", stdout)
        if stderr:
            logger.debug("stderr: %s", stderr)
        if result.returncode and result.returncode not in ignore_returncodes:
            if not any(err and err in stderr for err in ignore_errors):
                if not suppress_error_log:
                    logger.error("Command failed (rc=%s): %s", result.returncode, cmd_str)
                    if stderr:
                        logger.error("stderr: %s", stderr)
                raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout, stderr=result.stderr)
            logger.debug("Ignoring error for command %s (rc=%s, stderr=%s)", cmd_str, result.returncode, stderr)
        return result

    def _ensure_interface(self, interface: str, if_id: int) -> None:
        name = interface or "xfrm0"
        if if_id is None:
            raise ValueError("if_id must be provided")
        self.interface = name
        self.if_id = if_id
        self._run(["ip", "link", "add", name, "type", "xfrm", "if_id", str(if_id)])
        if self.mtu:
            self._run(["ip", "link", "set", "dev", name, "mtu", str(self.mtu)])
        self._run(["ip", "link", "set", name, "up"])

    @staticmethod
    def _range_to_network(start: str, end: str) -> Optional[ipaddress._BaseNetwork]:
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        if start_ip.version != end_ip.version:
            return None
        bits = start_ip.max_prefixlen
        diff = int(start_ip) ^ int(end_ip)
        prefix = bits - diff.bit_length()
        if prefix < 0:
            prefix = 0
        return ipaddress.ip_network(f"{start}/{prefix}", strict=False)

    def _ts_prefixes(self, ts_list: Sequence[tuple], family: int) -> list[str]:
        prefixes: list[str] = []
        for ts in ts_list or []:
            ts_type = ts[0]
            if family == 4 and ts_type != TS_IPV4_ADDR_RANGE:
                continue
            if family == 6 and ts_type != TS_IPV6_ADDR_RANGE:
                continue
            network = self._range_to_network(ts[4], ts[5])
            if network:
                prefixes.append(str(network))
        return list(dict.fromkeys(prefixes))

    def _match_prefix(self, address: str, ts_list: Sequence[tuple]) -> Optional[int]:
        ip = ipaddress.ip_address(address)
        for ts in ts_list or []:
            network = self._range_to_network(ts[4], ts[5])
            if network and ip.version == network.version and ip in network:
                return network.prefixlen
        return None

    def _configure_addresses(self, session: SessionConfig) -> None:
        if not self.interface:
            raise ValueError("XFRM interface name is not set")
        self._assigned_ipv4.clear()
        self._assigned_ipv6.clear()
        v4_seen: set[str] = set()
        for addr in session.local_inner_ipv4:
            if addr in v4_seen:
                continue
            v4_seen.add(addr)
            prefix = self._match_prefix(addr, session.ts_local) or 32
            cidr = f"{addr}/{prefix}"
            self._run(["ip", "addr", "replace", cidr, "dev", self.interface])
            self._assigned_ipv4.append(cidr)
        v6_seen: set[str] = set()
        for addr in session.local_inner_ipv6:
            if addr in v6_seen:
                continue
            v6_seen.add(addr)
            prefix = self._match_prefix(addr, session.ts_local) or 128
            cidr = f"{addr}/{prefix}"
            self._run(["ip", "-6", "addr", "replace", cidr, "dev", self.interface])
            self._assigned_ipv6.append(cidr)

    def _configure_routes(self, session: SessionConfig) -> None:
        if not self.interface:
            raise ValueError("XFRM interface name is not set")
        self._installed_routes_v4.clear()
        self._installed_routes_v6.clear()
        v4_routes: list[str] = []
        if session.local_inner_ipv4:
            prefixes = self._ts_prefixes(session.ts_remote, 4) or ["0.0.0.0/0"]
            for prefix in prefixes:
                if prefix == "0.0.0.0/0":
                    v4_routes.extend(["0.0.0.0/1", "128.0.0.0/1"])
                else:
                    v4_routes.append(prefix)
        for route in dict.fromkeys(v4_routes):
            self._run(["ip", "route", "replace", route, "dev", self.interface])
            self._installed_routes_v4.append(route)
        v6_routes: list[str] = []
        if session.local_inner_ipv6:
            prefixes = self._ts_prefixes(session.ts_remote, 6) or ["::/0"]
            for prefix in prefixes:
                if prefix == "::/0":
                    v6_routes.extend(["::/1", "8000::/1"])
                else:
                    v6_routes.append(prefix)
        for route in dict.fromkeys(v6_routes):
            self._run(["ip", "-6", "route", "replace", route, "dev", self.interface])
            self._installed_routes_v6.append(route)

    def _select_inner_family(self, session: SessionConfig) -> Optional[str]:
        has_v4 = bool(session.local_inner_ipv4)
        has_v6 = bool(session.local_inner_ipv6)
        if has_v6 and not has_v4:
            return "inet6"
        if has_v4 and not has_v6:
            return "inet"
        ts_types = {ts[0] for ts in session.ts_local or []}
        if TS_IPV6_ADDR_RANGE in ts_types and TS_IPV4_ADDR_RANGE not in ts_types:
            return "inet6"
        if TS_IPV4_ADDR_RANGE in ts_types and TS_IPV6_ADDR_RANGE not in ts_types:
            return "inet"
        return None

    def _selector_family(self, session: SessionConfig) -> Optional[int]:
        family = self._select_inner_family(session)
        if family == "inet6":
            return 6
        if family == "inet":
            return 4
        if session.local_inner_ipv6:
            return 6
        if session.local_inner_ipv4:
            return 4
        ts_types = {ts[0] for ts in session.ts_local or []}
        if TS_IPV6_ADDR_RANGE in ts_types:
            return 6
        if TS_IPV4_ADDR_RANGE in ts_types:
            return 4
        return None

    @staticmethod
    def _selector_default(family: int) -> str:
        return "::/0" if family == 6 else "0.0.0.0/0"

    def _selector_from_local(self, session: SessionConfig, family: int) -> str:
        return self._selector_default(family)

    def _selector_from_remote(self, session: SessionConfig, family: int) -> str:
        return self._selector_default(family)

    def _install_states(self, session: SessionConfig) -> None:
        if self.if_id is None:
            raise ValueError("XFRM if_id is not configured")
        child = session.child_sa
        if child.encr_alg not in self.ENCR_ALG_MAP:
            raise ValueError(f"Encryption algorithm {child.encr_alg} is not supported yet.")
        enc_type = self.ENCR_ALG_MAP[child.encr_alg]
        reqid = child.spi_out & 0xFFFFFFFF

        # Remove any stale states with matching SPI values prior to programming new ones.
        self._cleanup_states(session)

        def _extend(cmd1: list[str], cmd2: list[str], args: list[str]) -> None:
            cmd1.extend(args)
            cmd2.extend(args)

        outbound_update_cmd = [
            "ip",
            "xfrm",
            "state",
            "update",
            "src",
            session.local_public_ip,
            "dst",
            session.remote_public_ip,
            "proto",
            "esp",
            "spi",
            f"{child.spi_out:#010x}",
            "mode",
            "tunnel",
            "if_id",
            str(self.if_id),
            "reqid",
            str(reqid),
            "replay-window",
            str(self.replay_window),
        ]
        outbound_add_cmd = outbound_update_cmd.copy()
        outbound_add_cmd[3] = "add"

        inbound_update_cmd = [
            "ip",
            "xfrm",
            "state",
            "update",
            "src",
            session.remote_public_ip,
            "dst",
            session.local_public_ip,
            "proto",
            "esp",
            "spi",
            f"{child.spi_in:#010x}",
            "mode",
            "tunnel",
            "if_id",
            str(self.if_id),
            "reqid",
            str(reqid),
            "replay-window",
            str(self.replay_window),
        ]
        inbound_add_cmd = inbound_update_cmd.copy()
        inbound_add_cmd[3] = "add"

        if enc_type[0] == "block":
            if child.integ_alg not in self.AUTH_ALG_MAP:
                raise ValueError(f"Integrity algorithm {child.integ_alg} is not supported yet.")
            auth_name, trunc_len = self.AUTH_ALG_MAP[child.integ_alg]
            if trunc_len:
                auth_out = ["auth-trunc", auth_name, _to_hex(child.integ_key_out), str(trunc_len)]
                auth_in = ["auth-trunc", auth_name, _to_hex(child.integ_key_in), str(trunc_len)]
            else:
                auth_out = ["auth", auth_name, _to_hex(child.integ_key_out)]
                auth_in = ["auth", auth_name, _to_hex(child.integ_key_in)]
            _extend(outbound_update_cmd, outbound_add_cmd, auth_out + ["enc", enc_type[1], _to_hex(child.encr_key_out)])
            _extend(inbound_update_cmd, inbound_add_cmd, auth_in + ["enc", enc_type[1], _to_hex(child.encr_key_in)])
        else:
            if child.integ_alg not in (NONE,):
                logger.warning("Ignoring integrity algorithm %s for AEAD cipher", child.integ_alg)
            aead_name = enc_type[1]
            icv_bits = enc_type[2]
            key_bits = (len(child.encr_key_out) - 4) * 8
            _extend(outbound_update_cmd, outbound_add_cmd, ["aead", aead_name, _to_hex(child.encr_key_out), str(icv_bits), str(key_bits)])
            _extend(inbound_update_cmd, inbound_add_cmd, ["aead", aead_name, _to_hex(child.encr_key_in), str(icv_bits), str(key_bits)])

        if session.userplane_mode == NAT_TRAVERSAL:
            sport = session.nat_src_port or 4500
            dport = session.nat_dst_port or 4500
            _extend(outbound_update_cmd, outbound_add_cmd, ["encap", "espinudp", str(sport), str(dport), session.remote_public_ip])
            _extend(inbound_update_cmd, inbound_add_cmd, ["encap", "espinudp", str(dport), str(sport), session.local_public_ip])

        selector_family = self._selector_family(session)
        if selector_family is None:
            selector_family = 6 if session.local_inner_ipv6 else 4
        sel_out_src = self._selector_from_local(session, selector_family)
        sel_out_dst = self._selector_from_remote(session, selector_family)
        sel_in_src = self._selector_from_remote(session, selector_family)
        sel_in_dst = self._selector_from_local(session, selector_family)
        _extend(outbound_update_cmd, outbound_add_cmd, ["sel", "src", sel_out_src, "dst", sel_out_dst])
        _extend(inbound_update_cmd, inbound_add_cmd, ["sel", "src", sel_in_src, "dst", sel_in_dst])

        logger.info("Programming outbound XFRM state: %s", " ".join(outbound_update_cmd))
        self._run_state_cmd(outbound_update_cmd, outbound_add_cmd)
        logger.info("Programming inbound XFRM state: %s", " ".join(inbound_update_cmd))
        self._run_state_cmd(inbound_update_cmd, inbound_add_cmd)

    def _run_state_cmd(self, update_cmd: list[str], add_cmd: list[str]) -> None:
        try:
            self._run(update_cmd, suppress_error_log=True)
            return
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").lower()
            if "no such file or directory" in stderr or "no such object" in stderr or "no such process" in stderr:
                logger.info("XFRM state missing during update - attempting to create with add.")
            else:
                raise

        logger.info("Programming XFRM state via add: %s", " ".join(add_cmd))
        self._run(add_cmd)

    def _install_policies(self, session: SessionConfig) -> None:
        if self.if_id is None:
            raise ValueError("XFRM if_id is not configured")
        selector_family = self._selector_family(session)
        if selector_family is None:
            selector_family = 6 if session.local_inner_ipv6 else 4
        reqid = session.child_sa.spi_out & 0xFFFFFFFF

        src_sel_out = self._selector_from_local(session, selector_family)
        dst_sel_out = self._selector_from_remote(session, selector_family)
        src_sel_in = self._selector_from_remote(session, selector_family)
        dst_sel_in = self._selector_from_local(session, selector_family)

        out_update_cmd = [
            "ip",
            "xfrm",
            "policy",
            "update",
            "src",
            src_sel_out,
            "dst",
            dst_sel_out,
            "dir",
            "out",
            "tmpl",
            "src",
            session.local_public_ip,
            "dst",
            session.remote_public_ip,
            "proto",
            "esp",
            "mode",
            "tunnel",
            "reqid",
            str(reqid),
            "if_id",
            str(self.if_id),
        ]
        out_add_cmd = out_update_cmd.copy()
        out_add_cmd[3] = "add"

        in_update_cmd = [
            "ip",
            "xfrm",
            "policy",
            "update",
            "src",
            src_sel_in,
            "dst",
            dst_sel_in,
            "dir",
            "in",
            "tmpl",
            "src",
            session.remote_public_ip,
            "dst",
            session.local_public_ip,
            "proto",
            "esp",
            "mode",
            "tunnel",
            "reqid",
            str(reqid),
            "if_id",
            str(self.if_id),
        ]
        in_add_cmd = in_update_cmd.copy()
        in_add_cmd[3] = "add"

        logger.info("Programming outbound XFRM policy: %s", " ".join(out_update_cmd))
        self._run_policy_cmd(out_update_cmd, out_add_cmd)
        self._record_policy("out", src_sel_out, dst_sel_out)

        logger.info("Programming inbound XFRM policy: %s", " ".join(in_update_cmd))
        self._run_policy_cmd(in_update_cmd, in_add_cmd)

    def _install_policy_routing(self, session: SessionConfig) -> None:
        if self.if_id is None:
            return
        table = self.if_id & 0xFFFF
        if session.local_inner_ipv4:
            self._run(["ip", "route", "replace", "default", "dev", self.interface, "table", str(table)])
            self._routing_tables.add(("ipv4", table))
        if session.local_inner_ipv6:
            self._run(["ip", "-6", "route", "replace", "default", "dev", self.interface, "table", str(table)])
            self._routing_tables.add(("ipv6", table))
        for addr in session.local_inner_ipv4:
            self._run(
                ["ip", "rule", "add", "from", addr, "table", str(table)],
                ignore_errors=("File exists",),
            )
            self._routing_rules.append(("ipv4", addr, table))
        for addr in session.local_inner_ipv6:
            self._run(
                ["ip", "-6", "rule", "add", "from", addr, "table", str(table)],
                ignore_errors=("File exists",),
            )
            self._routing_rules.append(("ipv6", addr, table))

    def _cleanup_policy_routing(self) -> None:
        for family, addr, table in self._routing_rules:
            if family == "ipv4":
                cmd = ["ip", "rule", "del", "from", addr, "table", str(table)]
            else:
                cmd = ["ip", "-6", "rule", "del", "from", addr, "table", str(table)]
            self._run(cmd, ignore_errors=("Cannot find", "No such process", "RTNETLINK answers: No such process"))
        self._routing_rules.clear()
        if not self.interface:
            self._routing_tables.clear()
            return
        for family, table in self._routing_tables:
            if family == "ipv4":
                cmd = ["ip", "route", "del", "default", "dev", self.interface, "table", str(table)]
            else:
                cmd = ["ip", "-6", "route", "del", "default", "dev", self.interface, "table", str(table)]
            self._run(cmd, ignore_errors=("Cannot find", "No such process", "RTNETLINK answers: No such process"))
        self._routing_tables.clear()

    def _run_policy_cmd(self, update_cmd: list[str], add_cmd: list[str]) -> None:
        try:
            self._run(update_cmd, suppress_error_log=True)
            return
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").lower()
            if "no such file or directory" in stderr or "no such object" in stderr or "no such process" in stderr or "not found" in stderr:
                logger.info("XFRM policy missing during update - attempting to create with add.")
            else:
                raise
        logger.info("Programming XFRM policy via add: %s", " ".join(add_cmd))
        self._run(add_cmd)

    def _record_policy(self, direction: str, src_sel: str, dst_sel: str) -> None:
        key = (direction, src_sel, dst_sel)
        if key not in self._installed_policies:
            self._installed_policies.append(key)

    def _select_ping_target(self, session: SessionConfig) -> Optional[str]:
        if self.ping_target_override:
            return self.ping_target_override
        if session.pcscf_servers_v6:
            return session.pcscf_servers_v6[0]
        if session.dns_servers_v6:
            return session.dns_servers_v6[0]
        return None

    def _start_monitor(self, session: SessionConfig) -> None:
        self._stop_monitor()
        if self.ping_interval <= 0:
            logger.info("Connectivity monitor disabled (interval <= 0)")
            return
        target = self._select_ping_target(session)
        if not target:
            logger.info("Skipping connectivity monitor - no IPv6 target available")
            return
        inner_v6 = session.local_inner_ipv6
        if not inner_v6:
            logger.info("Skipping connectivity monitor - no inner IPv6 address available")
            return
        if not self.interface:
            logger.info("Skipping connectivity monitor - interface not configured")
            return
        self._monitor_target = target
        self._monitor_source = inner_v6[0]
        self._monitor_failures = 0
        self._monitor_stop.clear()
        thread = threading.Thread(target=self._monitor_loop, name=f"ipsec-ping-{self.interface}", daemon=True)
        self._monitor_thread = thread
        thread.start()
        logger.info("Started IPv6 connectivity monitor towards %s", target)

    def _stop_monitor(self) -> None:
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_stop.set()
            if threading.current_thread() is not self._monitor_thread:
                self._monitor_thread.join(timeout=5)
        self._monitor_thread = None
        self._monitor_target = None
        self._monitor_source = None
        self._monitor_failures = 0
        self._monitor_stop.clear()

    def _monitor_loop(self) -> None:
        while not self._monitor_stop.is_set():
            success, rtt, output = self._run_ping()
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            if success:
                self._monitor_failures = 0
                if rtt is not None:
                    logger.info(
                        "Ping monitor %s -> %s via %s: %.3f ms (%s)",
                        self._monitor_source,
                        self._monitor_target,
                        self.interface,
                        rtt,
                        timestamp,
                    )
                else:
                    logger.info(
                        "Ping monitor %s -> %s via %s: success (%s)",
                        self._monitor_source,
                        self._monitor_target,
                        self.interface,
                        timestamp,
                    )
            else:
                self._monitor_failures += 1
                logger.warning(
                    "Ping monitor %s -> %s via %s: no reply (%d/%d) (%s)",
                    self._monitor_source,
                    self._monitor_target,
                    self.interface,
                    self._monitor_failures,
                    self.ping_fail_threshold,
                    timestamp,
                )
                if output:
                    logger.debug("ping output: %s", output.strip())
                if self._monitor_failures >= self.ping_fail_threshold:
                    self._handle_monitor_failure()
                    break
            if self._monitor_stop.wait(self.ping_interval):
                break

    def _run_ping(self) -> tuple[bool, Optional[float], str]:
        if not self._monitor_target or not self.interface:
            return False, None, ""
        cmd = ["ping", "-6", "-n", "-c", "1", "-W", "3"]
        if self.interface:
            cmd.extend(["-I", self.interface])
        if self._monitor_target:
            cmd.append(self._monitor_target)
        else:
            return False, None, ""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            logger.error("ping utility is not available - disabling connectivity monitor")
            self._monitor_stop.set()
            return False, None, ""
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            match = re.search(r"time[=<]([0-9.]+)\s*ms", output)
            rtt = float(match.group(1)) if match else None
            return True, rtt, output
        return False, None, output

    def _handle_monitor_failure(self) -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        logger.error(
            "Ping monitor detected connectivity loss to %s after %d consecutive failures (%s)",
            self._monitor_target,
            self._monitor_failures,
            timestamp,
        )
        self._monitor_stop.set()
        logger.warning("Connectivity lost - stopping dataplane. Please restart the script to re-establish the tunnel.")
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:  # pragma: no cover - best effort shutdown
            logger.exception("Failed to terminate process after connectivity loss")
            os._exit(2)

    def _cleanup_states(self, session: SessionConfig) -> None:
        child = session.child_sa
        cmds = [
            [
                "ip",
                "xfrm",
                "state",
                "delete",
                "src",
                session.local_public_ip,
                "dst",
                session.remote_public_ip,
                "proto",
                "esp",
                "spi",
                f"{child.spi_out:#010x}",
            ],
            [
                "ip",
                "xfrm",
                "state",
                "delete",
                "src",
                session.remote_public_ip,
                "dst",
                session.local_public_ip,
                "proto",
                "esp",
                "spi",
                f"{child.spi_in:#010x}",
            ],
        ]
        for cmd in cmds:
            self._run(cmd, ignore_errors=("No such file or directory", "No such process", "No such object"))

    def _cleanup_policies(self) -> None:
        for direction, src_sel, dst_sel in self._installed_policies:
            cmd = [
                "ip",
                "xfrm",
                "policy",
                "delete",
                "src",
                src_sel,
                "dst",
                dst_sel,
                "dir",
                direction,
            ]
            self._run(
                cmd,
                ignore_errors=(
                    "No such file or directory",
                    "No such process",
                    "No such object",
                    "not found",
                    "No such policy",
                ),
            )
        self._installed_policies.clear()

    # ----------------------------------------------------------------- public API

    def activate(self, session: SessionConfig) -> None:
        if self.active:
            logger.info("Re-activating IPsec - cleaning previous configuration")
            self.cleanup()
        interface = session.xfrm_ifname or self.interface or "xfrm0"
        if_id = session.xfrm_if_id if session.xfrm_if_id is not None else self.if_id
        if if_id is None:
            raise ValueError("XFRM if_id is required for dataplane activation")
        self.interface = interface
        self.if_id = if_id
        self._session = session

        logger.info("Configuring xfrm interface %s (if_id=%s)", interface, if_id)
        self._ensure_interface(interface, if_id)
        interface = self.interface
        if_id = self.if_id
        self._configure_addresses(session)
        self._configure_routes(session)
        self._installed_policies.clear()
        self._install_states(session)
        self._install_policies(session)
        self._routing_rules.clear()
        self._routing_tables.clear()
        self._install_policy_routing(session)
        self.active = True
        self._start_monitor(session)
        logger.info("IPsec dataplane configured on %s", self.interface)

    def cleanup(self) -> None:
        if not self._session and not self.active:
            self._stop_monitor()
            interface = self.interface
            if interface:
                self._run(["ip", "link", "del", interface], ignore_errors=("Cannot find device", "No such device"))
            self.active = False
            return

        session = self._session
        interface = self.interface
        logger.info("Cleaning up IPsec dataplane (%s)", interface or "unknown")
        self._stop_monitor()
        if session:
            self._cleanup_policy_routing()
            self._cleanup_policies()
            self._cleanup_states(session)
        if interface:
            for route in self._installed_routes_v6:
                self._run(["ip", "-6", "route", "del", route, "dev", interface], ignore_errors=("No such process", "No such file or directory", "Cannot find device"))
            for route in self._installed_routes_v4:
                self._run(["ip", "route", "del", route, "dev", interface], ignore_errors=("No such process", "No such file or directory", "Cannot find device"))
            for addr in self._assigned_ipv6:
                self._run(["ip", "-6", "addr", "del", addr, "dev", interface], ignore_errors=("Cannot find device", "Cannot assign requested address"))
        for addr in self._assigned_ipv4:
            self._run(["ip", "addr", "del", addr, "dev", interface], ignore_errors=("Cannot find device", "Cannot assign requested address"))
        if interface:
            self._run(["ip", "link", "del", interface], ignore_errors=("Cannot find device", "No such device"))
        self._assigned_ipv4.clear()
        self._assigned_ipv6.clear()
        self._installed_routes_v4.clear()
        self._installed_routes_v6.clear()
        self.active = False
        self._session = None


def main(argv: Optional[Sequence[str]] = None) -> None:
    """
    Minimal CLI entry-point for manual testing.

    Example:
        python -m swu_new.swu_new --source 192.0.2.10 --epdg 203.0.113.5 \\
            --apn internet --imsi 001010123456789 --ki 465b5ce8b199b49faa5f0a2ee238a6bc \\
            --opc 9e375a9b2e3f36d4191b2d4782 --interface xfrm0
    """

    import argparse

    parser = argparse.ArgumentParser(description="Simplified SWu controller")
    parser.add_argument("--source", required=True, help="Local public IP")
    parser.add_argument("--epdg", required=True, help="ePDG address (IP)")
    parser.add_argument("--apn", required=True, help="APN to request")
    parser.add_argument("--imsi", required=True, help="IMSI for EAP-AKA")
    parser.add_argument("--ki", required=True, help="MilenaGE Ki value (hex)")
    parser.add_argument("--op", help="MilenaGE OP value (hex)")
    parser.add_argument("--opc", help="MilenaGE OPC value (hex)")
    parser.add_argument("--mcc", help="Override MCC (three digits)")
    parser.add_argument("--mnc", help="Override MNC (two or three digits)")
    parser.add_argument("-i", "--interface", required=True, help="XFRM interface name")
    parser.add_argument("-id", "--if-id", required=True, type=int, help="XFRM interface identifier")
    parser.add_argument(
        "--ping",
        type=float,
        default=0.0,
        help="Enable connectivity probes every N seconds (0 disables the monitor).",
    )
    parser.add_argument(
        "--ip",
        action="append",
        help="Requested IP version(s) for tunnel inner addresses (4, 6). Specify multiple times or comma-separated.",
    )
    parser.add_argument(
        "--dh",
        action="append",
        help="Diffie-Hellman group list for IKE_SA proposals (comma-separated). Default: 14.",
    )

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    def _parse_numeric_list(values: Optional[list[str]], name: str) -> Optional[list[int]]:
        if not values:
            return None
        tokens: list[str] = []
        for entry in values:
            tokens.extend(part.strip() for part in entry.split(",") if part.strip())
        if not tokens:
            return []
        try:
            return [int(token) for token in tokens]
        except ValueError as exc:
            parser.error(f"Invalid value for --{name}: {exc}")  # parser.error exits
        return None  # Unreachable, satisfies mypy/linters

    ip_versions = _parse_numeric_list(args.ip, "ip")
    dh_groups = _parse_numeric_list(args.dh, "dh")

    ike = ePDGIKEv2(
        source_address=args.source,
        epdg_address=args.epdg,
        apn=args.apn,
        imsi=args.imsi,
        ki=args.ki,
        op=args.op,
        opc=args.opc,
        mcc=args.mcc,
        mnc=args.mnc,
        ip_versions=ip_versions,
        dh_groups=dh_groups,
    )
    session = ike.connect()

    ipsec = ePDGIPSec(interface=args.interface, if_id=args.if_id, monitor_interval=args.ping)
    ipsec.activate(session)

    def _cleanup(signum, _frame) -> None:  # pragma: no cover - signal handler
        logger.info("Received signal %s - shutting down", signum)
        ike.shutdown()
        ipsec.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    try:
        ike.keep_alive()
    finally:
        ike.shutdown()
        ipsec.cleanup()


if __name__ == "__main__":
    main()
