"""
High-level SWu controller built on top of the original `swu_emulator` utilities.

The module exposes two classes:

- :class:`ePDGIKEv2` orchestrates the IKEv2 control plane with the ePDG.  It reuses
  the proven implementation from ``swu_emulator`` but strips out the legacy user-
  plane handling based on raw ESP sockets.
- :class:`ePDGIPSec` manages the IPsec data plane using Linux XFRM in tunnel mode
  with a VTI interface, so the kernel encrypts user traffic instead of the Python
  helpers.

The classes are intentionally thin – the goal is to keep the complex IKEv2
negotiation logic in one place while exposing a cleaner API for future tooling.
"""

from __future__ import annotations

import logging
import signal
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional, Sequence
import ipaddress

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
    IKE,
    INTERNAL_IP4_ADDRESS,
    INTERNAL_IP4_DNS,
    INTERNAL_IP6_ADDRESS,
    INTERNAL_IP6_DNS,
    P_CSCF_IP4_ADDRESS,
    P_CSCF_IP6_ADDRESS,
    INFORMATIONAL,
    KEY_LENGTH,
    MODP_1024_bit,
    MODP_2048_bit,
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
    """Relevant pieces of information for programming XFRM/VTI."""

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
    child_sa: ChildSAParams
    userplane_mode: int
    ts_local: Sequence[tuple]
    ts_remote: Sequence[tuple]


def _to_hex(data: bytes) -> str:
    return "0x" + data.hex()


def _spi_bytes_to_int(spi: bytes) -> int:
    return int.from_bytes(spi, byteorder="big", signed=False)


class ePDGIKEv2:
    """
    Thin wrapper around :class:`swu_emulator.swu` that exposes a friendlier API.

    The class intentionally reuses the proven IKEv2 implementation.  The only
    responsibility here is to drive the state machine, capture the resulting
    parameters, and keep the SA alive until the application shuts down.
    """

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
        default_gateway: Optional[str] = None,
        netns: Optional[str] = None,
    ) -> None:
        if not (op or opc):
            raise ValueError("Either OP or OPC must be provided for Milenage.")

        try:
            resolved_epdg = socket.gethostbyname(epdg_address)
        except OSError as exc:
            raise RuntimeError(f"Unable to resolve ePDG hostname '{epdg_address}': {exc}") from exc

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

        # Instantiate the legacy helper but neutralise user-plane assumptions.
        self._ike = swu(
            source_address,
            resolved_epdg,
            apn,
            modem=None,
            default_gateway=default_gateway,
            mcc=mcc,
            mnc=mnc,
            imsi=imsi,
            ki=ki,
            op=op,
            opc=opc,
            netns=netns,
            sqn=None,
        )
        self._ike.ike_to_ipsec_encoder = _NullPipe()
        self._ike.ike_to_ipsec_decoder = _NullPipe()
        self._ike.set_sa_list(self._default_sa_list())
        self._ike.set_sa_list_child(self._default_child_sa_list())
        self._ike.set_ts_list(TSI, self._default_ts_initiator())
        self._ike.set_ts_list(TSR, self._default_ts_responder())
        self._ike.set_cp_list(self._default_cp_list())
        self._session: Optional[SessionConfig] = None
        self._running = False
        self._epdg_hostname = epdg_address
        self._epdg_ip = resolved_epdg
        self._mcc = mcc
        self._mnc = mnc

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _default_sa_list() -> list:
        return [
            [
                [IKE, 0],
                [ENCR, ENCR_NULL],
                [PRF, PRF_HMAC_SHA1],
                [INTEG, AUTH_HMAC_SHA1_96],
                [D_H, MODP_1024_bit],
            ],
            [
                [IKE, 0],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 128]],
                [PRF, PRF_HMAC_SHA1],
                [INTEG, AUTH_HMAC_SHA1_96],
                [D_H, MODP_2048_bit],
            ],
            [
                [IKE, 0],
                [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 128]],
                [PRF, PRF_HMAC_SHA1],
                [INTEG, AUTH_HMAC_SHA1_96],
                [D_H, MODP_1024_bit],
            ],
        ]

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

    @staticmethod
    def _default_ts_initiator() -> list:
        return [
            [TS_IPV4_ADDR_RANGE, ANY, 0, 65535, "0.0.0.0", "255.255.255.255"],
            [TS_IPV6_ADDR_RANGE, ANY, 0, 65535, "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ]

    @staticmethod
    def _default_ts_responder() -> list:
        return [
            [TS_IPV4_ADDR_RANGE, ANY, 0, 65535, "0.0.0.0", "255.255.255.255"],
            [TS_IPV6_ADDR_RANGE, ANY, 0, 65535, "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ]

    @staticmethod
    def _default_cp_list() -> list:
        return [
            CFG_REQUEST,
            [INTERNAL_IP4_ADDRESS],
            [INTERNAL_IP4_DNS],
            [INTERNAL_IP6_ADDRESS],
            [INTERNAL_IP6_DNS],
            [P_CSCF_IP4_ADDRESS],
            [P_CSCF_IP6_ADDRESS],
        ]

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
                logger.info("STATE 2 repeat requested – re-sending")
                result = ike.state_2(retry=True)
            if result[0] != OK:
                logger.error("IKE_AUTH (EAP step 1) failed: %s", result[1])
                continue

            result = ike.state_3()
            if result[0] == REPEAT_STATE:
                logger.info("STATE 3 repeat requested – re-sending")
                result = ike.state_3()
            if result[0] != OK:
                logger.error("IKE_AUTH (EAP step 2) failed: %s", result[1])
                continue

            result = ike.state_4()
            if result[0] != OK:
                logger.error("IKE_AUTH (final) failed: %s", result[1])
                continue

            # We are connected – gather parameters and leave.
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
        ts_local = list(getattr(ike, "ts_list_initiator_negotiated", []) or [])
        ts_remote = list(getattr(ike, "ts_list_responder_negotiated", []) or [])
        return SessionConfig(
            local_public_ip=ike.source_address,
            remote_public_ip=ike.epdg_address,
            local_inner_ipv4=local_inner_ipv4,
            local_inner_ipv6=local_inner_ipv6,
            dns_servers_v4=dns_v4,
            dns_servers_v6=dns_v6,
            child_sa=child,
            userplane_mode=ike.userplane_mode,
            ts_local=ts_local,
            ts_remote=ts_remote,
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

        logger.info("Entering keep-alive loop – press Ctrl+C to terminate.")
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
                logger.info("Received INFORMATIONAL request – sending delete ack")
                response = ike.answer_INFORMATIONAL_delete()
                ike.send_data(response)
                self._running = False
            elif exch == CREATE_CHILD_SA:
                logger.info("CREATE_CHILD_SA not supported in helper – sending NO_PROPOSAL_CHOSEN")
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
            ike.send_data(packet)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to send DELETE INFORMATIONAL")
        finally:
            try:
                ike.socket.close()
            except Exception:  # pylint: disable=broad-except
                pass
            try:
                ike.socket_nat.close()
            except Exception:  # pylint: disable=broad-except
                pass


class ePDGIPSec:
    """
    Configure a tunnel-mode ESP SA pair via Linux XFRM and a VTI interface.

    Only IPv4 is covered for the initial implementation.  Support for additional
    algorithms can be added by extending the mapping dictionaries below.
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

    def __init__(self, *, interface: str = "vti0") -> None:
        self.interface = interface
        self.active = False
        self._session: Optional[SessionConfig] = None

    # ---------------------------------------------------------------- utilities

    @staticmethod
    def _run(command: Sequence[str]) -> None:
        logger.debug("Running command: %s", " ".join(command))
        subprocess.run(command, check=True)  # nosec B603

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

    def _policy_specs(self, session: SessionConfig) -> list[tuple[str, str, str, list[str]]]:
        specs: list[tuple[str, str, str, list[str]]] = []
        tmpl_out = ["tmpl", "src", session.local_public_ip, "dst", session.remote_public_ip, "proto", "esp", "mode", "tunnel"]
        tmpl_in = ["tmpl", "src", session.remote_public_ip, "dst", session.local_public_ip, "proto", "esp", "mode", "tunnel"]

        if session.local_inner_ipv4:
            v4_dsts = self._ts_prefixes(session.ts_remote, 4) or ["0.0.0.0/0"]
            v4_srcs = []
            for addr in session.local_inner_ipv4:
                prefix = self._match_prefix(addr, session.ts_local) or 32
                v4_srcs.append(f"{addr}/{prefix}")
            for src in dict.fromkeys(v4_srcs):
                for dst in v4_dsts:
                    specs.append(("out", src, dst, tmpl_out))
                    specs.append(("in", dst, src, tmpl_in))
                    specs.append(("fwd", dst, src, tmpl_in))

        if session.local_inner_ipv6:
            v6_dsts = self._ts_prefixes(session.ts_remote, 6) or ["::/0"]
            v6_srcs = []
            for addr in session.local_inner_ipv6:
                prefix = self._match_prefix(addr, session.ts_local) or 128
                v6_srcs.append(f"{addr}/{prefix}")
            for src in dict.fromkeys(v6_srcs):
                for dst in v6_dsts:
                    specs.append(("out", src, dst, tmpl_out))
                    specs.append(("in", dst, src, tmpl_in))
                    specs.append(("fwd", dst, src, tmpl_in))

        return specs

    def _install_states(self, session: SessionConfig) -> None:
        child = session.child_sa

        if child.encr_alg not in self.ENCR_ALG_MAP:
            raise ValueError(f"Encryption algorithm {child.encr_alg} is not supported yet.")
        enc_type = self.ENCR_ALG_MAP[child.encr_alg]

        if enc_type[0] == "block":
            if child.integ_alg not in self.AUTH_ALG_MAP:
                raise ValueError(f"Integrity algorithm {child.integ_alg} is not supported yet.")
            auth_name, auth_trunc = self.AUTH_ALG_MAP[child.integ_alg]
            enc_name = enc_type[1]

            outbound_cmd = [
                "ip",
                "xfrm",
                "state",
                "add",
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
                "auth",
                auth_name,
                _to_hex(child.integ_key_out),
                "enc",
                enc_name,
                _to_hex(child.encr_key_out),
            ]
            inbound_cmd = [
                "ip",
                "xfrm",
                "state",
                "add",
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
                "auth",
                auth_name,
                _to_hex(child.integ_key_in),
                "enc",
                enc_name,
                _to_hex(child.encr_key_in),
            ]
        else:  # AEAD (GCM)
            if child.integ_alg not in (NONE,):
                logger.warning("Ignoring integrity algorithm %s for AES-GCM", child.integ_alg)
            aead_name = enc_type[1]
            icv_bits = enc_type[2]
            key_bits = (len(child.encr_key_out) - 4) * 8
            outbound_cmd = [
                "ip",
                "xfrm",
                "state",
                "add",
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
                "aead",
                aead_name,
                _to_hex(child.encr_key_out),
                str(icv_bits),
                str(key_bits),
            ]
            inbound_cmd = [
                "ip",
                "xfrm",
                "state",
                "add",
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
                "aead",
                aead_name,
                _to_hex(child.encr_key_in),
                str(icv_bits),
                str(key_bits),
            ]

        self._run(outbound_cmd)
        self._run(inbound_cmd)

    def _install_policies(self, session: SessionConfig) -> None:
        for direction, src, dst, tmpl in self._policy_specs(session):
            self._run(["ip", "xfrm", "policy", "add", "src", src, "dst", dst, "dir", direction, "priority", "2342", *tmpl])

    # ----------------------------------------------------------------- public API

    def activate(self, session: SessionConfig) -> None:
        if self.active:
            logger.info("Re-activating IPsec – cleaning previous configuration")
            self.cleanup()
        self._session = session

        logger.info("Creating VTI interface %s", self.interface)
        try:
            self._run(
                [
                    "ip",
                    "link",
                    "add",
                    self.interface,
                    "type",
                    "vti",
                    "local",
                    session.local_public_ip,
                    "remote",
                    session.remote_public_ip,
                    "ikey",
                    str(session.child_sa.spi_out),
                    "okey",
                    str(session.child_sa.spi_in),
                ]
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            if "File exists" in stderr:
                logger.info("Interface %s already exists – reusing", self.interface)
            elif "Operation not permitted" in stderr:
                logger.warning("Insufficient privileges to create VTI interface. Proceeding without dataplane configuration.")
                return
            else:
                raise
        self._run(["ip", "link", "set", self.interface, "up"])

        if session.local_inner_ipv4:
            for addr in session.local_inner_ipv4:
                prefix = self._match_prefix(addr, session.ts_local) or 32
                try:
                    self._run(["ip", "addr", "add", f"{addr}/{prefix}", "dev", self.interface])
                except subprocess.CalledProcessError as exc:
                    stderr = exc.stderr.decode() if exc.stderr else ""
                    if "File exists" not in stderr:
                        raise
            for route in ("0.0.0.0/1", "128.0.0.0/1"):
                try:
                    self._run(["ip", "route", "add", route, "dev", self.interface])
                except subprocess.CalledProcessError as exc:
                    stderr = exc.stderr.decode() if exc.stderr else ""
                    if "File exists" not in stderr:
                        raise

        if session.local_inner_ipv6:
            for addr in session.local_inner_ipv6:
                prefix = self._match_prefix(addr, session.ts_local) or 128
                try:
                    self._run(["ip", "-6", "addr", "add", f"{addr}/{prefix}", "dev", self.interface])
                except subprocess.CalledProcessError as exc:
                    stderr = exc.stderr.decode() if exc.stderr else ""
                    if "File exists" not in stderr:
                        raise
            v6_dsts = self._ts_prefixes(session.ts_remote, 6) or ["::/0"]
            routes: list[str] = []
            for dst in v6_dsts:
                if dst == "::/0":
                    routes.extend(["::/1", "8000::/1"])
                else:
                    routes.append(dst)
            seen_routes: set[str] = set()
            for route in routes:
                if route in seen_routes:
                    continue
                seen_routes.add(route)
                try:
                    self._run(["ip", "-6", "route", "add", route, "dev", self.interface])
                except subprocess.CalledProcessError as exc:
                    stderr = exc.stderr.decode() if exc.stderr else ""
                    if "File exists" not in stderr:
                        raise

        self._install_states(session)
        self._install_policies(session)
        self.active = True
        logger.info("IPsec dataplane configured on %s", self.interface)

    def cleanup(self) -> None:
        if not self.active:
            return
        session = self._session
        logger.info("Cleaning up IPsec dataplane (%s)", self.interface)
        if session:
            child = session.child_sa
            delete_state_cmds = [
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
            delete_policy_cmds = [
                ["ip", "xfrm", "policy", "delete", "src", src, "dst", dst, "dir", direction]
                for direction, src, dst, _ in self._policy_specs(session)
            ]
            for cmd in delete_state_cmds + delete_policy_cmds:
                try:
                    self._run(cmd)
                except subprocess.CalledProcessError as exc:
                    logger.debug("Cleanup command failed (ignored): %s", exc)
            if session.local_inner_ipv4:
                for route in ("0.0.0.0/1", "128.0.0.0/1"):
                    try:
                        self._run(["ip", "route", "del", route, "dev", self.interface])
                    except subprocess.CalledProcessError as exc:
                        logger.debug("Route cleanup failed (ignored): %s", exc)
        try:
            self._run(["ip", "link", "del", self.interface])
        except subprocess.CalledProcessError as exc:
            logger.debug("Failed to delete VTI interface (ignored): %s", exc)
        try:
            self._run(["ip", "link", "del", f"ip_{self.interface}"])
        except subprocess.CalledProcessError:
            pass

        self.active = False
        self._session = None


def main(argv: Optional[Sequence[str]] = None) -> None:
    """
    Minimal CLI entry-point for manual testing.

    Example:
        python -m swu_new.swu_new --source 192.0.2.10 --epdg 203.0.113.5 \\
            --apn internet --imsi 001010123456789 --ki 465b5ce8b199b49faa5f0a2ee238a6bc \\
            --opc 9e375a9b2e3f36d4191b2d4782 --interface vti0
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
    parser.add_argument("--interface", default="vti0", help="VTI interface name")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

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
    )
    session = ike.connect()

    ipsec = ePDGIPSec(interface=args.interface)
    ipsec.activate(session)

    def _cleanup(signum, _frame) -> None:  # pragma: no cover - signal handler
        logger.info("Received signal %s – shutting down", signum)
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
