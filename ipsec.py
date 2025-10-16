"""IPsec Helper Module - Manages IPsec configuration using Linux XFRM framework"""

import logging
import random
import subprocess

from jinja2 import BaseLoader, Environment

from tinysip.sip.data.constants import algMap, ealgMap
from tinysip.sip.data.data import ClientData


class IPSecHelper:
    """Helper class to configure and manage IPsec using Linux XFRM."""

    # Expanded templates to handle all required policies and states
    XFRM_TEMPLATES = {
        "outbound_sa_1": """
            ip xfrm state add src {{ ue_ip }} dst {{ ims_ip }}
            proto esp spi {{ "{:#010x}".format(ims_spi_s) }} mode transport reqid {{ ims_spi_s }}
            auth {{ auth_algo }} {{ auth_key }} enc {{ enc_algo }} {{ enc_key }}
            sel src {{ ue_ip }} dst {{ ims_ip }} sport {{ ue_port_c }} dport {{ ims_port_s }}
        """,
        "outbound_policy_1": """
            ip xfrm policy add src {{ ue_ip }} dst {{ ims_ip }} sport {{ ue_port_c }} dport {{ ims_port_s }}
            dir out priority 2342 tmpl src {{ ue_ip }} dst {{ ims_ip }}
            proto esp reqid {{ ims_spi_s }} mode transport
        """,
        "inbound_sa_1": """
            ip xfrm state add src {{ ims_ip }} dst {{ ue_ip }}
            proto esp spi {{ "{:#010x}".format(ue_spi_s) }} mode transport reqid {{ ue_spi_s }}
            auth {{ auth_algo }} {{ auth_key }} enc {{ enc_algo }} {{ enc_key }}
            sel src {{ ims_ip }} dst {{ ue_ip }} sport {{ ims_port_c }} dport {{ ue_port_s }}
        """,
        "inbound_policy_1": """
            ip xfrm policy add src {{ ims_ip }} dst {{ ue_ip }} sport {{ ims_port_c }} dport {{ ue_port_s }}
            dir in priority 2342 tmpl src {{ ims_ip }} dst {{ ue_ip }}
            proto esp reqid {{ ue_spi_s }} mode transport
        """,
        "inbound_sa_2": """
            ip xfrm state add src {{ ims_ip }} dst {{ ue_ip }}
            proto esp spi {{ "{:#010x}".format(ue_spi_c) }} mode transport reqid {{ ue_spi_c }}
            auth {{ auth_algo }} {{ auth_key }} enc {{ enc_algo }} {{ enc_key }}
            sel src {{ ims_ip }} dst {{ ue_ip }} sport {{ ims_port_s }} dport {{ ue_port_c }}
        """,
        "inbound_policy_2": """
            ip xfrm policy add src {{ ims_ip }} dst {{ ue_ip }} sport {{ ims_port_s }} dport {{ ue_port_c }}
            dir in priority 2342 tmpl src {{ ims_ip }} dst {{ ue_ip }}
            proto esp reqid {{ ue_spi_c }} mode transport
        """,
        "outbound_sa_2": """
            ip xfrm state add src {{ ue_ip }} dst {{ ims_ip }}
            proto esp spi {{ "{:#010x}".format(ims_spi_c) }} mode transport reqid {{ ims_spi_c }}
            auth {{ auth_algo }} {{ auth_key }} enc {{ enc_algo }} {{ enc_key }}
            sel src {{ ue_ip }} dst {{ ims_ip }} sport {{ ue_port_s }} dport {{ ims_port_c }}
        """,
        "outbound_policy_2": """
            ip xfrm policy add src {{ ue_ip }} dst {{ ims_ip }} sport {{ ue_port_s }} dport {{ ims_port_c }}
            dir out priority 2342 tmpl src {{ ue_ip }} dst {{ ims_ip }}
            proto esp reqid {{ ims_spi_c }} mode transport
        """,
    }

    def __init__(self, client: ClientData):
        """
        Initialize the IPsec helper.

        Args:
            config (IPSecConfig): The configuration parameters for IPsec.

        Raises:
            RuntimeError: If port reservation fails.
        """
        self.client = client
        self.jinja_env = Environment(loader=BaseLoader(), trim_blocks=True, lstrip_blocks=True)

        # Reserve ports
        self.client.ue.port_c = self.client.ue._reserve_port(self.client.ue.protocol, self.client.ue.ip)
        self.client.ue.port_s = self.client.ue._reserve_port(self.client.ue.protocol, self.client.ue.ip)

        # Generate local SPIs
        self.client.ue.spi_c, self.client.ue.spi_s = self._generate_spis()

        # Will be set during activation

        self.xfrm_active = False

        logging.info(f"IPSec helper initialized with ports: client={self.client.ue.port_c}, server={self.client.ue.port_s}")

    def _generate_spis(self) -> tuple[int, int]:
        """
        Generate random Security Parameter Index (SPI) values.

        Returns:
            tuple[int, int]: A tuple containing two random SPI values.
        """
        return (random.randint(0x100, 0xFFFFFFFF), random.randint(0x100, 0xFFFFFFFF))

    def activate(self):
        """
        Activate IPsec configuration by applying all XFRM policies and states.
        Raises:
            subprocess.CalledProcessError: If any XFRM command fails.
        """
        if self.xfrm_active:
            logging.warning("IPsec already active, deactivating first")
            self.cleanup()

        logging.info(f"Activating IPsec with CK: {self.client.ue.ck.hex()}, IK: {self.client.ue.ik.hex()}")

        template_data = {
            "ue_ip": self.client.ue.ip,
            "ims_ip": self.client.ims.ip,
            "ue_port_c": self.client.ue.port_c,
            "ue_port_s": self.client.ue.port_s,
            "ims_port_c": self.client.ims.port_c,
            "ims_port_s": self.client.ims.port_s,
            "ue_spi_c": self.client.ue.spi_c,
            "ue_spi_s": self.client.ue.spi_s,
            "ims_spi_c": self.client.ims.spi_c,
            "ims_spi_s": self.client.ims.spi_s,
            "auth_algo": algMap[self.client.ims.alg],
            "enc_algo": ealgMap[self.client.ims.ealg],
            "auth_key": f"0x{self.client.ue.ik.hex()}",
            "enc_key": f"0x{self.client.ue.ck.hex()}" if self.client.ims.ealg != "null" else '""',
        }

        # Apply all templates
        for template_name, template_str in self.XFRM_TEMPLATES.items():
            template_str = " ".join(template_str.split("\n")).strip()
            template = self.jinja_env.from_string(template_str)
            command = template.render(template_data).strip()
            command = " ".join(command.split())
            try:
                subprocess.run(command, shell=True, check=True)
                logging.debug(f"Applied {template_name}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to apply {template_name}: {e.stderr}")
                raise
        self.xfrm_active = True

    def cleanup(self):
        """
        Cleanup and remove all IPsec (XFRM) states and policies.
        """
        if not self.xfrm_active:
            logging.debug("IPsec not active, skipping cleanup")
            return

        # Remove specific XFRM states and policies for our SPIs
        cleanup_commands = [
            f"ip xfrm state delete src {self.client.ue.ip} dst {self.client.ims.ip} proto esp spi {self.client.ims.spi_s:#010x}",
            f"ip xfrm state delete src {self.client.ims.ip} dst {self.client.ue.ip} proto esp spi {self.client.ue.spi_s:#010x}",
            f"ip xfrm state delete src {self.client.ims.ip} dst {self.client.ue.ip} proto esp spi {self.client.ue.spi_c:#010x}",
            f"ip xfrm state delete src {self.client.ue.ip} dst {self.client.ims.ip} proto esp spi {self.client.ims.spi_c:#010x}",
            f"ip xfrm policy delete src {self.client.ue.ip} dst {self.client.ims.ip} sport {self.client.ue.port_c} dport {self.client.ims.port_s} dir out",
            f"ip xfrm policy delete src {self.client.ims.ip} dst {self.client.ue.ip} sport {self.client.ims.port_c} dport {self.client.ue.port_s} dir in",
            f"ip xfrm policy delete src {self.client.ims.ip} dst {self.client.ue.ip} sport {self.client.ims.port_s} dport {self.client.ue.port_c} dir in",
            f"ip xfrm policy delete src {self.client.ue.ip} dst {self.client.ims.ip} sport {self.client.ue.port_s} dport {self.client.ims.port_c} dir out",
        ]

        for cmd in cleanup_commands:
            try:
                subprocess.run(cmd.split(), check=True, capture_output=True, text=True)
                logging.debug(f"Cleanup: {cmd}")
            except subprocess.CalledProcessError as e:
                # It's normal for some delete commands to fail if the policy/state doesn't exist
                logging.debug(f"Cleanup command failed (expected): {e.stderr}")

        self.xfrm_active = False
        logging.info("IPsec cleanup completed")
