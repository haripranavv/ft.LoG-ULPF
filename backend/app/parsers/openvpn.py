import re

from .base import BaseParser, ParsedEvent


class OpenVPNParser(BaseParser):
    name = "openvpn"
    version = "1.0.0"

    PATTERN = re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"(?P<user>\S+)\s+"
        r"(?P<action>CONNECTED|DISCONNECTED)\s+"
        r"SRC=(?P<src>\S+)"
        r"(?:\s+VPN_IP=(?P<vpn_ip>\S+))?"
    )

    def can_parse(self, raw_payload: str) -> bool:
        return self.PATTERN.match(raw_payload.strip()) is not None

    def parse(self, raw_payload: str) -> ParsedEvent:
        match = self.PATTERN.match(raw_payload.strip())

        if not match:
            raise ValueError("Invalid OpenVPN payload")

        fields = match.groupdict()

        return ParsedEvent(
            source_format="openvpn",
            vendor="OpenVPN",
            product="VPN",
            fields=fields,
            raw_payload=raw_payload,
        )