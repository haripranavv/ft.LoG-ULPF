import re

from .base import BaseParser, ParsedEvent


class AcmeGuardParser(BaseParser):
    name = "acmeguard"
    version = "1.0.0"

    PATTERN = re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"(?P<device>\S+)\s+"
        r"(?P<action>\S+)\s+"
        r"SRC=(?P<src>\S+)\s+"
        r"DST=(?P<dst>\S+)\s+"
        r"SP=(?P<sport>\d+)\s+"
        r"DP=(?P<dport>\d+)\s+"
        r"PROTO=(?P<protocol>\S+)"
        r"(?:\s+RULE=(?P<rule>\S+))?"
        r"(?:\s+USER=(?P<user>\S+))?"
        r"(?:\s+THREAT=(?P<threat>\S+))?"
    )

    def can_parse(self, raw_payload: str) -> bool:
        return self.PATTERN.match(raw_payload.strip()) is not None

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        match = self.PATTERN.match(payload)

        if not match:
            raise ValueError("Invalid AcmeGuard firewall payload")

        fields = match.groupdict()

        fields["sport"] = int(fields["sport"])
        fields["dport"] = int(fields["dport"])

        return ParsedEvent(
            source_format="acmeguard",
            vendor="AcmeGuard",
            product="Firewall",
            fields=fields,
            raw_payload=raw_payload,
        )