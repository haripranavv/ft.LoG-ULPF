import re

from .base import BaseParser, ParsedEvent


class CiscoIOSParser(BaseParser):
    name = "cisco_ios"
    version = "1.0.0"

    PATTERN = re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"(?P<device>\S+)\s+"
        r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d+)-"
        r"(?P<event_code>[A-Z0-9_]+):\s*"
        r"(?P<message>.+)$"
    )

    def can_parse(self, raw_payload: str) -> bool:
        return self.PATTERN.match(raw_payload.strip()) is not None

    def parse(self, raw_payload: str) -> ParsedEvent:
        match = self.PATTERN.match(raw_payload.strip())

        if not match:
            raise ValueError("Invalid Cisco IOS payload")

        fields = match.groupdict()
        fields["severity"] = int(fields["severity"])

        return ParsedEvent(
            source_format="cisco_ios",
            vendor="Cisco",
            product="IOS Router",
            fields=fields,
            raw_payload=raw_payload,
        )