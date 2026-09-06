import re

from .base import BaseParser, ParsedEvent


class SyslogParser(BaseParser):
    name = "syslog"
    version = "1.0.0"

    def can_parse(self, raw_payload: str) -> bool:
        payload = raw_payload.strip()

        return bool(
            re.match(
                r"^(?:<\d+>)?(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?\S+",
                payload,
            )
        )

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()

        priority = None
        message = payload

        priority_match = re.match(r"^<(\d+)>\s*(.*)$", payload)

        if priority_match:
            priority = int(priority_match.group(1))
            message = priority_match.group(2)

        parts = message.split()

        hostname = parts[0] if parts else None

        fields = {
            "hostname": hostname,
            "priority": priority,
            "message": message,
        }

        return ParsedEvent(
            source_format="syslog",
            vendor=None,
            product=None,
            fields=fields,
            raw_payload=raw_payload,
        )