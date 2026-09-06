import re

from .base import BaseParser, ParsedEvent


class KeyValueParser(BaseParser):
    name = "key_value"
    version = "1.0.0"

    def can_parse(
        self,
        raw_payload: str,
    ) -> bool:

        pairs = re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*=[^\s]+",
            raw_payload,
        )

        return len(pairs) >= 2

    def parse(
        self,
        raw_payload: str,
    ) -> ParsedEvent:

        pairs = re.findall(
            r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)",
            raw_payload,
        )

        fields = {
            key: value
            for key, value in pairs
        }

        vendor = fields.get("vendor") or fields.get("dev")
        product = fields.get("product") or fields.get("device")

        return ParsedEvent(
            source_format="key_value",
            vendor=vendor,
            product=product,
            fields=fields,
            raw_payload=raw_payload,
        )