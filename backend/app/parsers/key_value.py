import re
from typing import Any
from .base import BaseParser, ParsedEvent


class KeyValueParser(BaseParser):
    name = "key_value"
    version = "1.1.0"

    # Match key="value with spaces" or key='value' or key=unquoted_val
    KV_PATTERN = re.compile(
        r'([A-Za-z0-9_\-\.]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=]+))'
    )

    def can_parse(self, raw_payload: str) -> bool:
        payload = raw_payload.strip()
        if payload.startswith("{") or payload.startswith("CEF:"):
            return False
        matches = self.KV_PATTERN.findall(payload)
        return len(matches) >= 2

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        matches = self.KV_PATTERN.findall(payload)

        fields: dict[str, Any] = {}
        for key, q1, q2, unquoted in matches:
            val = q1 or q2 or unquoted
            # Convert pure integer tokens where unambiguous
            if val.isdigit() and not (val.startswith("0") and len(val) > 1):
                try:
                    fields[key] = int(val)
                    continue
                except ValueError:
                    pass
            fields[key] = val

        # Detect leading timestamp or status if present
        prefix_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+",
            payload,
        )
        if prefix_match and "timestamp" not in fields:
            fields["timestamp"] = prefix_match.group(1)

        vendor = fields.get("vendor") or fields.get("dev") or fields.get("dvendor")
        product = fields.get("product") or fields.get("device") or fields.get("dproduct") or fields.get("app")

        return ParsedEvent(
            source_format="key_value",
            vendor=str(vendor) if vendor else None,
            product=str(product) if product else None,
            fields=fields,
            raw_payload=raw_payload,
        )