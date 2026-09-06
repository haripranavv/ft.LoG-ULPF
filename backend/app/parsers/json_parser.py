import json

from .base import BaseParser, ParsedEvent


class JSONParser(BaseParser):
    name = "json"
    version = "1.0.0"

    def can_parse(self, raw_payload: str) -> bool:
        try:
            value = json.loads(raw_payload)
            return isinstance(value, dict)
        except (json.JSONDecodeError, TypeError):
            return False

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        data = json.loads(payload)

        return ParsedEvent(
            source_format="json",
            vendor=data.get("vendor"),
            product=data.get("product"),
            fields=data,
            raw_payload=raw_payload,
        )