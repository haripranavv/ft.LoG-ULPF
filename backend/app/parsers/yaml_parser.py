import yaml
from typing import Any
from .base import BaseParser, ParsedEvent


class YAMLParser(BaseParser):
    name = "yaml"
    version = "1.0.0"

    def can_parse(self, raw_payload: str) -> bool:
        payload = raw_payload.strip()
        if not payload or payload.startswith("{") or payload.startswith("CEF:") or payload.startswith("<"):
            return False
        # Look for typical YAML key: value multiline or colon structure
        lines = payload.splitlines()
        colon_lines = [l for l in lines if ":" in l and not l.strip().startswith("#")]
        if len(colon_lines) >= 2:
            try:
                data = yaml.safe_load(payload)
                return isinstance(data, dict) and len(data) > 0
            except Exception:
                return False
        return False

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        data = yaml.safe_load(payload) or {}

        fields: dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    fields[f"{k}.{sub_k}"] = sub_v
            else:
                fields[str(k)] = v

        return ParsedEvent(
            source_format="yaml",
            vendor=fields.get("vendor"),
            product=fields.get("product"),
            fields=fields,
            raw_payload=raw_payload,
        )
