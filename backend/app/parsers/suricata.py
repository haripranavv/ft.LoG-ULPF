import json

from .base import BaseParser, ParsedEvent


class SuricataParser(BaseParser):
    name = "suricata"
    version = "1.0.0"

    def can_parse(self, raw_payload: str) -> bool:
        try:
            data = json.loads(raw_payload)

            return (
                isinstance(data, dict)
                and (
                    "event_type" in data
                    or "alert" in data
                )
            )
        except Exception:
            return False

    def parse(self, raw_payload: str) -> ParsedEvent:
        try:
            data = json.loads(raw_payload)
        except Exception as error:
            raise ValueError(
                "Invalid Suricata JSON payload"
            ) from error

        fields = {
            "timestamp": data.get("timestamp"),
            "event_type": data.get("event_type"),
            "src_ip": data.get("src_ip"),
            "src_port": data.get("src_port"),
            "dest_ip": data.get("dest_ip"),
            "dest_port": data.get("dest_port"),
            "proto": data.get("proto"),
        }

        alert = data.get("alert")

        if isinstance(alert, dict):
            fields["signature"] = alert.get("signature")
            fields["severity"] = alert.get("severity")
            fields["category"] = alert.get("category")

        return ParsedEvent(
            source_format="suricata",
            vendor="OISF",
            product="Suricata IDS",
            fields=fields,
            raw_payload=raw_payload,
        )