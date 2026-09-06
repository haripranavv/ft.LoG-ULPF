import json
import re

from .base import BaseParser, ParsedEvent


class DiscoveryParser(BaseParser):
    name = "discovery"
    version = "1.0.0"

    PATTERN = re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"DISCOVERY\s+"
        r"type=(?P<discovery_type>\S+)\s+"
        r"ip=(?P<ip>\S+)\s+"
        r"mac=(?P<mac>\S+)"
        r"(?:\s+hostname=(?P<hostname>\S+))?"
        r"(?:\s+status=(?P<status>\S+))?"
        r"(?:\s+vendor=(?P<vendor>\S+))?"
    )

    def can_parse(self, raw_payload: str) -> bool:
        payload = raw_payload.strip()
        if self.PATTERN.match(payload):
            return True
        try:
            data = json.loads(payload)
            return isinstance(data, dict) and data.get("event_type") == "discovery"
        except Exception:
            return False

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        match = self.PATTERN.match(payload)
        if match:
            fields = match.groupdict()
            vendor = fields.get("vendor") or "ULPF-Scanner"
            return ParsedEvent(
                source_format="discovery",
                vendor=vendor,
                product="DeviceScanner",
                fields=fields,
                raw_payload=raw_payload,
            )

        try:
            data = json.loads(payload)
        except Exception as error:
            raise ValueError("Invalid discovery payload") from error

        vendor = data.get("vendor") or "ULPF-Scanner"
        fields = {
            "timestamp": data.get("timestamp"),
            "discovery_type": data.get("discovery_type"),
            "ip": data.get("ip") or data.get("src_ip"),
            "mac": data.get("mac") or data.get("hardware_id"),
            "hostname": data.get("hostname") or data.get("device_name"),
            "status": data.get("status"),
            "action": data.get("action", "DISCOVER"),
            "vendor": vendor,
        }

        return ParsedEvent(
            source_format="discovery",
            vendor=vendor,
            product="DeviceScanner",
            fields=fields,
            raw_payload=raw_payload,
        )
