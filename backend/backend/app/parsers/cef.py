import re

from .base import BaseParser, ParsedEvent


class CEFParser(BaseParser):
    name = "cef"
    version = "1.0.0"

    def can_parse(self, raw_payload: str) -> bool:
        return raw_payload.strip().startswith("CEF:")

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()

        parts = payload.split("|", 7)

        if len(parts) < 8:
            raise ValueError("Invalid CEF payload")

        version = parts[0].replace("CEF:", "", 1)
        vendor = parts[1]
        product = parts[2]
        device_version = parts[3]
        signature_id = parts[4]
        name = parts[5]
        severity = parts[6]
        extension = parts[7]

        fields = {
            "cef_version": version,
            "vendor": vendor,
            "product": product,
            "device_version": device_version,
            "signature_id": signature_id,
            "name": name,
            "severity": severity,
            "extension": extension,
        }

        for key, value in re.findall(r"(\w+)=([^\s]+)", extension):
            fields[key] = value

        return ParsedEvent(
            source_format="cef",
            vendor=vendor,
            product=product,
            fields=fields,
            raw_payload=raw_payload,
        )