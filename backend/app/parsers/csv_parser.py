import csv
import io
import re
from typing import Any
from .base import BaseParser, ParsedEvent


class CSVParser(BaseParser):
    name = "csv"
    version = "1.0.0"

    IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    ISO_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}")

    def can_parse(self, raw_payload: str) -> bool:
        payload = raw_payload.strip()
        if not payload or payload.startswith("{") or payload.startswith("CEF:"):
            return False
        # Must have at least 2 commas separating tokens, without syslog headers
        if payload.count(",") >= 2:
            # Avoid matching lines where commas are inside prose
            parts = [p.strip() for p in payload.split(",")]
            if len(parts) >= 3 and not parts[0].startswith("<"):
                return True
        return False

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        lines = [line.strip() for line in payload.splitlines() if line.strip()]
        
        # Check if first line is a header row and subsequent lines are data
        if len(lines) >= 2:
            reader = csv.reader(io.StringIO(payload))
            headers = [h.strip() for h in next(reader, [])]
            first_data = [d.strip() for d in next(reader, [])]
            fields: dict[str, Any] = {}
            for h, val in zip(headers, first_data):
                clean_key = h.lower().replace(" ", "_").replace(".", "_")
                # Type inference
                if val.isdigit():
                    fields[clean_key] = int(val)
                else:
                    fields[clean_key] = val
            return ParsedEvent(
                source_format="csv",
                vendor=fields.get("vendor"),
                product=fields.get("product"),
                fields=fields,
                raw_payload=raw_payload,
            )

        reader = csv.reader(io.StringIO(payload))
        row = next(reader, [])

        fields: dict[str, Any] = {}
        for i, val in enumerate(row):
            clean_val = val.strip()
            # Try to infer obvious field semantics from value patterns
            if self.ISO_DATE_PATTERN.match(clean_val):
                fields["timestamp"] = clean_val
            elif self.IP_PATTERN.match(clean_val):
                if "src_ip" not in fields:
                    fields["src_ip"] = clean_val
                elif "dst_ip" not in fields:
                    fields["dst_ip"] = clean_val
                else:
                    fields[f"ip_{i+1}"] = clean_val
            elif clean_val.isdigit() and int(clean_val) <= 65535 and ("src_ip" in fields or "dst_ip" in fields):
                if "src_port" not in fields and "src_ip" in fields and "dst_ip" not in fields:
                    fields["src_port"] = int(clean_val)
                elif "dst_port" not in fields:
                    fields["dst_port"] = int(clean_val)
                else:
                    fields[f"col_{i+1}"] = int(clean_val)
            elif clean_val.upper() in ("TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"):
                fields["protocol"] = clean_val.upper()
            elif clean_val.upper() in ("ALLOW", "DENY", "DROP", "BLOCK", "REJECT", "PERMIT"):
                fields["action"] = clean_val.upper()
            else:
                fields[f"col_{i+1}"] = clean_val

        return ParsedEvent(
            source_format="csv",
            vendor=fields.get("vendor"),
            product=fields.get("product"),
            fields=fields,
            raw_payload=raw_payload,
        )
