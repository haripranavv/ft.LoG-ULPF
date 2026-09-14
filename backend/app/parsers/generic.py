import csv
import io
import json
import re
from typing import Any
from .base import BaseParser, ParsedEvent


class GenericAdaptiveParser(BaseParser):
    name = "generic_adaptive"
    version = "2.0.0"

    # Common Web Access Log regex (Apache/Nginx combined)
    WEB_ACCESS_PATTERN = re.compile(
        r'^(?P<client_ip>\S+)\s+\S+\s+(?P<ident>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<http_method>\S+)\s+(?P<uri>\S+)\s+(?P<http_version>[^"]+)"\s+'
        r'(?P<status_code>\d{3})\s+(?P<bytes_sent>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    # Syslog PRI header regex (e.g. <134>Sep 06 10:00:00 ...)
    SYSLOG_PATTERN = re.compile(
        r'^<(?P<priority>\d{1,3})>(?:(?P<version>\d+)\s+)?'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)?\s*'
        r'(?P<hostname>[^\s:]+)?\s*(?P<tag>[^:\s\[]+)?(?:\s*\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
    )

    # Windows event log markers
    WINDOWS_MARKERS = [
        "EventID", "SourceName", "EventCode", "TaskCategory", "Security ID", "Account Name"
    ]

    # Firewall markers
    FIREWALL_MARKERS = [
        "ALLOW", "DENY", "DROP", "BLOCK", "REJECT", "FORWARD", "TEARDOWN", "BUILT"
    ]

    # VPN markers
    VPN_MARKERS = [
        "CONNECTED", "DISCONNECTED", "TUNNEL", "VPN_IP", "OpenVPN", "WireGuard", "IPsec"
    ]

    # IDS / IPS markers
    IDS_MARKERS = [
        "signature", "ET EXPLOIT", "ET TROJAN", "GPL ATTACK", "SURICATA", "SNORT", "alert", "classification"
    ]

    def can_parse(self, raw_payload: str) -> bool:
        # The generic adaptive parser can handle any non-empty string payload
        return bool(raw_payload and raw_payload.strip())

    def classify(self, raw_payload: str) -> dict[str, Any]:
        """
        Stage 1: Input Classification
        Deterministically evaluates payload characteristics and returns likely format and confidence.
        """
        payload = raw_payload.strip()
        if not payload:
            return {"format": "unknown", "confidence": 0.0, "details": "Empty payload"}

        # 1. CEF check
        if payload.startswith("CEF:"):
            return {
                "format": "cef",
                "confidence": 0.99,
                "details": "Common Event Format signature header",
            }

        # 2. JSON / Nested JSON check
        if (payload.startswith("{") and payload.endswith("}")) or (payload.startswith("[") and payload.endswith("]")):
            try:
                parsed_json = json.loads(payload)
                if isinstance(parsed_json, dict):
                    has_nested = any(isinstance(v, (dict, list)) for v in parsed_json.values())
                    if has_nested:
                        return {
                            "format": "nested_json",
                            "confidence": 0.98,
                            "details": "JSON object with nested dictionaries or arrays",
                        }
                    return {
                        "format": "json",
                        "confidence": 0.96,
                        "details": "Flat JSON key-value dictionary",
                    }
                if isinstance(parsed_json, list):
                    return {
                        "format": "json_array",
                        "confidence": 0.95,
                        "details": "Array of JSON elements",
                    }
            except Exception:
                pass

        # 3. JSON Lines check
        lines = [line.strip() for line in payload.splitlines() if line.strip()]
        if len(lines) > 1 and all(l.startswith("{") and l.endswith("}") for l in lines[:5]):
            try:
                for l in lines[:5]:
                    json.loads(l)
                return {
                    "format": "jsonl",
                    "confidence": 0.97,
                    "details": "Newline-delimited JSON Lines stream",
                }
            except Exception:
                pass

        # 4. Web Access Log (Apache / Nginx)
        if self.WEB_ACCESS_PATTERN.match(payload):
            return {
                "format": "web_access",
                "confidence": 0.94,
                "details": "Combined/Common HTTP Web Access Log",
            }

        # 5. Syslog check
        syslog_match = self.SYSLOG_PATTERN.match(payload)
        if syslog_match:
            msg = syslog_match.group("message") or ""
            # Check if inner message has specialized markers
            if any(m in msg for m in self.FIREWALL_MARKERS) and ("SRC=" in msg or "src=" in msg):
                return {
                    "format": "firewall",
                    "confidence": 0.92,
                    "details": "Syslog-encapsulated Firewall Event",
                }
            return {
                "format": "syslog",
                "confidence": 0.90,
                "details": "RFC 3164/5424 Syslog Header encapsulation",
            }

        # 6. Windows Event style check
        if any(marker in payload for marker in self.WINDOWS_MARKERS):
            return {
                "format": "windows_event",
                "confidence": 0.88,
                "details": "Windows Event Log / Sysmon token signature",
            }

        # 7. IDS / IPS signature check
        if any(marker in payload for marker in self.IDS_MARKERS):
            return {
                "format": "ids_ips",
                "confidence": 0.86,
                "details": "Intrusion Detection System alert pattern",
            }

        # 8. Firewall / VPN signature check
        if any(m in payload for m in self.VPN_MARKERS) and ("SRC=" in payload or "VPN_IP=" in payload or "user=" in payload):
            return {
                "format": "vpn",
                "confidence": 0.90,
                "details": "VPN Tunnel / Remote Access Gateway Event",
            }
        if any(m in payload for m in self.FIREWALL_MARKERS) and ("SRC=" in payload or "src=" in payload or "DST=" in payload):
            return {
                "format": "firewall",
                "confidence": 0.91,
                "details": "Network Perimeter Firewall Action Event",
            }

        # 9. Key-Value pairs check (e.g. k=v or k: v or pipe delimited)
        eq_pairs = re.findall(r"([A-Za-z0-9_\-\.]+)=([^\s]+)", payload)
        colon_pairs = re.findall(r"([A-Za-z0-9_\-\.]+):\s*([^\s,\|]+)", payload)
        if len(eq_pairs) >= 2 or len(colon_pairs) >= 2:
            return {
                "format": "key_value",
                "confidence": 0.89,
                "details": f"Key-Value structure with {max(len(eq_pairs), len(colon_pairs))} pairs detected",
            }

        # 10. CSV check
        if "," in payload and "\n" not in payload:
            parts = [p.strip() for p in payload.split(",")]
            if len(parts) >= 3:
                return {
                    "format": "csv",
                    "confidence": 0.70,
                    "details": f"Delimited columns ({len(parts)} fields)",
                }

        # Fallback to plain text
        return {
            "format": "plain_text",
            "confidence": 0.50,
            "details": "Unstructured text payload with no explicit framing",
        }

    def extract_structure(self, raw_payload: str) -> dict[str, Any]:
        """
        Stage 2: Structure Detection & Field Normalization
        Extracts raw fields, separators, delimiters, and timestamps into an intermediate representation.
        """
        payload = raw_payload.strip()
        classification = self.classify(payload)
        fmt = classification["format"]

        raw_fields: dict[str, Any] = {}
        extracted_timestamp: str | None = None
        extracted_message: str | None = None

        # --- Branch A: JSON / Nested JSON ---
        if fmt in ("json", "nested_json"):
            try:
                data = json.loads(payload)
                if isinstance(data, dict):
                    # Flatten up to 2 levels if nested
                    for k, v in data.items():
                        if isinstance(v, dict):
                            for sub_k, sub_v in v.items():
                                raw_fields[f"{k}.{sub_k}"] = sub_v
                        else:
                            raw_fields[k] = v
            except Exception:
                pass

        # --- Branch B: Web Access Log ---
        elif fmt == "web_access":
            m = self.WEB_ACCESS_PATTERN.match(payload)
            if m:
                raw_fields = {k: v for k, v in m.groupdict().items() if v is not None}
                extracted_timestamp = raw_fields.get("timestamp")

        # --- Branch C: Syslog ---
        elif fmt == "syslog":
            m = self.SYSLOG_PATTERN.match(payload)
            if m:
                groups = m.groupdict()
                raw_fields = {k: v for k, v in groups.items() if v is not None}
                extracted_timestamp = raw_fields.get("timestamp")
                extracted_message = raw_fields.get("message")
                # Also extract any key-values from inner message
                if extracted_message:
                    inner_pairs = self._extract_key_value_pairs(extracted_message)
                    raw_fields.update(inner_pairs)

        # --- Branch D: Key-Value, Firewall, VPN, IDS ---
        elif fmt in ("key_value", "firewall", "vpn", "ids_ips", "windows_event"):
            # If payload starts with timestamp or syslog header, separate it
            prefix_match = re.match(
                r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$",
                payload,
            )
            if prefix_match:
                extracted_timestamp = prefix_match.group(1)
                body = prefix_match.group(2)
            else:
                body = payload

            # Extract key-value pairs (k=v, k="v", k:v)
            raw_fields = self._extract_key_value_pairs(body)

            # If timestamp wasn't in prefix, look inside fields
            if not extracted_timestamp:
                for time_key in ("timestamp", "time", "date", "ts", "datetime"):
                    if time_key in raw_fields:
                        extracted_timestamp = str(raw_fields[time_key])
                        break

            # If token body has leading positional items (e.g. "FW01 ALLOW ...")
            tokens = body.split()
            if tokens and not any("=" in tokens[0] for _ in [0]):
                raw_fields["_device"] = tokens[0]
                if len(tokens) > 1 and tokens[1].upper() in self.FIREWALL_MARKERS:
                    raw_fields["action"] = tokens[1].upper()

        # --- Branch E: CSV ---
        elif fmt == "csv":
            try:
                reader = csv.reader(io.StringIO(payload))
                row = next(reader, None)
                if row:
                    for i, col in enumerate(row):
                        raw_fields[f"col_{i+1}"] = col.strip()
            except Exception:
                pass

        # --- Branch F: Plain Text / Unknown Fallback ---
        else:
            raw_fields = self._extract_key_value_pairs(payload)
            if not raw_fields:
                raw_fields["message"] = payload

        return {
            "format": fmt,
            "confidence": classification["confidence"],
            "classification_details": classification["details"],
            "raw_fields": raw_fields,
            "extracted_timestamp": extracted_timestamp,
            "message": extracted_message or payload,
        }

    def _extract_key_value_pairs(self, text: str) -> dict[str, Any]:
        """Extract key=value, key="value with spaces", or key: value pairs."""
        pairs: dict[str, Any] = {}

        # 1. Quoted key="value" or key='value'
        quoted = re.findall(r'([A-Za-z0-9_\-\.]+)=["\']([^"\']*)["\']', text)
        for k, v in quoted:
            pairs[k.strip()] = v.strip()

        # 2. Standard key=value
        unquoted = re.findall(r'([A-Za-z0-9_\-\.]+)=([^\s"\'=]+)', text)
        for k, v in unquoted:
            if k not in pairs:
                # Cast integers where unambiguous
                val = v.strip().rstrip(",")
                if val.isdigit():
                    try:
                        pairs[k.strip()] = int(val)
                        continue
                    except ValueError:
                        pass
                pairs[k.strip()] = val

        # 3. Delimited colon pairs e.g. Key: Value | Key2: Value2
        if "|" in text or ";" in text:
            delimiters = [p.strip() for p in re.split(r"[|;]", text) if ":" in p]
            for part in delimiters:
                if ":" in part:
                    k, v = part.split(":", 1)
                    k_clean = k.strip()
                    if k_clean and k_clean not in pairs:
                        pairs[k_clean] = v.strip()

        return pairs

    def parse(self, raw_payload: str) -> ParsedEvent:
        """
        Parses raw input through the generic adaptive structural detection pipeline.
        Returns a canonical ParsedEvent.
        """
        structure = self.extract_structure(raw_payload)
        fields = structure["raw_fields"]
        fmt = structure["format"]

        # Attempt to pull vendor and product from fields if present
        vendor = fields.get("vendor") or fields.get("dev")
        product = fields.get("product") or fields.get("device") or fields.get("app")

        return ParsedEvent(
            source_format=f"generic_{fmt}",
            vendor=str(vendor) if vendor else None,
            product=str(product) if product else None,
            fields=fields,
            raw_payload=raw_payload,
        )
