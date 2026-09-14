import re
from typing import Any


class SourceFingerprinter:
    """
    Lightweight, deterministic vendor and source device fingerprinting engine.
    Analyzes log prefixes, facility tags, field tokens, and message structures
    to identify originating technology without hallucinations.
    """

    SIGNATURES = [
        # Cisco IOS / ASA
        {
            "vendor": "Cisco",
            "product": "IOS Router",
            "device_type": "router",
            "patterns": [r"%[A-Z0-9_]+-\d+-[A-Z0-9_]+:", r"%SYS-\d+-", r"Cisco IOS"],
            "field_matches": ["facility", "event_code"],
            "base_confidence": 0.96,
        },
        {
            "vendor": "Cisco",
            "product": "ASA Firewall",
            "device_type": "firewall",
            "patterns": [r"%ASA-\d+-\d+:", r"ASA-5506", r"Cisco ASA"],
            "field_matches": [],
            "base_confidence": 0.95,
        },
        # AcmeGuard Firewall
        {
            "vendor": "AcmeGuard",
            "product": "Firewall",
            "device_type": "firewall",
            "patterns": [r"AcmeGuard", r"FW01\s+ALLOW", r"FW01\s+DENY", r"RULE=ALLOW_"],
            "field_matches": ["rule"],
            "base_confidence": 0.98,
        },
        # OpenVPN
        {
            "vendor": "OpenVPN",
            "product": "VPN Gateway",
            "device_type": "vpn",
            "patterns": [r"VPN_IP=", r"CONNECTED\s+SRC=", r"DISCONNECTED\s+SRC=", r"OpenVPN"],
            "field_matches": ["vpn_ip"],
            "base_confidence": 0.97,
        },
        # Suricata IDS
        {
            "vendor": "OISF",
            "product": "Suricata IDS",
            "device_type": "ids",
            "patterns": [r'"event_type":\s*"alert"', r"SURICATA", r"ET EXPLOIT", r"ET TROJAN"],
            "field_matches": ["signature", "src_port", "dest_port"],
            "base_confidence": 0.96,
        },
        # Snort IDS
        {
            "vendor": "Cisco",
            "product": "Snort IDS",
            "device_type": "ids",
            "patterns": [r"\[\d+:\d+:\d+\]", r"Priority:\s*\d+"],
            "field_matches": ["classification"],
            "base_confidence": 0.92,
        },
        # Nginx / Apache
        {
            "vendor": "Nginx/Apache",
            "product": "Web Access Server",
            "device_type": "web_server",
            "patterns": [r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/[0-9\.]+"'],
            "field_matches": ["http_method", "uri", "status_code"],
            "base_confidence": 0.93,
        },
        # AWS CloudTrail
        {
            "vendor": "AWS",
            "product": "CloudTrail",
            "device_type": "cloud_audit",
            "patterns": [r'"eventSource":', r'"awsRegion":', r'"userIdentity":'],
            "field_matches": ["eventSource", "awsRegion"],
            "base_confidence": 0.99,
        },
        # Microsoft Windows Security / Sysmon
        {
            "vendor": "Microsoft",
            "product": "Windows Security Log",
            "device_type": "endpoint",
            "patterns": [r"Microsoft-Windows-Security-Auditing", r"Microsoft-Windows-Sysmon", r"EventID=\d+"],
            "field_matches": ["EventID", "SourceName"],
            "base_confidence": 0.95,
        },
        # Linux Auth / Systemd
        {
            "vendor": "Linux",
            "product": "System Auth Log",
            "device_type": "server",
            "patterns": [r"sshd\[\d+\]:", r"sudo:\s+", r"systemd\[\d+\]:"],
            "field_matches": [],
            "base_confidence": 0.92,
        },
        # ULPF Scanner Discovery
        {
            "vendor": "ULPF-Scanner",
            "product": "DeviceScanner",
            "device_type": "scanner",
            "patterns": [r"DISCOVERY\s+type=", r"vendor=ULPF-Scanner"],
            "field_matches": ["discovery_type"],
            "base_confidence": 1.0,
        },
    ]

    def fingerprint(
        self,
        raw_payload: str,
        parsed_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Deterministically inspects raw payload and extracted fields.
        Returns vendor, product, device_type, and confidence score.
        """
        fields = parsed_fields or {}

        # 1. Check if vendor/product was explicitly declared in fields
        explicit_vendor = fields.get("vendor") or fields.get("dev_vendor")
        explicit_product = fields.get("product") or fields.get("dev_product")
        if explicit_vendor and explicit_product:
            return {
                "vendor": str(explicit_vendor),
                "product": str(explicit_product),
                "device_type": self._infer_device_type(fields),
                "confidence": 0.99,
                "fingerprint_method": "explicit_source_metadata",
            }

        # 2. Test known signature patterns
        for sig in self.SIGNATURES:
            for pat in sig["patterns"]:
                if re.search(pat, raw_payload):
                    return {
                        "vendor": sig["vendor"],
                        "product": sig["product"],
                        "device_type": sig["device_type"],
                        "confidence": sig["base_confidence"],
                        "fingerprint_method": f"regex_pattern_match:{pat[:25]}",
                    }

            # Check field matches
            if sig["field_matches"] and all(f in fields for f in sig["field_matches"]):
                return {
                    "vendor": sig["vendor"],
                    "product": sig["product"],
                    "device_type": sig["device_type"],
                    "confidence": sig["base_confidence"] - 0.05,
                    "fingerprint_method": "structural_fields_match",
                }

        # 3. Fallback to generic classification without hallucination
        return {
            "vendor": None,
            "product": None,
            "device_type": self._infer_device_type(fields),
            "confidence": 0.15,
            "fingerprint_method": "unmatched_generic_payload",
        }

    def _infer_device_type(self, fields: dict[str, Any]) -> str:
        if "action" in fields and ("src" in fields or "src_ip" in fields):
            return "firewall"
        if "vpn_ip" in fields:
            return "vpn"
        if "http_method" in fields or "uri" in fields:
            return "web_server"
        if "signature" in fields or "threat" in fields:
            return "ids"
        return "generic_node"
