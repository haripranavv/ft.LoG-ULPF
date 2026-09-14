import re
from typing import Any


class CanonicalFieldResolver:
    """
    Intelligent semantic field inference and alias resolution.
    Maps raw source field keys to canonical ULPF schema targets with confidence scoring
    and ambiguity detection.
    """

    IP_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

    # High-confidence alias mappings
    ALIAS_MAP: dict[str, tuple[str, float, str]] = {
        # Source IP
        "src": ("source.ip", 0.98, "known source IP abbreviation"),
        "src_ip": ("source.ip", 0.99, "explicit source IP alias"),
        "source": ("source.ip", 0.95, "source address token"),
        "source_ip": ("source.ip", 0.99, "canonical source IP alias"),
        "srcaddr": ("source.ip", 0.98, "firewall source address alias"),
        "sourceaddress": ("source.ip", 0.98, "network source address alias"),
        "client_ip": ("source.ip", 0.97, "client network origin alias"),
        "clientip": ("source.ip", 0.97, "client network origin alias"),
        "c_ip": ("source.ip", 0.95, "W3C format client IP alias"),

        # Destination IP
        "dst": ("destination.ip", 0.98, "known destination IP abbreviation"),
        "dst_ip": ("destination.ip", 0.99, "explicit destination IP alias"),
        "destination": ("destination.ip", 0.95, "destination address token"),
        "destination_ip": ("destination.ip", 0.99, "canonical destination IP alias"),
        "dstaddr": ("destination.ip", 0.98, "firewall destination address alias"),
        "destaddr": ("destination.ip", 0.98, "firewall destination address alias"),
        "destinationaddress": ("destination.ip", 0.98, "network destination address alias"),
        "server_ip": ("destination.ip", 0.97, "server network target alias"),
        "serverip": ("destination.ip", 0.97, "server network target alias"),
        "s_ip": ("destination.ip", 0.95, "W3C format server IP alias"),

        # Source Port
        "sport": ("source.port", 0.98, "known source port abbreviation"),
        "spt": ("source.port", 0.98, "CEF source port token"),
        "src_port": ("source.port", 0.99, "explicit source port alias"),
        "source_port": ("source.port", 0.99, "canonical source port alias"),
        "s_port": ("source.port", 0.96, "source port token"),

        # Destination Port
        "dport": ("destination.port", 0.98, "known destination port abbreviation"),
        "dpt": ("destination.port", 0.98, "CEF destination port token"),
        "dst_port": ("destination.port", 0.99, "explicit destination port alias"),
        "destination_port": ("destination.port", 0.99, "canonical destination port alias"),
        "d_port": ("destination.port", 0.96, "destination port token"),

        # User / Actor
        "suser": ("user.name", 0.99, "CEF source user alias"),
        "srcuser": ("user.name", 0.98, "source user alias"),
        "source_user": ("user.name", 0.98, "source user alias"),
        "duser": ("user.name", 0.95, "CEF destination user alias"),
        "dstuser": ("user.name", 0.95, "destination user alias"),
        "target_user": ("user.name", 0.95, "target user alias"),
        "user": ("user.name", 0.96, "known user alias"),
        "username": ("user.name", 0.98, "explicit username alias"),
        "account": ("user.name", 0.94, "account identity alias"),
        "login": ("user.name", 0.92, "login identifier alias"),
        "principal": ("user.name", 0.94, "authentication principal alias"),
        "auth_user": ("user.name", 0.97, "authenticated user alias"),
        "usr": ("user.name", 0.94, "short user token"),

        # Action
        "action": ("event.action", 0.99, "canonical event action token"),
        "event_action": ("event.action", 0.99, "explicit event action alias"),
        "operation": ("event.action", 0.92, "operational activity alias"),
        "activity": ("event.action", 0.92, "security activity alias"),
        "act": ("event.action", 0.99, "CEF event action alias"),
        "outcome": ("event.outcome", 0.99, "CEF event outcome token"),
        "result": ("event.outcome", 0.96, "event result token"),

        # Severity
        "severity": ("event.severity", 0.99, "canonical severity token"),
        "priority": ("event.severity", 0.95, "syslog priority/severity alias"),
        "level": ("event.severity", 0.92, "log level/severity alias"),
        "risk": ("event.severity", 0.93, "threat risk rating alias"),
        "custom_severity": ("event.severity", 0.96, "custom firewall severity alias"),
        "sev": ("event.severity", 0.95, "short severity abbreviation"),

        # Protocol
        "proto": ("network.protocol", 0.98, "known protocol abbreviation"),
        "protocol": ("network.protocol", 0.99, "canonical network protocol token"),
        "transport": ("network.protocol", 0.94, "transport layer protocol token"),

        # Threat / Rule
        "threat": ("security.threat", 0.98, "canonical threat signature"),
        "threat_name": ("security.threat", 0.98, "threat identification alias"),
        "signature": ("security.signature", 0.98, "security signature alias"),
        "signature_id": ("security.signature", 0.99, "CEF signature ID token"),
        "sig_id": ("security.signature", 0.98, "CEF signature ID alias"),
        "rule": ("security.rule_id", 0.96, "security firewall rule token"),
        "rule_id": ("security.rule_id", 0.99, "explicit rule ID token"),

        # Observer / Host
        "device": ("observer.hostname", 0.94, "device identifier alias"),
        "dev": ("observer.hostname", 0.92, "device short token"),
        "hostname": ("observer.hostname", 0.98, "canonical hostname alias"),
        "host": ("observer.hostname", 0.95, "host entity alias"),
        "dname": ("observer.hostname", 0.93, "device name alias"),
        "device_version": ("observer.version", 0.98, "device software version"),
        "cef_version": ("observer.version", 0.90, "CEF standard version"),

        # Timestamp
        "rt": ("event.timestamp", 0.99, "CEF receipt time alias"),
        "receipt_time": ("event.timestamp", 0.98, "receipt time alias"),
        "device_receipt_time": ("event.timestamp", 0.98, "device receipt time alias"),
        "start": ("event.timestamp", 0.94, "event start time alias"),
        "end": ("event.timestamp", 0.94, "event end time alias"),
        "timestamp": ("event.timestamp", 0.99, "canonical event timestamp token"),
        "time": ("event.timestamp", 0.95, "time token"),
        "datetime": ("event.timestamp", 0.97, "datetime token"),
        "ts": ("event.timestamp", 0.94, "short timestamp alias"),

        # Message
        "msg": ("event.message", 0.99, "CEF message alias"),
        "message": ("event.message", 0.99, "canonical message token"),
        "description": ("event.message", 0.96, "event description alias"),
        "cef_name": ("event.message", 0.98, "CEF event name alias"),
        "event_name": ("event.message", 0.98, "event name alias"),

        # HTTP / Web
        "method": ("event.action", 0.92, "HTTP request method mapped to event action"),
        "http_method": ("event.action", 0.95, "HTTP request method mapped to event action"),
        "uri": ("event.message", 0.90, "HTTP URI path mapped to event message"),
        "url": ("event.message", 0.90, "HTTP URL mapped to event message"),
        "path": ("event.message", 0.88, "HTTP path mapped to event message"),
        "status_code": ("event.outcome", 0.92, "HTTP status code mapped to event outcome"),
        "http_status": ("event.outcome", 0.92, "HTTP status code mapped to event outcome"),
        "status": ("event.action", 0.85, "status/outcome token mapped to event action"),
    }

    # Ambiguous fields requiring review
    AMBIGUOUS_FIELDS: dict[str, list[str]] = {
        "id": ["event.id", "observer.device_id", "user.id", "security.rule_id"],
        "name": ["event.message", "observer.hostname", "security.threat"],
        "type": ["event.type", "network.protocol", "observer.device_type"],
        "status": ["event.outcome", "event.action", "security.rule_id"],
        "code": ["event.code", "security.rule_id", "http.status_code"],
        "ip": ["source.ip", "destination.ip", "observer.ip"],
        "port": ["source.port", "destination.port"],
    }

    def resolve_field(self, raw_key: str, value: Any = None) -> dict[str, Any]:
        """
        Infers canonical schema target for a given raw key and optional sample value.
        Returns candidate mapping, confidence score, reason, and review requirement.
        """
        clean_key = raw_key.strip().lower().replace("-", "_").replace(" ", "_")

        # 1. Check ambiguous fields first
        if clean_key in self.AMBIGUOUS_FIELDS:
            candidates = self.AMBIGUOUS_FIELDS[clean_key]
            if clean_key == "ip" and value and isinstance(value, str) and self.IP_PATTERN.match(value.strip()):
                return {
                    "field": raw_key,
                    "canonical_candidate": "source.ip",
                    "candidates": candidates,
                    "confidence": 0.65,
                    "reason": "ambiguous IP entity, defaulted to source.ip",
                    "requires_review": True,
                }
            if clean_key == "name":
                # In CEF and security event headers, 'name' is the Event Name/Description, NOT user.name
                str_val = str(value).strip() if value else ""
                has_multi_words = " " in str_val or any(w in str_val.lower() for w in ["login", "packet", "event", "vpn", "traffic", "auth"])
                return {
                    "field": raw_key,
                    "canonical_candidate": "event.message",
                    "candidates": candidates,
                    "confidence": 0.95 if has_multi_words else 0.85,
                    "reason": "event name/description token (not user.name)",
                    "requires_review": False,
                }
            return {
                "field": raw_key,
                "canonical_candidate": candidates[0],
                "candidates": candidates,
                "confidence": 0.45,
                "reason": f"ambiguous generic key '{raw_key}' matches multiple schema domains",
                "requires_review": True,
            }

        # 2. Check alias map
        if clean_key in self.ALIAS_MAP:
            target, base_confidence, reason = self.ALIAS_MAP[clean_key]
            confidence = base_confidence

            # Boost or verify confidence based on value type
            if value is not None:
                str_val = str(value).strip()
                if target in ("source.ip", "destination.ip"):
                    if self.IP_PATTERN.match(str_val):
                        confidence = min(0.99, confidence + 0.02)
                    elif str_val and not re.match(r"^[0-9a-fA-F:\.]+$", str_val):
                        # Value is not an IP, decrease confidence
                        confidence = max(0.40, confidence - 0.35)
                        return {
                            "field": raw_key,
                            "canonical_candidate": None,
                            "candidates": [target, "observer.hostname"],
                            "confidence": confidence,
                            "reason": f"field named '{raw_key}' contains non-IP value '{str_val}'",
                            "requires_review": True,
                        }

                elif target in ("source.port", "destination.port"):
                    try:
                        port_int = int(str_val)
                        if 0 <= port_int <= 65535:
                            confidence = min(0.99, confidence + 0.02)
                    except ValueError:
                        confidence = max(0.30, confidence - 0.40)

            return {
                "field": raw_key,
                "canonical_candidate": target,
                "candidates": [target],
                "confidence": round(confidence, 3),
                "reason": reason,
                "requires_review": confidence < 0.80,
            }

        # 3. Suffix heuristics (e.g. any key ending with _ip, _port, _user)
        if clean_key.endswith("_ip") or clean_key.endswith("ip"):
            if "dst" in clean_key or "dest" in clean_key or "server" in clean_key or "target" in clean_key:
                return {
                    "field": raw_key,
                    "canonical_candidate": "destination.ip",
                    "candidates": ["destination.ip"],
                    "confidence": 0.88,
                    "reason": "detected destination IP suffix pattern",
                    "requires_review": False,
                }
            return {
                "field": raw_key,
                "canonical_candidate": "source.ip",
                "candidates": ["source.ip", "destination.ip"],
                "confidence": 0.85,
                "reason": "detected IP suffix pattern",
                "requires_review": False,
            }

        if clean_key.endswith("_port") or clean_key.endswith("port"):
            if "dst" in clean_key or "dest" in clean_key or "server" in clean_key:
                return {
                    "field": raw_key,
                    "canonical_candidate": "destination.port",
                    "candidates": ["destination.port"],
                    "confidence": 0.88,
                    "reason": "detected destination port suffix pattern",
                    "requires_review": False,
                }
            return {
                "field": raw_key,
                "canonical_candidate": "source.port",
                "candidates": ["source.port", "destination.port"],
                "confidence": 0.85,
                "reason": "detected port suffix pattern",
                "requires_review": False,
            }

        # 4. Unknown field
        return {
            "field": raw_key,
            "canonical_candidate": None,
            "candidates": [],
            "confidence": 0.10,
            "reason": "unrecognized source field, mapped to null/extension",
            "requires_review": True,
        }

    def resolve_all(self, raw_fields: dict[str, Any]) -> dict[str, Any]:
        """
        Resolves a full dictionary of extracted fields.
        Returns mapped proposals, confidence metrics, and human review requirements.
        """
        resolutions: list[dict[str, Any]] = []
        canonical_map: dict[str, Any] = {}
        review_required = False

        for k, v in raw_fields.items():
            res = self.resolve_field(k, v)
            resolutions.append(res)
            if res["requires_review"]:
                review_required = True
            target = res["canonical_candidate"]
            if target:
                canonical_map[k] = target

        total_conf = sum(r["confidence"] for r in resolutions) if resolutions else 0.0
        avg_conf = round(total_conf / len(resolutions), 3) if resolutions else 0.0

        return {
            "resolutions": resolutions,
            "canonical_mapping": canonical_map,
            "average_confidence": avg_conf,
            "review_required": review_required,
        }
