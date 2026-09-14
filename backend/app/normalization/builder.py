from datetime import datetime, timezone
from hashlib import sha256
from uuid import uuid4

from app.schemas.event import (
    EventIdentity,
    NetworkEndpoint,
    NetworkInfo,
    Observer,
    Provenance,
    RawEvent,
    SecurityInfo,
    ULPFEvent,
    ULPFMetadata,
    UserInfo,
)


class CanonicalEventBuilder:

    def build(
        self,
        raw_payload: str,
        normalized: dict,
        source_format: str,
        parser_name: str,
        parser_version: str,
        mapping_id: str,
        mapping_version: str,
        vendor: str | None,
        product: str | None,
        event_timestamp: datetime | None = None,
        collector_id: str = "ulpf-collector-01",
        source_fields: dict | None = None,
    ) -> ULPFEvent:

        processing_time = datetime.now(timezone.utc)
        timestamp = event_timestamp or processing_time
        trace_id = str(uuid4())

        raw_hash = sha256(raw_payload.encode("utf-8")).hexdigest()

        event_data = normalized.get("event", {})
        source_data = normalized.get("source", {})
        destination_data = normalized.get("destination", {})
        network_data = normalized.get("network", {})
        security_data = normalized.get("security", {})
        user_data = normalized.get("user", {})
        observer_data = normalized.get("observer", {})

        action = event_data.get("action")
        action_lower = str(action or "").lower()
        name_val = source_fields.get("name") if source_fields else None
        name_lower = str(name_val or "").lower()

        # Infer category
        category = event_data.get("category")
        if not category:
            if action_lower in ("login", "logon", "auth", "authenticate") or any(w in name_lower for w in ["login", "auth", "vpn user"]):
                category = "authentication"
            elif action_lower in ("drop", "block", "deny", "allow", "permit"):
                category = "network"
            else:
                category = self._infer_category(source_format)

        # Infer type
        event_type = event_data.get("type")
        if not event_type:
            if action_lower in ("login", "logon", "auth", "authenticate") or any(w in name_lower for w in ["login", "auth", "vpn user"]):
                event_type = "authentication"
            elif action_lower in ("drop", "block", "deny"):
                event_type = "denied"
            elif action_lower in ("allow", "permit"):
                event_type = "allowed"
            else:
                event_type = self._infer_type(source_format)

        # Infer outcome (explicit from event_data first, then fallback to action inference)
        outcome = event_data.get("outcome") or self._infer_outcome(action)

        # Observer version
        obs_version = observer_data.get("version")
        if not obs_version and source_fields:
            obs_version = source_fields.get("device_version") or source_fields.get("cef_version")

        # Security signature
        sec_signature = security_data.get("signature")
        if not sec_signature and source_fields and "signature_id" in source_fields:
            sec_signature = str(source_fields["signature_id"])

        extensions = {}
        if source_fields:
            extensions["source_fields"] = source_fields
        if "message" in event_data:
            extensions["message"] = event_data["message"]

        return ULPFEvent(
            event=EventIdentity(
                id=trace_id,
                kind="event",
                category=category,
                type=event_type,
                action=action,
                severity=self._normalize_severity(
                    event_data.get("severity")
                ),
                outcome=outcome,
            ),
            timestamp=timestamp,
            source=NetworkEndpoint(
                ip=source_data.get("ip"),
                port=source_data.get("port"),
            ),
            destination=NetworkEndpoint(
                ip=destination_data.get("ip"),
                port=destination_data.get("port"),
            ),
            network=NetworkInfo(
                protocol=network_data.get("protocol"),
            ),
            observer=Observer(
                vendor=vendor,
                product=product,
                version=obs_version,
            ),
            user=UserInfo(
                name=user_data.get("name"),
            ),
            security=SecurityInfo(
                rule_id=security_data.get("rule_id"),
                threat=security_data.get("threat"),
                signature=sec_signature,
            ),
            labels=[],
            extensions=extensions,
            ulpf=ULPFMetadata(
                schema_version="1.0.0",
                source_format=source_format,
                parser_name=parser_name,
                parser_version=parser_version,
                mapping_id=mapping_id,
                mapping_version=mapping_version,
                normalization_status="success",
                processing_mode="deterministic",
            ),
            provenance=Provenance(
                trace_id=trace_id,
                raw_event_hash=raw_hash,
                hash_algorithm="SHA-256",
                ingestion_timestamp=processing_time,
                processing_timestamp=processing_time,
                collector_id=collector_id,
            ),
            raw=RawEvent(
                preserved=True,
                encoding="utf-8",
                content_type="text/plain",
                payload=raw_payload,
            ),
        )
    def _normalize_severity(
        self,
        value,
    ) -> int:

        if value is None:
            return 3

        if isinstance(value, int):
            return max(1, min(value, 10))

        severity_map = {
            "LOW": 2,
            "MEDIUM": 5,
            "MODERATE": 5,
            "HIGH": 8,
            "CRITICAL": 10,
            "INFO": 1,
            "INFORMATIONAL": 1,
        }

        value_upper = str(value).strip().upper()

        if value_upper in severity_map:
            return severity_map[value_upper]

        try:
            return max(1, min(int(value), 10))
        except (ValueError, TypeError):
            return 3

    def _infer_category(self, source_format: str) -> str:
        categories = {
            "acmeguard": "network",
            "openvpn": "authentication",
            "cisco_ios": "network",
            "suricata": "intrusion_detection",
            "cef": "security_event",
            "syslog": "system",
            "key_value": "network",
        }

        return categories.get(source_format, "unknown")

    def _infer_type(self, source_format: str) -> str:
        types = {
            "acmeguard": "firewall",
            "openvpn": "vpn",
            "cisco_ios": "router",
            "suricata": "ids_alert",
            "cef": "security_event",
            "syslog": "syslog",
            "key_value": "network_event",
        }

        return types.get(source_format, "unknown")

    def _infer_outcome(self, action: str | None) -> str | None:
        if not action:
            return None

        action = action.upper()

        outcomes = {
            "ALLOW": "success",
            "PERMIT": "success",
            "ACCEPT": "success",
            "ACCEPTED": "success",
            "CONNECTED": "success",
            "DISCONNECTED": "success",
            "LOGIN": "success",
            "LOGON": "success",
            "AUTHENTICATE": "success",
            "AUTHENTICATED": "success",
            "DENY": "failure",
            "BLOCK": "failure",
            "DROP": "failure",
            "REJECT": "failure",
            "FAILED": "failure",
            "FAIL": "failure",
        }

        return outcomes.get(action)