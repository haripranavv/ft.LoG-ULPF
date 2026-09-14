import time
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.mapping.engine import MappingEngine
from app.mapping.models import FieldMapping, MappingDefinition
from app.mapping.registry import MappingRegistry
from app.normalization.builder import CanonicalEventBuilder
from app.normalization.field_resolver import CanonicalFieldResolver
from app.parsers import ParserRegistry
from app.parsers.fingerprint import SourceFingerprinter
from app.parsers.generic import GenericAdaptiveParser
from app.validation.validator import EventValidator


DEFAULT_MAPPING_DIR = Path(__file__).resolve().parent.parent / "mapping" / "definitions"


class ULPFProcessor:
    """
    Universal Log Pre-processing Framework Engine.
    Executes the deterministic normalization pipeline:
    Raw Log -> Fast Format Detection / Generic Adaptive Parser ->
    Field Extraction -> Source Fingerprinting -> Canonical Field Resolver ->
    Deterministic Mapping -> Schema Validation -> Forensic Provenance.
    """

    def __init__(
        self,
        mapping_dir: str | Path | None = None,
        collector_id: str = "ulpf-collector-01",
    ) -> None:
        self.mapping_dir = Path(mapping_dir) if mapping_dir else DEFAULT_MAPPING_DIR
        self.parser_registry = ParserRegistry()
        self.generic_parser = GenericAdaptiveParser()
        self.field_resolver = CanonicalFieldResolver()
        self.fingerprinter = SourceFingerprinter()
        self.mapping_registry = MappingRegistry(str(self.mapping_dir))
        self.mapping_engine = MappingEngine()
        self.builder = CanonicalEventBuilder()
        self.validator = EventValidator()
        self._mapping_assistant: Any = None
        self.collector_id = collector_id

    @property
    def mapping_assistant(self) -> Any:
        """Lazy-loads the local schema assistant only when AI inference is necessary."""
        if self._mapping_assistant is None:
            from app.ai.mapping_assistant import MappingAssistant
            self._mapping_assistant = MappingAssistant()
        return self._mapping_assistant

    def process(
        self,
        raw_payload: str,
    ) -> dict[str, Any]:
        start_time = time.perf_counter()
        clean_payload = raw_payload.strip()

        # Step 1: Format Detection & Parsing (Deterministic Known Parsers First)
        parser_name = "generic_adaptive"
        parser_version = "2.0.0"
        used_generic = False

        try:
            parsed = self.parser_registry.parse(clean_payload)
            matched_parser = self._get_parser(clean_payload)
            parser_name = matched_parser.name
            parser_version = matched_parser.version
        except ValueError:
            # Fallback to Generic Adaptive Parser (deterministic structure analyzer)
            parsed = self.generic_parser.parse(clean_payload)
            used_generic = True

        # Step 2: Source & Vendor Fingerprinting
        fingerprint = self.fingerprinter.fingerprint(clean_payload, parsed.fields)
        if not parsed.vendor and fingerprint.get("vendor"):
            parsed.vendor = fingerprint["vendor"]
        if not parsed.product and fingerprint.get("product"):
            parsed.product = fingerprint["product"]

        # Step 3: Mapping Lookup
        mapping: MappingDefinition | None = None
        try:
            mapping = self.mapping_registry.get(
                source_format=parsed.source_format,
                vendor=parsed.vendor,
                product=parsed.product,
            )
        except ValueError:
            mapping = None

        # Step 4: Semantic Field Resolution
        resolved = self.field_resolver.resolve_all(parsed.fields)

        # If no registered mapping exists:
        if not mapping:
            # Deterministic inference first: check if confidence is below 0.60
            if resolved["average_confidence"] < 0.60 and len(parsed.fields) > 1:
                try:
                    proposal = self.mapping_assistant.analyze(clean_payload)
                except Exception as ai_err:
                    proposal = {
                        "status": "ai_unavailable",
                        "error": str(ai_err),
                        "mapping_proposals": resolved["resolutions"],
                    }
            else:
                proposal = {
                    "status": "proposal_generated",
                    "mode": "deterministic_field_resolver",
                    "average_confidence": resolved["average_confidence"],
                    "candidate_fields": list(parsed.fields.keys()),
                    "mapping_proposals": resolved["resolutions"],
                    "auto_approved": False,
                    "fingerprint": fingerprint,
                }

            # Check if we have resolved fields to construct a provisional normalized event
            if resolved["canonical_mapping"]:
                provisional_fields: list[FieldMapping] = [
                    FieldMapping(source_field=k, target_field=v, confidence=0.9, required=False)
                    for k, v in resolved["canonical_mapping"].items()
                ]
                synth_id = f"dynamic-{(parsed.vendor or 'generic').lower()}-{(parsed.product or 'adaptive').lower()}".replace(" ", "-")
                mapping = MappingDefinition(
                    mapping_id=synth_id,
                    version="1.0-dynamic",
                    source_format=parsed.source_format,
                    vendor=parsed.vendor,
                    product=parsed.product,
                    fields=provisional_fields,
                )
            else:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                raw_hash = hashlib.sha256(clean_payload.encode("utf-8")).hexdigest()
                now_iso = datetime.now(timezone.utc).isoformat()
                return {
                    "processing": {
                        "valid": False,
                        "mode": "assisted",
                        "reason": "mapping_not_found",
                        "requires_human_approval": True,
                        "latency_ms": elapsed_ms,
                    },
                    "detected_log": {
                        "source_format": parsed.source_format,
                        "vendor": parsed.vendor,
                        "product": parsed.product,
                        "fingerprint": fingerprint,
                    },
                    "parsed_fields": parsed.fields,
                    "ai_assistance": proposal,
                    "raw": {
                        "preserved": True,
                        "encoding": "utf-8",
                        "content_type": "text/plain",
                        "payload": clean_payload,
                    },
                    "ulpf": {
                        "schema_version": "1.0.0",
                        "source_format": parsed.source_format,
                        "parser_name": parser_name,
                        "parser_version": parser_version,
                        "mapping_id": "unmapped",
                        "mapping_version": "0.0.0",
                        "normalization_status": "unmapped",
                        "processing_mode": "assisted",
                    },
                    "provenance": {
                        "trace_id": str(uuid.uuid4()),
                        "raw_event_hash": raw_hash,
                        "hash_algorithm": "SHA-256",
                        "ingestion_timestamp": now_iso,
                        "collector_id": self.collector_id,
                    },
                    "event": {
                        "kind": "event",
                        "category": "unclassified",
                        "action": "unmapped",
                        "severity": 1,
                    },
                }

        # Step 5: Apply Schema Mapping
        normalized = self.mapping_engine.apply(
            parsed.fields,
            mapping,
        )

        event_timestamp = self._extract_timestamp(
            normalized.get("event", {}).get("timestamp") or parsed.fields.get("timestamp") or parsed.fields.get("rt")
        )

        # Step 6: Build Canonical ULPF Event with Cryptographic Provenance
        event = self.builder.build(
            raw_payload=clean_payload,
            normalized=normalized,
            source_format=parsed.source_format,
            parser_name=parser_name,
            parser_version=parser_version,
            mapping_id=mapping.mapping_id,
            mapping_version=mapping.version,
            vendor=parsed.vendor,
            product=parsed.product,
            event_timestamp=event_timestamp,
            collector_id=self.collector_id,
            source_fields=parsed.fields,
        )

        # Step 7: Deterministic Schema Validation
        validation = self.validator.validate(event)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        result = event.model_dump(mode="json")

        result["processing"] = {
            "valid": validation.valid,
            "errors": validation.errors,
            "mode": "adaptive" if used_generic else "deterministic",
            "latency_ms": elapsed_ms,
            "fingerprint": fingerprint,
            "field_resolution_confidence": resolved["average_confidence"],
        }

        return result

    def _get_parser(self, raw_payload: str):
        for parser in self.parser_registry.parsers:
            if parser.can_parse(raw_payload):
                return parser
        raise ValueError("Parser not found")

    def _extract_timestamp(self, value: Any) -> datetime | None:
        if not value:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            val = value.strip()
            # 1. ISO format
            try:
                clean_val = val.replace("Z", "+00:00")
                return datetime.fromisoformat(clean_val)
            except ValueError:
                pass

            # 2. CEF / Syslog text formats
            for fmt in (
                "%b %d %Y %H:%M:%S %Z",
                "%b %d %Y %H:%M:%S",
                "%b %d %H:%M:%S %Y",
                "%b %d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(val, fmt)
                    if "%Y" not in fmt:
                        dt = dt.replace(year=datetime.now().year)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    pass

            # 3. Epoch timestamps (ms or s)
            try:
                num = float(val)
                if num > 1e11:  # ms
                    return datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
                elif num > 1e8:  # s
                    return datetime.fromtimestamp(num, tz=timezone.utc)
            except (ValueError, OSError):
                pass

        return None


# Global singleton processor instance
_processor_instance: ULPFProcessor | None = None


def get_processor() -> ULPFProcessor:
    global _processor_instance
    if _processor_instance is None:
        _processor_instance = ULPFProcessor()
    return _processor_instance