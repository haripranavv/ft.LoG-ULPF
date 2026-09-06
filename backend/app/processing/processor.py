from app.ai.mapping_assistant import MappingAssistant
from datetime import datetime
from typing import Any

from app.mapping.engine import MappingEngine
from app.mapping.registry import MappingRegistry
from app.normalization.builder import CanonicalEventBuilder
from app.parsers import ParserRegistry
from app.validation.validator import EventValidator


class ULPFProcessor:
    def __init__(
        self,
        mapping_dir: str,
        collector_id: str = "ulpf-collector-01",
    ) -> None:

        self.parser_registry = ParserRegistry()

        self.mapping_registry = MappingRegistry(
            mapping_dir
        )

        self.mapping_engine = MappingEngine()

        self.builder = CanonicalEventBuilder()

        self.validator = EventValidator()

        self.mapping_assistant = MappingAssistant()

        self.collector_id = collector_id

    def process(
        self,
        raw_payload: str,
    ) -> dict[str, Any]:

        try:
            parsed = self.parser_registry.parse(
                raw_payload
            )

        except ValueError:

            proposal = self.mapping_assistant.analyze(
                raw_payload
            )

            return {
                "processing": {
                    "valid": False,
                    "mode": "assisted",
                    "reason": "unknown_log_format",
                    "requires_human_approval": True,
                },
                "ai_assistance": proposal,
            }

        try:

            mapping = self.mapping_registry.get(
                source_format=parsed.source_format,
                vendor=parsed.vendor,
                product=parsed.product,
            )

        except ValueError:

            proposal = self.mapping_assistant.analyze(
                raw_payload
            )

            return {
                "processing": {
                    "valid": False,
                    "mode": "assisted",
                    "reason": "mapping_not_found",
                    "requires_human_approval": True,
                },
                "detected_log": {
                    "source_format": parsed.source_format,
                    "vendor": parsed.vendor,
                    "product": parsed.product,
                },
                "parsed_fields": parsed.fields,
                "ai_assistance": proposal,
            }

        normalized = self.mapping_engine.apply(
            parsed.fields,
            mapping,
        )

        event_timestamp = self._extract_timestamp(
            normalized.get("event", {}).get("timestamp")
        )

        parser = self._get_parser(
            raw_payload
        )

        event = self.builder.build(
            raw_payload=raw_payload,
            normalized=normalized,
            source_format=parsed.source_format,
            parser_name=parser.name,
            parser_version=parser.version,
            mapping_id=mapping.mapping_id,
            mapping_version=mapping.version,
            vendor=parsed.vendor,
            product=parsed.product,
            event_timestamp=event_timestamp,
            collector_id=self.collector_id,
            source_fields=parsed.fields,
        )

        validation = self.validator.validate(event)

        result = event.model_dump(mode="json")

        result["processing"] = {
            "valid": validation.valid,
            "errors": validation.errors,
            "mode": "deterministic",
        }

        return result

    def _get_parser(
        self,
        raw_payload: str,
    ):

        for parser in self.parser_registry.parsers:
            if parser.can_parse(raw_payload):
                return parser

        raise ValueError(
            "Parser not found"
        )

    def _extract_timestamp(
        self,
        value: Any,
    ) -> datetime | None:
        if not value:
            return None

        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            try:
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except ValueError:
                return None

        return None