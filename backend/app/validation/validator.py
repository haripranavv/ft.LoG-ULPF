from hashlib import sha256

from app.schemas.event import ULPFEvent


class ValidationResult:
    def __init__(
        self,
        valid: bool,
        errors: list[str] | None = None,
    ) -> None:
        self.valid = valid
        self.errors = errors or []


class EventValidator:
    def validate(self, event: ULPFEvent) -> ValidationResult:
        errors: list[str] = []

        self._validate_raw_integrity(event, errors)
        self._validate_provenance(event, errors)
        self._validate_metadata(event, errors)

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
        )

    def _validate_raw_integrity(
        self,
        event: ULPFEvent,
        errors: list[str],
    ) -> None:
        if not event.raw.preserved:
            errors.append("Raw event is not marked as preserved")

        if not event.raw.payload:
            errors.append("Raw event payload is empty")
            return

        calculated_hash = sha256(
            event.raw.payload.encode(event.raw.encoding)
        ).hexdigest()

        if calculated_hash != event.provenance.raw_event_hash:
            errors.append(
                "Raw event integrity check failed: "
                "SHA-256 mismatch"
            )

    def _validate_provenance(
        self,
        event: ULPFEvent,
        errors: list[str],
    ) -> None:
        if not event.provenance.trace_id:
            errors.append("Missing provenance trace_id")

        if not event.provenance.raw_event_hash:
            errors.append("Missing raw event hash")

        if not event.provenance.collector_id:
            errors.append("Missing collector_id")

    def _validate_metadata(
        self,
        event: ULPFEvent,
        errors: list[str],
    ) -> None:
        if not event.ulpf.schema_version:
            errors.append("Missing ULPF schema version")

        if not event.ulpf.parser_name:
            errors.append("Missing parser name")

        if not event.ulpf.parser_version:
            errors.append("Missing parser version")

        if not event.ulpf.mapping_id:
            errors.append("Missing mapping ID")

        if not event.ulpf.mapping_version:
            errors.append("Missing mapping version")