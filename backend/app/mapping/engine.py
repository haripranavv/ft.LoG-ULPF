from typing import Any

from .models import MappingDefinition


class MappingEngine:
    def apply(
        self,
        parsed_fields: dict[str, Any],
        mapping: MappingDefinition,
    ) -> dict[str, Any]:
        normalized: dict[str, Any] = {}

        for field_mapping in mapping.fields:
            if field_mapping.source_field not in parsed_fields:
                if field_mapping.required:
                    raise ValueError(
                        f"Required source field missing: "
                        f"{field_mapping.source_field}"
                    )
                continue

            value = parsed_fields[field_mapping.source_field]
            self._set_nested(normalized, field_mapping.target_field, value)

        return normalized

    def _set_nested(
        self,
        target: dict[str, Any],
        path: str,
        value: Any,
    ) -> None:
        parts = path.split(".")
        current = target

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value