import json
from pathlib import Path

from .models import MappingDefinition


class MappingRegistry:
    def __init__(self, definitions_dir: str | Path) -> None:
        self.definitions_dir = Path(definitions_dir)
        self._mappings: list[MappingDefinition] = []
        self._load()

    def _load(self) -> None:
        if not self.definitions_dir.exists():
            raise FileNotFoundError(
                f"Mapping definitions directory not found: {self.definitions_dir}"
            )

        self._mappings.clear()

        for path in self.definitions_dir.glob("*.json"):
            with path.open("r", encoding="utf-8") as file:
                definition = MappingDefinition.model_validate(
                    json.load(file)
                )

            self._mappings.append(definition)

    def reload(self) -> None:
        self._load()

    def get(
        self,
        source_format: str,
        vendor: str | None = None,
        product: str | None = None,
    ) -> MappingDefinition:

        candidates = [
            mapping
            for mapping in self._mappings
            if mapping.source_format == source_format
        ]

        if vendor:
            candidates = [
                mapping
                for mapping in candidates
                if mapping.vendor == vendor
            ]

        if product:
            candidates = [
                mapping
                for mapping in candidates
                if mapping.product == product
            ]

        if not candidates:
            raise ValueError(
                "No mapping registered for "
                f"source_format={source_format}, "
                f"vendor={vendor}, "
                f"product={product}"
            )

        return candidates[0]

    def list_all(self) -> list[MappingDefinition]:
        return self._mappings.copy()