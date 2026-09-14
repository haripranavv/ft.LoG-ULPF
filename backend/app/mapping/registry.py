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

        format_matches = [
            mapping
            for mapping in self._mappings
            if mapping.source_format == source_format
        ]

        if not format_matches:
            raise ValueError(
                f"No mapping registered for source_format={source_format}"
            )

        # 1. Exact match (format, vendor, product)
        if vendor and product:
            exact = [m for m in format_matches if m.vendor == vendor and m.product == product]
            if exact:
                return exact[0]

        # 2. Match format and vendor
        if vendor:
            vendor_match = [m for m in format_matches if m.vendor == vendor]
            if vendor_match:
                return vendor_match[0]

        # 3. Generic fallback mapping (where vendor is None or matches "generic")
        generic_match = [m for m in format_matches if not m.vendor or m.vendor.lower() == "generic"]
        if generic_match:
            return generic_match[0]

        # No suitable mapping found
        raise ValueError(
            "No mapping registered for "
            f"source_format={source_format}, "
            f"vendor={vendor}, "
            f"product={product}"
        )

    def list_all(self) -> list[MappingDefinition]:
        return self._mappings.copy()