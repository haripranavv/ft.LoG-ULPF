from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ParsedEvent:
    source_format: str
    vendor: str | None
    product: str | None
    fields: dict[str, Any]
    raw_payload: str


class BaseParser(ABC):
    name: str = "base"
    version: str = "1.0.0"

    @abstractmethod
    def can_parse(self, raw_payload: str) -> bool:
        "Return True when this parser recognizes the event."

    @abstractmethod
    def parse(self, raw_payload: str) -> ParsedEvent:
        "Convert raw input into an intermediate representation."
