from .base import BaseParser, ParsedEvent
from .cef import CEFParser
from .json_parser import JSONParser
from .syslog import SyslogParser


class ParserRegistry:
    def __init__(self) -> None:
        self.parsers: list[BaseParser] = [
            CEFParser(),
            JSONParser(),
            SyslogParser(),
        ]

    def detect(self, raw_payload: str) -> BaseParser:
        for parser in self.parsers:
            if parser.can_parse(raw_payload):
                return parser

        raise ValueError("Unsupported or unrecognized log format")

    def parse(self, raw_payload: str) -> ParsedEvent:
        parser = self.detect(raw_payload)
        return parser.parse(raw_payload)