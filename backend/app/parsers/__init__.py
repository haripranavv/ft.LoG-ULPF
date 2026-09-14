from .base import BaseParser, ParsedEvent
from .acmeguard import AcmeGuardParser
from .openvpn import OpenVPNParser
from .cisco_ios import CiscoIOSParser
from .suricata import SuricataParser
from .discovery import DiscoveryParser
from .cef import CEFParser
from .json_parser import JSONParser
from .syslog import SyslogParser
from .key_value import KeyValueParser
from .csv_parser import CSVParser
from .yaml_parser import YAMLParser


class ParserRegistry:
    def __init__(self) -> None:
        self.parsers: list[BaseParser] = [
            AcmeGuardParser(),
            OpenVPNParser(),
            CiscoIOSParser(),
            SuricataParser(),
            DiscoveryParser(),
            CEFParser(),
            JSONParser(),
            SyslogParser(),
            KeyValueParser(),
            CSVParser(),
            YAMLParser(),
        ]

    def parse(self, raw_payload: str) -> ParsedEvent:
        for parser in self.parsers:
            if parser.can_parse(raw_payload):
                return parser.parse(raw_payload)

        raise ValueError(
            "Unknown log format. No deterministic parser matched the payload."
        )

    def detect(self, raw_payload: str) -> str | None:
        for parser in self.parsers:
            if parser.can_parse(raw_payload):
                return parser.name

        return None

    def list_parsers(self) -> list[dict]:
        return [
            {
                "name": parser.name,
                "version": parser.version,
            }
            for parser in self.parsers
        ]