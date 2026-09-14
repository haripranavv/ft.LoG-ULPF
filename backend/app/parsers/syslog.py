import re
from typing import Any
from .base import BaseParser, ParsedEvent


class SyslogParser(BaseParser):
    name = "syslog"
    version = "1.2.0"

    # RFC 3164 and RFC 5424 pattern
    SYSLOG_REGEX = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?(?:\d+\s+)?"
        r"(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
        r"(?P<hostname>[A-Za-z0-9_\.\-]+)\s+"
        r"(?:(?P<app>[A-Za-z0-9_\.\-]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
        r"(?P<message>.*)$"
    )

    KV_PATTERN = re.compile(r'([A-Za-z0-9_\-\.]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=]+))')

    def can_parse(self, raw_payload: str) -> bool:
        payload = raw_payload.strip()
        if payload.startswith("{") or payload.startswith("CEF:"):
            return False
        return bool(self.SYSLOG_REGEX.match(payload))

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        match = self.SYSLOG_REGEX.match(payload)

        fields: dict[str, Any] = {}
        if match:
            groups = match.groupdict()
            if groups.get("pri"):
                pri_val = int(groups["pri"])
                fields["priority"] = pri_val
                # Facility is pri // 8, Severity is pri % 8
                fields["facility"] = pri_val // 8
                fields["severity"] = pri_val % 8

            if groups.get("timestamp"):
                fields["timestamp"] = groups["timestamp"]
            if groups.get("hostname"):
                fields["hostname"] = groups["hostname"]
            if groups.get("app"):
                fields["app"] = groups["app"]
            if groups.get("pid"):
                fields["pid"] = int(groups["pid"])

            body = groups.get("message") or ""
            fields["message"] = body

            # Extract any inner key-value tokens from syslog message
            inner_kvs = self.KV_PATTERN.findall(body)
            for k, q1, q2, uq in inner_kvs:
                val = q1 or q2 or uq
                if k not in fields:
                    fields[k] = val
        else:
            fields["message"] = payload

        return ParsedEvent(
            source_format="syslog",
            vendor=fields.get("vendor") or fields.get("dev"),
            product=fields.get("app") or fields.get("product"),
            fields=fields,
            raw_payload=raw_payload,
        )