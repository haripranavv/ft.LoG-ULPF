import re
from typing import Any

from .base import BaseParser, ParsedEvent


def is_escaped(s: str, pos: int) -> bool:
    """Returns True if the character at pos is preceded by an odd number of backslashes."""
    count = 0
    i = pos - 1
    while i >= 0 and s[i] == "\\":
        count += 1
        i -= 1
    return (count % 2) == 1


def unescape_cef_value(val: str) -> str:
    """
    Unescapes CEF escape sequences:
    \\= -> =
    \\\\ -> \\
    \\n -> newline
    \\r -> carriage return
    \\| -> |
    """
    result = []
    i = 0
    n = len(val)
    while i < n:
        if val[i] == "\\" and i + 1 < n:
            nxt = val[i + 1]
            if nxt in ("=", "\\", "n", "r", "|"):
                if nxt == "n":
                    result.append("\n")
                elif nxt == "r":
                    result.append("\r")
                else:
                    result.append(nxt)
                i += 2
            else:
                result.append(val[i])
                i += 1
        else:
            result.append(val[i])
            i += 1
    return "".join(result)


def split_cef_header(raw_payload: str) -> list[str]:
    """
    Splits the CEF string into 8 components on unescaped '|' characters.
    Header contains 7 pipes separating:
    [0] CEF:Version
    [1] Device Vendor
    [2] Device Product
    [3] Device Version
    [4] Device Event Class ID (Signature ID)
    [5] Name
    [6] Severity
    [7] Extension
    """
    parts = []
    current = []
    i = 0
    n = len(raw_payload)
    pipes_found = 0

    while i < n:
        if raw_payload[i] == "\\" and i + 1 < n and pipes_found < 7:
            nxt = raw_payload[i + 1]
            if nxt in ("|", "\\"):
                current.append(raw_payload[i : i + 2])
                i += 2
                continue
        if raw_payload[i] == "|" and pipes_found < 7:
            parts.append("".join(current))
            current = []
            pipes_found += 1
            i += 1
            continue
        current.append(raw_payload[i])
        i += 1

    parts.append("".join(current))
    return parts


def parse_cef_extension(extension_str: str) -> dict[str, str]:
    """
    Robustly parses CEF extension key-value pairs:
    - Correctly detects key=value boundaries without splitting on spaces.
    - Allows values to contain spaces and special characters.
    - Supports escaped characters (\\=, \\\\, \\n, \\r).
    - Identifies the next valid key=value token as the boundary for the previous value.
    """
    if not extension_str or not extension_str.strip():
        return {}

    # Key consists of alphanumeric characters, underscores, hyphens, and dots.
    # Preceded by start of string or whitespace, followed immediately by an unescaped '='.
    pattern = re.compile(r"(?:^|\s+)([A-Za-z0-9_.-]+)=")
    matches = []

    for m in pattern.finditer(extension_str):
        eq_pos = m.end() - 1
        if not is_escaped(extension_str, eq_pos):
            matches.append((m.group(1), m.start(), m.end()))

    if not matches:
        return {}

    fields: dict[str, str] = {}
    for i, (key, m_start, m_end) in enumerate(matches):
        val_start = m_end
        if i + 1 < len(matches):
            val_end = matches[i + 1][1]
        else:
            val_end = len(extension_str)

        raw_val = extension_str[val_start:val_end].strip()
        fields[key] = unescape_cef_value(raw_val)

    return fields


class CEFParser(BaseParser):
    name = "cef"
    version = "1.0.0"

    def can_parse(self, raw_payload: str) -> bool:
        return raw_payload.strip().startswith("CEF:")

    def parse(self, raw_payload: str) -> ParsedEvent:
        payload = raw_payload.strip()
        parts = split_cef_header(payload)

        if len(parts) < 8:
            raise ValueError("Invalid CEF payload: expected 7 header pipes separating 8 parts")

        version = unescape_cef_value(parts[0].replace("CEF:", "", 1).strip())
        vendor = unescape_cef_value(parts[1].strip())
        product = unescape_cef_value(parts[2].strip())
        device_version = unescape_cef_value(parts[3].strip())
        signature_id = unescape_cef_value(parts[4].strip())
        name = unescape_cef_value(parts[5].strip())
        severity = unescape_cef_value(parts[6].strip())
        extension_str = parts[7]

        fields: dict[str, Any] = {
            "cef_version": version,
            "vendor": vendor,
            "product": product,
            "device_version": device_version,
            "signature_id": signature_id,
            "name": name,
            "severity": severity,
        }

        # Parse extension fields with boundary detection
        extension_fields = parse_cef_extension(extension_str)
        fields.update(extension_fields)

        return ParsedEvent(
            source_format="cef",
            vendor=vendor,
            product=product,
            fields=fields,
            raw_payload=raw_payload,
        )
