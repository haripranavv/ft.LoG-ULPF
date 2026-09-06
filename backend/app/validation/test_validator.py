from app.mapping import FieldMapping, MappingDefinition, MappingEngine
from app.normalization import CanonicalEventBuilder
from app.parsers import ParserRegistry
from app.validation import EventValidator


raw_payload = (
    "2026-09-05T10:00:00Z FW01 ALLOW "
    "SRC=10.10.10.25 DST=172.16.1.20 "
    "SP=49152 DP=443 PROTO=TCP "
    "RULE=ALLOW_WEB USER=alice"
)

parser_registry = ParserRegistry()
parsed = parser_registry.parse(raw_payload)

mapping = MappingDefinition(
    mapping_id="acmeguard-firewall-v1",
    version="1.0.0",
    source_format="acmeguard",
    vendor="AcmeGuard",
    product="Firewall",
    fields=[
        FieldMapping(
            source_field="src",
            target_field="source.ip",
            confidence=1.0,
            required=True,
        ),
        FieldMapping(
            source_field="dst",
            target_field="destination.ip",
            confidence=1.0,
            required=True,
        ),
        FieldMapping(
            source_field="sport",
            target_field="source.port",
            confidence=1.0,
        ),
        FieldMapping(
            source_field="dport",
            target_field="destination.port",
            confidence=1.0,
        ),
        FieldMapping(
            source_field="protocol",
            target_field="network.protocol",
            confidence=1.0,
        ),
        FieldMapping(
            source_field="action",
            target_field="event.action",
            confidence=1.0,
        ),
        FieldMapping(
            source_field="rule",
            target_field="security.rule_id",
            confidence=1.0,
        ),
        FieldMapping(
            source_field="user",
            target_field="user.name",
            confidence=1.0,
        ),
    ],
)

mapping_engine = MappingEngine()

normalized = mapping_engine.apply(
    parsed.fields,
    mapping,
)

builder = CanonicalEventBuilder()

event = builder.build(
    raw_payload=raw_payload,
    normalized=normalized,
    source_format=parsed.source_format,
    parser_name="acmeguard",
    parser_version="1.0.0",
    mapping_id=mapping.mapping_id,
    mapping_version=mapping.version,
    vendor=parsed.vendor,
    product=parsed.product,
)

validator = EventValidator()

result = validator.validate(event)

print("VALID EVENT TEST")
print("Valid :", result.valid)
print("Errors:", result.errors)

assert result.valid is True
assert result.errors == []

print("\nTAMPER TEST")

event.raw.payload = event.raw.payload.replace(
    "ALLOW",
    "DENY",
    1,
)

tampered_result = validator.validate(event)

print("Valid :", tampered_result.valid)
print("Errors:", tampered_result.errors)

assert tampered_result.valid is False
assert "SHA-256 mismatch" in tampered_result.errors[0]

print("\nValidation tests passed.")