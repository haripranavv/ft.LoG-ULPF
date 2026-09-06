from app.mapping import FieldMapping, MappingDefinition, MappingEngine
from app.parsers import ParserRegistry


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

engine = MappingEngine()
normalized = engine.apply(parsed.fields, mapping)

print("Source fields:")
print(parsed.fields)

print("\nNormalized fields:")
print(normalized)