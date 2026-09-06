import hashlib
from datetime import datetime, timezone

from app.schemas.event import (
    EventIdentity,
    NetworkEndpoint,
    NetworkInfo,
    Observer,
    Provenance,
    RawEvent,
    ULPFEvent,
    ULPFMetadata,
)


raw_payload = (
    "2026-09-05T10:00:00Z FW01 ALLOW "
    "SRC=10.10.10.25 DST=172.16.1.20 "
    "SP=49152 DP=443 PROTO=TCP"
)

raw_hash = hashlib.sha256(raw_payload.encode()).hexdigest()

event = ULPFEvent(
    event=EventIdentity(
        id="evt-demo-0001",
        kind="network",
        category="network",
        type="connection",
        action="allow",
        severity=3,
        outcome="success",
    ),
    timestamp=datetime.now(timezone.utc),
    source=NetworkEndpoint(
        ip="10.10.10.25",
        port=49152,
    ),
    destination=NetworkEndpoint(
        ip="172.16.1.20",
        port=443,
    ),
    network=NetworkInfo(
        transport="tcp",
        protocol="https",
        direction="outbound",
    ),
    observer=Observer(
        vendor="DemoFirewall",
        product="ULPF Test Firewall",
        hostname="FW01",
        device_type="firewall",
    ),
    ulpf=ULPFMetadata(
        schema_version="1.0.0",
        source_format="syslog",
        parser_name="demo_firewall_parser",
        parser_version="1.0.0",
        mapping_id="demo-firewall",
        mapping_version="1.0.0",
        normalization_status="success",
        processing_mode="deterministic",
    ),
    provenance=Provenance(
        trace_id="trace-demo-0001",
        raw_event_hash=raw_hash,
        hash_algorithm="SHA-256",
        ingestion_timestamp=datetime.now(timezone.utc),
        processing_timestamp=datetime.now(timezone.utc),
        collector_id="collector-demo-01",
    ),
    raw=RawEvent(
        preserved=True,
        encoding="utf-8",
        content_type="text/plain",
        payload=raw_payload,
    ),
)

print("ULPF EVENT VALID")
print()
print(event.model_dump_json(indent=2))
print()
print("SHA-256:", raw_hash)