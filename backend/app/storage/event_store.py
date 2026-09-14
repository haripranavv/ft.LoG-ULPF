import json
from typing import Any
import uuid
from app.storage.database import get_connection


def store_ingestion(
    file_id: str,
    filename: str,
    sha256_hash: str,
    file_size_bytes: int,
    content_type: str,
    total_events: int,
    valid_events: int,
    invalid_events: int,
    status: str,
    storage_path: str,
    batch_merkle_root: str | None = None,
) -> None:
    """Inserts or updates an ingestion record in the PostgreSQL database."""
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ingestions (
                    id, filename, sha256_hash, file_size_bytes, content_type,
                    total_events, valid_events, invalid_events, status, storage_path, batch_merkle_root
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    total_events = EXCLUDED.total_events,
                    valid_events = EXCLUDED.valid_events,
                    invalid_events = EXCLUDED.invalid_events,
                    status = EXCLUDED.status,
                    batch_merkle_root = EXCLUDED.batch_merkle_root;
                """,
                (
                    file_id,
                    filename,
                    sha256_hash,
                    file_size_bytes,
                    content_type,
                    total_events,
                    valid_events,
                    invalid_events,
                    status,
                    storage_path,
                    batch_merkle_root,
                ),
            )
        conn.commit()


def store_events_batch(
    events: list[dict],
    ingestion_id: str | None = None,
    batch_merkle_root: str | None = None,
) -> int:
    """Batch inserts multiple normalized events in a single transaction with ingestion provenance."""
    if not events:
        return 0

    records = []
    for event in events:
        try:
            event_data = event.get("event", {})
            source = event.get("source", {})
            destination = event.get("destination", {})
            network = event.get("network", {})
            ulpf = event.get("ulpf", {})
            provenance = event.get("provenance", {})
            raw = event.get("raw", {})
            processing = event.get("processing", {})
            event_id = event_data.get("id")
            if not event_id:
                continue

            records.append((
                event_id,
                event.get("timestamp"),
                event_data.get("type"),
                event_data.get("action"),
                event_data.get("severity"),
                source.get("ip"),
                source.get("port"),
                destination.get("ip"),
                destination.get("port"),
                network.get("protocol"),
                ulpf.get("source_format"),
                ulpf.get("parser_name"),
                ulpf.get("parser_version"),
                ulpf.get("mapping_id"),
                ulpf.get("mapping_version"),
                ulpf.get("processing_mode"),
                ulpf.get("normalization_status"),
                processing.get("valid", False),
                provenance.get("raw_event_hash"),
                provenance.get("trace_id"),
                provenance.get("collector_id"),
                raw.get("payload", ""),
                json.dumps(event, default=str),
                ingestion_id,
                batch_merkle_root,
                provenance.get("ingestion_timestamp"),
                provenance.get("processing_timestamp"),
            ))
        except Exception:
            continue

    if not records:
        return 0

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO normalized_events(
                    id, timestamp, event_type, action, severity,
                    source_ip, source_port, destination_ip, destination_port, protocol,
                    source_format, parser_name, parser_version, mapping_id, mapping_version,
                    processing_mode, normalization_status, valid, raw_event_hash, trace_id,
                    collector_id, raw_payload, normalized_event, ingestion_id, batch_merkle_root,
                    ingestion_timestamp, processing_timestamp
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s
                )
                ON CONFLICT (id) DO NOTHING
                """,
                records,
            )
        conn.commit()

    return len(records)


def store_event(
    event: dict,
    ingestion_id: str | None = None,
    batch_merkle_root: str | None = None,
) -> None:
    """Store a single normalized event."""
    store_events_batch([event], ingestion_id, batch_merkle_root)


def upsert_devices_batch(devices: list[dict[str, Any]]) -> int:
    """Inserts or updates discovered devices in PostgreSQL."""
    if not devices:
        return 0

    records = []
    for d in devices:
        try:
            records.append((
                d["id"],
                d.get("name", "Unknown Device"),
                d.get("ip_address") or d.get("ip"),
                d.get("mac_address") or d.get("hardware_id"),
                d.get("manufacturer") or d.get("vendor"),
                d.get("device_type", "unknown"),
                float(d.get("device_type_confidence", 1.0)),
                d.get("discovery_method", "LAN ARP inspection"),
                d.get("status", "new"),
                json.dumps(d.get("metadata", {}), default=str),
            ))
        except Exception:
            continue

    if not records:
        return 0

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO devices (
                    id, name, ip_address, mac_address, manufacturer,
                    device_type, device_type_confidence, discovery_method,
                    first_seen, last_seen, status, metadata
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                    mac_address = COALESCE(EXCLUDED.mac_address, devices.mac_address),
                    manufacturer = COALESCE(EXCLUDED.manufacturer, devices.manufacturer),
                    device_type = EXCLUDED.device_type,
                    device_type_confidence = EXCLUDED.device_type_confidence,
                    last_seen = NOW(),
                    status = EXCLUDED.status,
                    metadata = EXCLUDED.metadata;
                """,
                records,
            )
        conn.commit()

    return len(records)


def record_export(
    target_type: str,
    destination: str,
    event_count: int,
    status: str = "completed",
    config: dict | None = None,
    error_message: str | None = None,
) -> str:
    """Logs an export action to PostgreSQL."""
    export_id = str(uuid.uuid4())
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO exports (
                        id, target_type, destination, status, event_count, config, error_message, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW());
                    """,
                    (
                        export_id,
                        target_type,
                        destination,
                        status,
                        event_count,
                        json.dumps(config or {}),
                        error_message,
                    ),
                )
            conn.commit()
    except Exception as e:
        print(f"[ExportStore] Notice: DB record deferred ({e})")
    return export_id