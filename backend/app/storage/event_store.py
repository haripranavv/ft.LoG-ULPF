import json

from app.storage.database import get_connection


def store_event(event: dict) -> None:
    event_data = event["event"]
    source = event.get("source", {})
    destination = event.get("destination", {})
    network = event.get("network", {})
    ulpf = event.get("ulpf", {})
    provenance = event.get("provenance", {})
    raw = event.get("raw", {})
    processing = event.get("processing", {})

    event_id = event_data["id"]

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO normalized_events(
                    id,
                    timestamp,
                    event_type,
                    action,
                    severity,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    source_format,
                    parser_name,
                    parser_version,
                    mapping_id,
                    mapping_version,
                    processing_mode,
                    normalization_status,
                    valid,
                    raw_event_hash,
                    trace_id,
                    collector_id,
                    raw_payload,
                    normalized_event,
                    ingestion_timestamp,
                    processing_timestamp
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                ON CONFLICT (id) DO NOTHING
                """,
                (
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
                    provenance.get("ingestion_timestamp"),
                    provenance.get("processing_timestamp"),
                ),
            )

        conn.commit()