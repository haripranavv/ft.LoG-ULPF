from typing import Any
from fastapi import APIRouter, HTTPException, Query
from app.storage.database import get_connection

router = APIRouter(prefix="/api/events", tags=["events"])

@router.get("")
def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None),
    source_format: str | None = Query(default=None),
    valid: bool | None = Query(default=None),
) -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            query = """
                SELECT
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
                    processing_timestamp,
                    created_at
                FROM normalized_events
                WHERE 1=1
            """
            params: list[Any] = []

            if search:
                query += " AND (raw_payload ILIKE %s OR action ILIKE %s OR event_type ILIKE %s)"
                term = f"%{search.strip()}%"
                params.extend([term, term, term])

            if source_format:
                query += " AND source_format = %s"
                params.append(source_format.strip())

            if valid is not None:
                query += " AND valid = %s"
                params.append(valid)

            # Count total matching query
            count_query = f"SELECT COUNT(*) FROM ({query}) AS total_filtered"
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()[0]

            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()

    events = []
    for row in rows:
        events.append(
            {
                "id": str(row[0]),
                "timestamp": row[1].isoformat() if row[1] else None,
                "event_type": row[2],
                "action": row[3],
                "severity": row[4],
                "source": {
                    "ip": str(row[5]) if row[5] else None,
                    "port": row[6],
                },
                "destination": {
                    "ip": str(row[7]) if row[7] else None,
                    "port": row[8],
                },
                "protocol": row[9],
                "source_format": row[10],
                "parser": {
                    "name": row[11],
                    "version": row[12],
                },
                "mapping": {
                    "id": row[13],
                    "version": row[14],
                },
                "processing_mode": row[15],
                "normalization_status": row[16],
                "valid": row[17],
                "raw_event_hash": row[18],
                "trace_id": str(row[19]) if row[19] else None,
                "collector_id": row[20],
                "raw_payload": row[21],
                "normalized_event": row[22],
                "ingestion_timestamp": row[23].isoformat() if row[23] else None,
                "processing_timestamp": row[24].isoformat() if row[24] else None,
                "created_at": row[25].isoformat() if row[25] else None,
            }
        )

    return {
        "count": len(events),
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "events": events,
    }

@router.get("/{event_id}")
def get_event(event_id: str) -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
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
                    processing_timestamp,
                    created_at
                FROM normalized_events
                WHERE id = %s
                """,
                (event_id,),
            )
            row = cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    return {
        "id": str(row[0]),
        "timestamp": row[1].isoformat() if row[1] else None,
        "event_type": row[2],
        "action": row[3],
        "severity": row[4],
        "source": {
            "ip": str(row[5]) if row[5] else None,
            "port": row[6],
        },
        "destination": {
            "ip": str(row[7]) if row[7] else None,
            "port": row[8],
        },
        "protocol": row[9],
        "source_format": row[10],
        "parser": {
            "name": row[11],
            "version": row[12],
        },
        "mapping": {
            "id": row[13],
            "version": row[14],
        },
        "processing_mode": row[15],
        "normalization_status": row[16],
        "valid": row[17],
        "raw_event_hash": row[18],
        "trace_id": str(row[19]) if row[19] else None,
        "collector_id": row[20],
        "raw_payload": row[21],
        "normalized_event": row[22],
        "ingestion_timestamp": row[23].isoformat() if row[23] else None,
        "processing_timestamp": row[24].isoformat() if row[24] else None,
        "created_at": row[25].isoformat() if row[25] else None,
    }
