from typing import Any
from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel

from app.export.engine import export_engine
from app.storage.database import get_connection

router = APIRouter(
    prefix="/api/exports",
    tags=["Exports"],
)


class ExportRequest(BaseModel):
    target_type: str  # jsonl, webhook, elasticsearch, opensearch
    event_ids: list[str] | None = None
    limit: int = 500
    config: dict[str, Any] | None = None


def _fetch_events_to_export(event_ids: list[str] | None = None, limit: int = 500) -> list[dict[str, Any]]:
    """Helper to fetch events from PostgreSQL for export."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                if event_ids:
                    placeholders = ",".join(["%s"] * len(event_ids))
                    cursor.execute(
                        f"""
                        SELECT id, timestamp, event_type, action, severity, source_ip,
                               destination_ip, protocol, source_format, normalized_event, raw_payload
                        FROM normalized_events
                        WHERE id IN ({placeholders})
                        ORDER BY created_at DESC;
                        """,
                        event_ids,
                    )
                else:
                    cursor.execute(
                        """
                        SELECT id, timestamp, event_type, action, severity, source_ip,
                               destination_ip, protocol, source_format, normalized_event, raw_payload
                        FROM normalized_events
                        ORDER BY created_at DESC
                        LIMIT %s;
                        """,
                        (limit,),
                    )
                rows = cursor.fetchall()
                events = []
                for r in rows:
                    events.append({
                        "id": str(r[0]),
                        "timestamp": r[1].isoformat() if r[1] else None,
                        "event_type": r[2],
                        "action": r[3],
                        "severity": r[4],
                        "source_ip": str(r[5]) if r[5] else None,
                        "destination_ip": str(r[6]) if r[6] else None,
                        "protocol": r[7],
                        "source_format": r[8],
                        "normalized_event": r[9],
                        "raw_payload": r[10],
                    })
                return events
    except Exception as e:
        print(f"[ExportAPI] Notice: DB query fallback ({e})")
        return []


@router.get("")
def list_exports(limit: int = 50) -> dict[str, Any]:
    """Returns export jobs and supported exporter connectors."""
    exports = []
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, target_type, destination, status, event_count, config, error_message, created_at
                    FROM exports
                    ORDER BY created_at DESC
                    LIMIT %s;
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                for r in rows:
                    exports.append({
                        "id": str(r[0]),
                        "target_type": r[1],
                        "destination": r[2],
                        "status": r[3],
                        "event_count": r[4],
                        "config": r[5],
                        "error_message": r[6],
                        "created_at": r[7].isoformat() if r[7] else None,
                    })
    except Exception:
        pass

    return {
        "supported_targets": list(export_engine.exporters.keys()),
        "exports": exports,
    }


@router.post("")
def trigger_export(request: ExportRequest) -> dict[str, Any]:
    """Triggers an export of normalized events to JSONL, Webhook, or Elasticsearch/OpenSearch."""
    events = _fetch_events_to_export(request.event_ids, request.limit)
    if not events:
        raise HTTPException(
            status_code=400,
            detail="No events available to export. Ingest events first.",
        )

    try:
        return export_engine.run_export(
            target_type=request.target_type,
            events=events,
            config=request.config or {},
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))


@router.get("/download")
def download_jsonl(limit: int = Query(default=1000, le=10000)) -> Response:
    """Streams normalized events as a downloadable .jsonl file."""
    events = _fetch_events_to_export(limit=limit)
    res = export_engine.run_export("jsonl", events, {"filename": "ulpf-normalized-events.jsonl"})
    content = res.get("content", "")

    return Response(
        content=content,
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="ulpf-normalized-events.jsonl"'
        },
    )
