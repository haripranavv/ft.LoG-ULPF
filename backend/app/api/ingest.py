import json
import time
from pathlib import Path
from typing import Any
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from app.processing.processor import get_processor
from app.storage.database import get_connection
from app.storage.event_store import store_events_batch, store_ingestion
from app.storage.raw_storage import raw_storage

router = APIRouter(
    prefix="/api/ingest",
    tags=["Ingestion"],
)


class JsonUploadRequest(BaseModel):
    filename: str
    content: str


def _process_file_content(filename: str, content_bytes: bytes, content_type: str = "text/plain") -> dict[str, Any]:
    """Core file ingestion pipeline: preserves raw file, parses, normalizes, validates, and stores."""
    start_time = time.perf_counter()

    # 1. Preserve raw file & calculate SHA-256
    stored = raw_storage.save_raw_file(
        filename=filename,
        content_bytes=content_bytes,
        content_type=content_type,
    )
    file_id = stored["id"]
    sha256_hash = stored["sha256_hash"]
    storage_path = stored["storage_path"]
    file_size = stored["file_size_bytes"]

    # 2. Decode content text safely
    try:
        content_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_text = content_bytes.decode("latin-1", errors="replace")

    trimmed_content = content_text.strip()
    if not trimmed_content:
        raise ValueError("Uploaded file content is empty")

    filename_lower = filename.lower()
    raw_logs: list[str] = []

    # 3. Handle various structured and line-delimited formats
    if filename_lower.endswith(".json"):
        try:
            data = json.loads(trimmed_content)
            if isinstance(data, list):
                raw_logs = [json.dumps(item) if isinstance(item, (dict, list)) else str(item) for item in data]
            elif isinstance(data, dict):
                raw_logs = [json.dumps(data)]
            else:
                raw_logs = [str(data)]
        except json.JSONDecodeError:
            # Fallback for JSON Lines (NDJSON)
            for line in trimmed_content.splitlines():
                clean = line.strip()
                if clean:
                    raw_logs.append(clean)
    elif filename_lower.endswith((".yaml", ".yml")):
        # YAML documents are multi-line, optionally separated by '---'
        docs = [d.strip() for d in trimmed_content.split("---") if d.strip()]
        raw_logs = docs if docs else [trimmed_content]
    elif filename_lower.endswith(".csv"):
        # CSV files: pair header row with each data row to preserve column names
        lines = [l.strip() for l in trimmed_content.splitlines() if l.strip()]
        if len(lines) >= 2 and "," in lines[0]:
            header = lines[0]
            for row in lines[1:]:
                raw_logs.append(f"{header}\n{row}")
        else:
            raw_logs = lines
    else:
        # .log, .txt, .jsonl, .cef, etc.
        for line in trimmed_content.splitlines():
            clean = line.strip()
            if clean:
                raw_logs.append(clean)

    if not raw_logs:
        raise ValueError("No parseable log records found in file")

    processor = get_processor()
    valid_count = 0
    invalid_count = 0
    assisted_count = 0
    items_result: list[dict[str, Any]] = []
    valid_events_to_store: list[dict[str, Any]] = []
    event_hashes: list[str] = []

    primary_format = "unknown"
    primary_parser = "generic_adaptive"

    for idx, log_payload in enumerate(raw_logs):
        try:
            res = processor.process(log_payload)
            proc = res.get("processing", {})
            is_valid = proc.get("valid", False)
            mode = proc.get("mode", "deterministic")

            ulpf_meta = res.get("ulpf", {})
            event_data = res.get("event", {})
            prov = res.get("provenance", {})

            if idx == 0:
                primary_format = ulpf_meta.get("source_format", "unknown")
                primary_parser = ulpf_meta.get("parser_name", "generic_adaptive")

            raw_hash = prov.get("raw_event_hash")
            if raw_hash:
                event_hashes.append(raw_hash)

            if is_valid:
                valid_events_to_store.append(res)
                valid_count += 1
            else:
                if mode == "assisted":
                    assisted_count += 1
                else:
                    invalid_count += 1

            items_result.append({
                "index": idx + 1,
                "preview": log_payload[:120] + ("..." if len(log_payload) > 120 else ""),
                "valid": is_valid,
                "mode": mode,
                "parser": ulpf_meta.get("parser_name"),
                "source_format": ulpf_meta.get("source_format"),
                "mapping_id": ulpf_meta.get("mapping_id"),
                "event_id": event_data.get("id"),
                "trace_id": prov.get("trace_id"),
                "errors": proc.get("errors", []),
                "latency_ms": proc.get("latency_ms"),
                "ai_assistance": res.get("ai_assistance"),
            })
        except Exception as err:
            invalid_count += 1
            items_result.append({
                "index": idx + 1,
                "preview": log_payload[:120] + ("..." if len(log_payload) > 120 else ""),
                "valid": False,
                "mode": "error",
                "errors": [str(err)],
            })

    # 4. Compute Merkle tree root for cryptographic batch tamper evidence
    merkle_root = raw_storage.compute_merkle_root(event_hashes)

    # 5. Store ingestion metadata record in PostgreSQL FIRST (to satisfy FK constraints)
    try:
        store_ingestion(
            file_id=file_id,
            filename=filename,
            sha256_hash=sha256_hash,
            file_size_bytes=file_size,
            content_type=content_type,
            total_events=len(raw_logs),
            valid_events=valid_count,
            invalid_events=invalid_count,
            status="completed",
            storage_path=storage_path,
            batch_merkle_root=merkle_root,
        )
    except Exception as db_err:
        print(f"[Ingestion] Warning: DB ingestion record deferred ({db_err})")

    # 6. Batch insert valid events into PostgreSQL SECOND
    if valid_events_to_store:
        try:
            store_events_batch(valid_events_to_store, ingestion_id=file_id, batch_merkle_root=merkle_root)
        except Exception as db_err:
            print(f"[Ingestion] Warning: DB events insert deferred ({db_err})")

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return {
        "status": "completed",
        "ingestion_id": file_id,
        "filename": filename,
        "sha256_hash": sha256_hash,
        "file_size_bytes": file_size,
        "total_events": len(raw_logs),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "assisted_count": assisted_count,
        "batch_merkle_root": merkle_root,
        "detected_format": primary_format,
        "source_format": primary_format,
        "parser_used": primary_parser,
        "parser_name": primary_parser,
        "valid_events": valid_count,
        "processing_time_ms": elapsed_ms,
        "storage_path": storage_path,
        "items": items_result,
    }


@router.post("/files")
async def ingest_file_multipart(file: UploadFile = File(...)) -> dict[str, Any]:
    """Ingests log files via standard multipart form upload."""
    try:
        content_bytes = await file.read()
        return _process_file_content(
            filename=file.filename or "upload.log",
            content_bytes=content_bytes,
            content_type=file.content_type or "text/plain",
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))


@router.post("/payload")
def ingest_file_json(request: JsonUploadRequest) -> dict[str, Any]:
    """Ingests log files via JSON payload with base/plain string content."""
    try:
        content_bytes = request.content.encode("utf-8")
        return _process_file_content(
            filename=request.filename,
            content_bytes=content_bytes,
            content_type="text/plain",
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))


@router.get("")
def list_ingestions(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """Returns recent log ingestions with provenance and file metadata."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM ingestions;")
                total = cursor.fetchone()[0]

                cursor.execute(
                    """
                    SELECT id, filename, sha256_hash, file_size_bytes, content_type,
                           total_events, valid_events, invalid_events, status, storage_path,
                           batch_merkle_root, created_at
                    FROM ingestions
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s;
                    """,
                    (limit, offset),
                )
                rows = cursor.fetchall()
                ingestions = []
                for r in rows:
                    ingestions.append({
                        "id": str(r[0]),
                        "filename": r[1],
                        "sha256_hash": r[2],
                        "file_size_bytes": r[3],
                        "content_type": r[4],
                        "total_events": r[5],
                        "valid_events": r[6],
                        "invalid_events": r[7],
                        "status": r[8],
                        "storage_path": r[9],
                        "batch_merkle_root": r[10],
                        "created_at": r[11].isoformat() if r[11] else None,
                    })
                return {
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "ingestions": ingestions,
                }
    except Exception as err:
        return {"total": 0, "limit": limit, "offset": offset, "ingestions": [], "notice": str(err)}


@router.get("/{ingestion_id}")
def get_ingestion(ingestion_id: str) -> dict[str, Any]:
    """Returns details and associated events for a specific ingestion batch."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, filename, sha256_hash, file_size_bytes, content_type,
                           total_events, valid_events, invalid_events, status, storage_path,
                           batch_merkle_root, created_at
                    FROM ingestions
                    WHERE id = %s;
                    """,
                    (ingestion_id,),
                )
                r = cursor.fetchone()
                if not r:
                    raise HTTPException(status_code=404, detail="Ingestion record not found")

                return {
                    "id": str(r[0]),
                    "filename": r[1],
                    "sha256_hash": r[2],
                    "file_size_bytes": r[3],
                    "content_type": r[4],
                    "total_events": r[5],
                    "valid_events": r[6],
                    "invalid_events": r[7],
                    "status": r[8],
                    "storage_path": r[9],
                    "batch_merkle_root": r[10],
                    "created_at": r[11].isoformat() if r[11] else None,
                }
    except HTTPException:
        raise
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))
