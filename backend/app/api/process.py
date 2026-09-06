from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.processing.processor import ULPFProcessor
from app.storage.event_store import store_event


router = APIRouter(
    prefix="/api/process",
    tags=["Processing"],
)


class ProcessRequest(BaseModel):
    raw_payload: str


class UploadRequest(BaseModel):
    filename: str
    content: str


@router.post("")
def process_log(
    request: ProcessRequest,
) -> dict[str, Any]:

    try:
        mapping_dir = (
            Path(__file__).resolve()
            .parent.parent
            / "mapping"
            / "definitions"
        )

        processor = ULPFProcessor(
            str(mapping_dir)
        )

        result = processor.process(
            request.raw_payload
        )

        if result.get("processing", {}).get("valid"):
            store_event(result)

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@router.post("/upload")
def upload_log(
    request: UploadRequest,
) -> dict[str, Any]:
    """
    Ingest uploaded .log, .txt, or .json file through the ULPF processing pipeline.
    Supports single or batch payloads, stores valid events, and reports itemized results.
    """
    try:
        mapping_dir = (
            Path(__file__).resolve()
            .parent.parent
            / "mapping"
            / "definitions"
        )

        processor = ULPFProcessor(str(mapping_dir))

        raw_logs: list[str] = []
        filename_lower = request.filename.lower()
        trimmed_content = request.content.strip()

        if not trimmed_content:
            raise ValueError("Uploaded file is empty")

        if filename_lower.endswith(".json"):
            import json
            try:
                data = json.loads(trimmed_content)
                if isinstance(data, list):
                    raw_logs = [json.dumps(item) if isinstance(item, (dict, list)) else str(item) for item in data]
                elif isinstance(data, dict):
                    raw_logs = [json.dumps(data)]
                else:
                    raw_logs = [str(data)]
            except json.JSONDecodeError:
                # Handle JSON lines (newline delimited JSON)
                for line in trimmed_content.splitlines():
                    clean = line.strip()
                    if clean:
                        raw_logs.append(clean)
        else:
            # .log, .txt or other text
            for line in trimmed_content.splitlines():
                clean = line.strip()
                if clean:
                    raw_logs.append(clean)

        if not raw_logs:
            raise ValueError("No parseable log lines found in uploaded content")

        valid_count = 0
        invalid_count = 0
        assisted_count = 0
        items_result: list[dict[str, Any]] = []

        for idx, log_payload in enumerate(raw_logs):
            try:
                res = processor.process(log_payload)
                proc = res.get("processing", {})
                is_valid = proc.get("valid", False)
                mode = proc.get("mode", "deterministic")

                if is_valid:
                    store_event(res)
                    valid_count += 1
                else:
                    if mode == "assisted":
                        assisted_count += 1
                    else:
                        invalid_count += 1

                ulpf_meta = res.get("ulpf", {})
                event_data = res.get("event", {})
                prov = res.get("provenance", {})

                items_result.append({
                    "index": idx + 1,
                    "preview": log_payload[:120] + ("..." if len(log_payload) > 120 else ""),
                    "valid": is_valid,
                    "mode": mode,
                    "parser": ulpf_meta.get("parser_name"),
                    "mapping_id": ulpf_meta.get("mapping_id"),
                    "event_id": event_data.get("id"),
                    "trace_id": prov.get("trace_id"),
                    "errors": proc.get("errors", []),
                    "reason": proc.get("reason"),
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

        return {
            "status": "completed",
            "filename": request.filename,
            "total_logs": len(raw_logs),
            "valid_count": valid_count,
            "invalid_count": invalid_count,
            "assisted_count": assisted_count,
            "items": items_result,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )