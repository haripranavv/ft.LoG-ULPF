import json
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.mapping.models import FieldMapping, MappingDefinition
from app.mapping.registry import MappingRegistry


router = APIRouter(
    prefix="/api/mappings",
    tags=["Mappings"],
)


class MappingApprovalRequest(BaseModel):
    mapping_id: str
    version: str = "1.0"
    source_format: str
    vendor: str | None = None
    product: str | None = None
    fields: list[FieldMapping] = Field(min_length=1)


@router.post("")
@router.post("/approve")
def approve_mapping(
    request: MappingApprovalRequest,
) -> dict[str, Any]:

    try:
        safe_mapping_id = re.sub(
            r"[^a-zA-Z0-9_-]",
            "-",
            request.mapping_id.strip(),
        ).lower()

        if not safe_mapping_id:
            raise ValueError("mapping_id cannot be empty")

        mapping = MappingDefinition(
            mapping_id=safe_mapping_id,
            version=request.version,
            source_format=request.source_format,
            vendor=request.vendor,
            product=request.product,
            fields=request.fields,
        )

        definitions_dir = (
            Path(__file__).resolve()
            .parent.parent
            / "mapping"
            / "definitions"
        )

        definitions_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_path = (
            definitions_dir
            / f"{safe_mapping_id}.json"
        )

        with file_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                mapping.model_dump(),
                file,
                indent=4,
            )

        # Reload mapping registry so new mapping is immediately active in runtime
        proc = get_processor()
        proc.mapping_registry.reload()

        return {
            "status": "mapping_approved",
            "mapping_id": safe_mapping_id,
            "file": file_path.name,
            "message": (
                "Mapping saved successfully. "
                "Future matching logs can now use deterministic processing."
            ),
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


@router.get("")
def list_mappings() -> list[dict[str, Any]]:
    """List all registered versioned mapping definitions."""
    definitions_dir = (
        Path(__file__).resolve().parent.parent
        / "mapping"
        / "definitions"
    )
    registry = MappingRegistry(str(definitions_dir))
    mappings = registry.list_all()
    return [m.model_dump() for m in mappings]


@router.get("/samples")
def get_sample_logs() -> list[dict[str, Any]]:
    """Return pre-configured sample logs for testing deterministic & assisted workflows."""
    return [
        {
            "id": "acmeguard",
            "name": "AcmeGuard Perimeter Firewall",
            "category": "Pre-Mapped (Deterministic)",
            "log": "2026-09-06T10:00:00Z FW01 ALLOW SRC=10.10.10.25 DST=172.16.1.20 SP=49152 DP=443 PROTO=TCP RULE=ALLOW_WEB USER=alice",
        },
        {
            "id": "openvpn",
            "name": "OpenVPN Gateway",
            "category": "Pre-Mapped (Deterministic)",
            "log": "2026-09-06T10:20:00Z alice CONNECTED SRC=203.0.113.10 VPN_IP=10.8.0.5",
        },
        {
            "id": "cisco_ios",
            "name": "Cisco IOS Core Router",
            "category": "Pre-Mapped (Deterministic)",
            "log": "2026-09-06T10:30:00Z R1 %SYS-5-CONFIG_I: Configured from console",
        },
        {
            "id": "suricata",
            "name": "Suricata IDS Alert",
            "category": "Pre-Mapped (Deterministic)",
            "log": json.dumps({
                "timestamp": "2026-09-06T10:40:00Z",
                "event_type": "alert",
                "src_ip": "192.168.1.50",
                "src_port": 54321,
                "dest_ip": "10.0.0.10",
                "dest_port": 443,
                "proto": "TCP",
                "alert": {
                    "signature": "Possible malicious traffic",
                    "severity": 2,
                    "category": "Attempted Admin"
                }
            }),
        },
        {
            "id": "discovery",
            "name": "ULPF Discovery Event",
            "category": "Pre-Mapped (Deterministic)",
            "log": "2026-09-06T15:30:00Z DISCOVERY type=lan ip=10.153.7.104 mac=e6:39:bc:f7:bf:98 hostname=gateway status=known vendor=ULPF-Scanner",
        },
        {
            "id": "unmapped_gateway",
            "name": "Unknown Perimeter Gateway",
            "category": "Unmapped (Triggers Onboarding Flow)",
            "log": "vendor=PerimeterGateway dev=CloudEdge action=DENY srcaddr=198.51.100.44 dstaddr=10.0.4.1 sport=50212 dport=22 threat_name=SSHBruteForce custom_severity=CRITICAL user=root",
        },
        {
            "id": "unstructured_auth",
            "name": "Custom Key-Value Access Gateway",
            "category": "Unmapped (Triggers Onboarding Flow)",
            "log": "vendor=AuthCorp dev=AccessGateway event=login_failed client_ip=192.0.2.77 target_host=auth.internal port=8443 reason=bad_credential user=secops_admin severity=HIGH",
        },
    ]


class TimelineRequest(BaseModel):
    raw_payload: str


DEFINITIONS_DIR = (
    Path(__file__).resolve().parent.parent
    / "mapping"
    / "definitions"
)
_shared_processor: Any = None


def get_processor() -> Any:
    global _shared_processor
    if _shared_processor is None:
        from app.processing.processor import ULPFProcessor
        _shared_processor = ULPFProcessor(str(DEFINITIONS_DIR))
    return _shared_processor


@router.post("/timeline")
def analyze_timeline(request: TimelineRequest) -> dict[str, Any]:
    """
    Execute the genuine ULPF 8-stage onboarding flow:
    1. Raw Log Received
    2. Format Detection
    3. Field Extraction
    4. Mapping Analysis
    5. AI / Rule-Based Mapping Proposal
    6. Human Approval Required
    7. Versioned Mapping Created
    8. Deterministic Processing Activated
    """
    from datetime import datetime, timezone
    from hashlib import sha256

    payload = request.raw_payload.strip()
    if not payload:
        raise HTTPException(status_code=400, detail="Empty payload")

    processor = get_processor()
    parser_registry = processor.parser_registry
    mapping_registry = MappingRegistry(str(DEFINITIONS_DIR))
    mapping_assistant = processor.mapping_assistant

    now_iso = datetime.now(timezone.utc).isoformat()
    raw_hash = sha256(payload.encode("utf-8")).hexdigest()

    # Stage 1: Raw Log Received
    stage1 = {
        "stage": 1,
        "name": "Raw Log Received",
        "status": "completed",
        "timestamp": now_iso,
        "details": {
            "bytes": len(payload.encode("utf-8")),
            "sha256": raw_hash,
            "raw_payload": payload,
        },
    }

    # Stage 2: Format Detection
    detected_parser_name = parser_registry.detect(payload)
    parsed_event = None
    if detected_parser_name:
        try:
            parsed_event = parser_registry.parse(payload)
        except Exception:
            pass

    stage2 = {
        "stage": 2,
        "name": "Format Detection",
        "status": "completed" if detected_parser_name else "unrecognized",
        "details": {
            "matched_parser": detected_parser_name or "None (No deterministic parser matched)",
            "source_format": parsed_event.source_format if parsed_event else "unknown",
            "vendor": parsed_event.vendor if parsed_event else "Unknown",
            "product": parsed_event.product if parsed_event else "Unknown",
        },
    }

    # Stage 3: Field Extraction
    extracted_fields: dict[str, Any] = {}
    if parsed_event:
        extracted_fields = parsed_event.fields
    else:
        # Fallback to field value extractor
        extracted_fields = mapping_assistant._extract_field_values(payload)

    stage3 = {
        "stage": 3,
        "name": "Field Extraction",
        "status": "completed" if extracted_fields else "warning",
        "details": {
            "fields": extracted_fields,
            "field_count": len(extracted_fields),
        },
    }

    # Stage 4: Mapping Analysis
    existing_mapping: MappingDefinition | None = None
    if parsed_event:
        try:
            existing_mapping = mapping_registry.get(
                source_format=parsed_event.source_format,
                vendor=parsed_event.vendor,
                product=parsed_event.product,
            )
        except ValueError:
            existing_mapping = None

    stage4 = {
        "stage": 4,
        "name": "Mapping Analysis",
        "status": "existing_mapping" if existing_mapping else "missing_mapping",
        "details": {
            "has_mapping": existing_mapping is not None,
            "mapping_id": existing_mapping.mapping_id if existing_mapping else None,
            "version": existing_mapping.version if existing_mapping else None,
            "registered_fields_count": len(existing_mapping.fields) if existing_mapping else 0,
            "note": (
                "Deterministic schema already active."
                if existing_mapping
                else "No matching mapping schema registered. Triggering onboarding proposal engine."
            ),
        },
    }

    # Stage 5: AI / Rule-Based Mapping Proposal
    proposals: list[dict[str, Any]] = []
    if existing_mapping:
        for f in existing_mapping.fields:
            proposals.append({
                "source_field": f.source_field,
                "suggested_target": f.target_field,
                "confidence": f.confidence,
                "source": "active_schema",
                "required": f.required,
            })
    else:
        proposal_res = mapping_assistant.analyze(payload)
        proposals = proposal_res.get("mapping_proposals", [])

    stage5 = {
        "stage": 5,
        "name": "AI / Rule-Based Mapping Proposal",
        "status": "completed",
        "details": {
            "proposals": proposals,
            "rule_based_count": sum(1 for p in proposals if p.get("source") == "rule_based"),
            "ai_count": sum(1 for p in proposals if p.get("source") == "local_ai"),
            "active_count": sum(1 for p in proposals if p.get("source") == "active_schema"),
            "inference_mode": "Air-Gapped Local Rule Engine + Local GGUF Inference",
        },
    }

    # Stage 6: Human Approval Required
    default_mapping_id = ""
    if not existing_mapping:
        candidate_vendor = (parsed_event.vendor if parsed_event and parsed_event.vendor else "perimeter").lower()
        candidate_product = (parsed_event.product if parsed_event and parsed_event.product else "device").lower()
        default_mapping_id = f"{candidate_vendor}-{candidate_product}".replace(" ", "-")

    stage6 = {
        "stage": 6,
        "name": "Human Approval Required",
        "status": "approved" if existing_mapping else "awaiting_approval",
        "details": {
            "required": existing_mapping is None,
            "message": (
                "Mapping previously verified and approved by cybersecurity engineer."
                if existing_mapping
                else "Air-Gapped Policy: AI proposals require human verification before rule promotion. Auto-approval disabled for security integrity."
            ),
            "approval_payload": None if existing_mapping else {
                "mapping_id": default_mapping_id,
                "version": "1.0.0",
                "source_format": parsed_event.source_format if parsed_event else "key_value",
                "vendor": parsed_event.vendor if parsed_event else "Custom",
                "product": parsed_event.product if parsed_event else "Firewall",
                "fields": [
                    {
                        "source_field": p["source_field"],
                        "target_field": p.get("suggested_target"),
                        "confidence": p.get("confidence", 0.9),
                        "required": False,
                    }
                    for p in proposals
                    if p.get("suggested_target")
                ],
            },
        },
    }

    # Stage 7: Versioned Mapping Created
    stage7 = {
        "stage": 7,
        "name": "Versioned Mapping Created",
        "status": "active" if existing_mapping else "pending",
        "details": {
            "mapping_id": existing_mapping.mapping_id if existing_mapping else None,
            "version": existing_mapping.version if existing_mapping else None,
            "file": f"{existing_mapping.mapping_id}.json" if existing_mapping else None,
            "note": (
                f"Stored in backend/app/mapping/definitions/{existing_mapping.mapping_id}.json"
                if existing_mapping
                else "Pending human approval submission."
            ),
        },
    }

    # Stage 8: Deterministic Processing Activated
    proc_result = None
    if existing_mapping:
        proc_result = processor.process(payload)
        is_valid = proc_result.get("processing", {}).get("valid", False)
    else:
        is_valid = False

    stage8 = {
        "stage": 8,
        "name": "Deterministic Processing Activated",
        "status": "active" if existing_mapping and is_valid else "ready_to_activate",
        "details": {
            "deterministic_execution": existing_mapping is not None,
            "validation_pass": is_valid,
            "ai_latency": "0 ms (Zero AI latency during deterministic runtime)" if existing_mapping else "Awaiting activation",
            "mode": proc_result.get("processing", {}).get("mode") if proc_result else "assisted",
            "event_id": proc_result.get("event", {}).get("id") if proc_result else None,
            "trace_id": proc_result.get("provenance", {}).get("trace_id") if proc_result else None,
        },
    }

    return {
        "timestamp": now_iso,
        "raw_payload": payload,
        "is_onboarded": existing_mapping is not None,
        "stages": [
            stage1,
            stage2,
            stage3,
            stage4,
            stage5,
            stage6,
            stage7,
            stage8,
        ],
    }