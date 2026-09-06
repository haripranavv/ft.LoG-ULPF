from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.scanner.engine import DeviceScanner

router = APIRouter(
    prefix="/api/scanner",
    tags=["Scanner"],
)

scanner = DeviceScanner()


class ScanRequest(BaseModel):
    scan_lan: bool = True
    scan_wifi: bool = True
    scan_bluetooth: bool = True
    ingest_to_ulpf: bool = True


class UpdateStatusRequest(BaseModel):
    status: str


@router.get("/capabilities")
def get_capabilities() -> dict[str, Any]:
    """Return legitimate host OS discovery capabilities."""
    try:
        return scanner.get_capabilities()
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@router.get("/devices")
def list_devices() -> list[dict[str, Any]]:
    """Return all discovered devices in inventory."""
    try:
        return scanner.list_devices()
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@router.post("/scan")
def run_scan(request: ScanRequest) -> dict[str, Any]:
    """
    Run authorized host discovery across LAN, Wi-Fi, and Bluetooth.
    Generates authentic ULPF logs and pipes them through the normalization pipeline.
    """
    try:
        return scanner.run_discovery(
            scan_lan=request.scan_lan,
            scan_wifi=request.scan_wifi,
            scan_bluetooth=request.scan_bluetooth,
            ingest_to_ulpf=request.ingest_to_ulpf,
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@router.patch("/devices/{device_id}")
def update_device_status(
    device_id: str,
    request: UpdateStatusRequest,
) -> dict[str, Any]:
    """Update device inventory status (known, new, unknown)."""
    try:
        return scanner.update_device_status(device_id, request.status)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Device '{device_id}' not found",
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=400,
            detail=str(val_err),
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )
