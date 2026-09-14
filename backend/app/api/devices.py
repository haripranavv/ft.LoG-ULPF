from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.scanner.engine import scanner

router = APIRouter(
    prefix="/api/devices",
    tags=["Devices"],
)


class DiscoverRequest(BaseModel):
    scan_lan: bool = True
    scan_wifi: bool = True
    scan_bluetooth: bool = False
    ingest_to_ulpf: bool = True


class UpdateStatusRequest(BaseModel):
    status: str


@router.get("/capabilities")
def get_capabilities() -> dict[str, Any]:
    """Returns local host discovery capabilities (LAN ARP, Wi-Fi, Bluetooth)."""
    return scanner.get_capabilities()


@router.get("")
def list_devices() -> list[dict[str, Any]]:
    """Returns all discovered network devices from PostgreSQL inventory."""
    return scanner.list_devices()


@router.post("/discover")
def run_discovery(request: DiscoverRequest | None = None) -> dict[str, Any]:
    """
    Triggers authorized LAN/Wi-Fi discovery, updates PostgreSQL inventory,
    and ingests canonical ULPF discovery events into normalized_events.
    """
    req = request or DiscoverRequest()
    try:
        return scanner.run_discovery(
            scan_lan=req.scan_lan,
            scan_wifi=req.scan_wifi,
            scan_bluetooth=req.scan_bluetooth,
            ingest_to_ulpf=req.ingest_to_ulpf,
        )
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))


@router.get("/{device_id}")
def get_device(device_id: str) -> dict[str, Any]:
    """Returns details for a single device."""
    dev = scanner.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")
    return dev


@router.patch("/{device_id}")
def update_device_status(device_id: str, request: UpdateStatusRequest) -> dict[str, Any]:
    """Updates device status (known, new, unknown)."""
    try:
        return scanner.update_device_status(device_id, request.status)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))
