import json
import os
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.processing.processor import ULPFProcessor
from app.storage.event_store import store_event


class DeviceScanner:
    STORAGE_FILE = (
        Path(__file__).resolve().parent.parent
        / "storage"
        / "discovered_devices.json"
    )

    def __init__(self) -> None:
        self.os_type = platform.system().lower()
        mapping_dir = (
            Path(__file__).resolve().parent.parent
            / "mapping"
            / "definitions"
        )
        self.processor = ULPFProcessor(str(mapping_dir))
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.STORAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not self.STORAGE_FILE.exists():
            self._save_devices({})

    def _load_devices(self) -> dict[str, dict[str, Any]]:
        try:
            if self.STORAGE_FILE.exists():
                with self.STORAGE_FILE.open("r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_devices(self, devices: dict[str, dict[str, Any]]) -> None:
        with self.STORAGE_FILE.open("w", encoding="utf-8") as f:
            json.dump(devices, f, indent=2)

    def get_capabilities(self) -> dict[str, Any]:
        """Detect and report authorized host discovery capabilities honestly."""
        capabilities: dict[str, Any] = {
            "os": platform.system(),
            "os_release": platform.release(),
            "lan": {
                "supported": True,
                "method": "Local ARP table inspection & NetBIOS/DNS resolution",
                "details": "Authorized subnet and neighbor cache inspection",
            },
            "wifi": {
                "supported": False,
                "reason": "Not verified",
                "details": "",
            },
            "bluetooth": {
                "supported": False,
                "reason": "Not verified",
                "details": "",
            },
        }

        # Wi-Fi check
        if self.os_type == "windows":
            try:
                result = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and "There is no wireless interface" not in result.stdout:
                    match = re.search(r"Description\s*:\s*(.+)", result.stdout)
                    adapter_name = match.group(1).strip() if match else "WLAN Interface"
                    capabilities["wifi"] = {
                        "supported": True,
                        "adapter": adapter_name,
                        "method": "Windows WLAN 802.11 Subsystem",
                        "details": "Local Wi-Fi interface and BSSID discovery supported",
                    }
                else:
                    capabilities["wifi"] = {
                        "supported": False,
                        "reason": "No active Wi-Fi adapter detected or WLAN service disabled",
                        "details": "Host system has no enabled 802.11 wireless interface",
                    }
            except Exception as e:
                capabilities["wifi"] = {
                    "supported": False,
                    "reason": f"WLAN query error: {e}",
                }
        else:
            capabilities["wifi"] = {
                "supported": False,
                "reason": f"Automated Wi-Fi scanning not configured for {platform.system()}",
            }

        # Bluetooth check
        if self.os_type == "windows":
            try:
                ps_cmd = (
                    "Get-PnpDevice -Class Bluetooth -Status OK "
                    "| Where-Object { $_.FriendlyName -notmatch 'Enumerator|RFCOMM' } "
                    "| Select-Object -First 1 FriendlyName"
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                if result.returncode == 0 and result.stdout.strip():
                    capabilities["bluetooth"] = {
                        "supported": True,
                        "method": "Windows Bluetooth PnP Subsystem",
                        "details": "Local Bluetooth controller and paired/visible radio discovery supported",
                    }
                else:
                    capabilities["bluetooth"] = {
                        "supported": False,
                        "reason": "No active Bluetooth adapter detected or Bluetooth radio powered off",
                        "details": "Host system has no active Bluetooth controller in PnP subsystem",
                    }
            except Exception as e:
                capabilities["bluetooth"] = {
                    "supported": False,
                    "reason": f"Bluetooth query error: {e}",
                }
        else:
            capabilities["bluetooth"] = {
                "supported": False,
                "reason": f"Bluetooth discovery not configured for {platform.system()}",
            }

        return capabilities

    def scan_lan(self) -> list[dict[str, Any]]:
        """Inspect local ARP cache for authorized LAN discovery."""
        discovered: list[dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if result.returncode != 0:
                return discovered

            # Parse lines like: 10.153.7.104 e6-39-bc-f7-bf-98 dynamic
            ip_mac_pattern = re.compile(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})\s+(\w+)"
            )

            current_interface = "local"
            for line in result.stdout.splitlines():
                line_str = line.strip()
                if "Interface:" in line_str:
                    parts = line_str.split()
                    if len(parts) >= 2:
                        current_interface = parts[1]
                    continue

                match = ip_mac_pattern.search(line_str)
                if match:
                    ip, raw_mac, entry_type = match.groups()
                    mac = raw_mac.replace("-", ":").upper()

                    # Filter out multicast and broadcast ranges
                    if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                        continue
                    if mac == "FF:FF:FF:FF:FF:FF" or mac.startswith("01:00:5E"):
                        continue

                    # Try reverse DNS lookup with small timeout
                    hostname = f"host-{ip.replace('.', '-')}"
                    try:
                        socket.setdefaulttimeout(0.4)
                        resolved, _, _ = socket.gethostbyaddr(ip)
                        if resolved:
                            hostname = resolved
                    except Exception:
                        pass

                    device_id = f"lan-{mac.replace(':', '').lower()}"
                    discovered.append({
                        "id": device_id,
                        "name": hostname,
                        "ip": ip,
                        "hardware_id": mac,
                        "discovery_type": "lan",
                        "interface": current_interface,
                        "entry_type": entry_type,
                    })
        except Exception:
            pass

        return discovered

    def scan_wifi(self) -> list[dict[str, Any]]:
        """Query local WLAN interface for connected and visible 802.11 APs."""
        discovered: list[dict[str, Any]] = []
        if self.os_type != "windows":
            return discovered

        try:
            # 1. Check connected interface
            res_iface = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=6,
            )
            if res_iface.returncode == 0:
                ssid_m = re.search(r"SSID\s*:\s*(.+)", res_iface.stdout)
                bssid_m = re.search(r"AP BSSID\s*:\s*(.+)", res_iface.stdout)
                signal_m = re.search(r"Signal\s*:\s*(.+)", res_iface.stdout)
                band_m = re.search(r"Band\s*:\s*(.+)", res_iface.stdout)

                if ssid_m and bssid_m:
                    ssid = ssid_m.group(1).strip()
                    bssid = bssid_m.group(1).strip().upper()
                    signal = signal_m.group(1).strip() if signal_m else "N/A"
                    band = band_m.group(1).strip() if band_m else "N/A"
                    device_id = f"wifi-{bssid.replace(':', '').lower()}"

                    discovered.append({
                        "id": device_id,
                        "name": f"{ssid} (Connected)",
                        "ip": None,
                        "hardware_id": bssid,
                        "discovery_type": "wifi",
                        "signal": signal,
                        "band": band,
                    })

            # 2. Query visible networks
            res_nets = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if res_nets.returncode == 0:
                current_ssid = ""
                for line in res_nets.stdout.splitlines():
                    s_line = line.strip()
                    if s_line.startswith("SSID "):
                        parts = s_line.split(":", 1)
                        if len(parts) == 2:
                            current_ssid = parts[1].strip() or "Hidden Network"
                    elif s_line.startswith("BSSID "):
                        parts = s_line.split(":", 1)
                        if len(parts) == 2:
                            bssid = parts[1].strip().upper()
                            device_id = f"wifi-{bssid.replace(':', '').lower()}"
                            # Avoid duplicates if already added as connected AP
                            if not any(d["hardware_id"] == bssid for d in discovered):
                                discovered.append({
                                    "id": device_id,
                                    "name": current_ssid,
                                    "ip": None,
                                    "hardware_id": bssid,
                                    "discovery_type": "wifi",
                                })
        except Exception:
            pass

        return discovered

    def scan_bluetooth(self) -> list[dict[str, Any]]:
        """Query local Bluetooth subsystem for active and paired devices."""
        discovered: list[dict[str, Any]] = []
        if self.os_type != "windows":
            return discovered

        try:
            ps_cmd = (
                "Get-PnpDevice -Class Bluetooth "
                "| Where-Object { $_.FriendlyName -notmatch 'Enumerator|RFCOMM|Transport|Generic|Service|Attribute' -and $_.FriendlyName -ne '' } "
                "| Select-Object FriendlyName, InstanceId "
                "| ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        items = [data]
                    elif isinstance(data, list):
                        items = data
                    else:
                        items = []

                    for item in items:
                        name = item.get("FriendlyName", "").strip()
                        instance_id = item.get("InstanceId", "").strip()
                        if not name:
                            continue

                        # Extract MAC address from InstanceId (e.g., DEV_73C00181C6E5)
                        mac_match = re.search(r"DEV_([0-9A-Fa-f]{12})", instance_id)
                        if mac_match:
                            raw_hex = mac_match.group(1).upper()
                            mac = ":".join(raw_hex[i:i+2] for i in range(0, 12, 2))
                        else:
                            mac = instance_id.split("\\")[-1] if "\\" in instance_id else instance_id

                        device_id = f"bt-{mac.replace(':', '').lower()}"
                        if not any(d["id"] == device_id for d in discovered):
                            discovered.append({
                                "id": device_id,
                                "name": name,
                                "ip": None,
                                "hardware_id": mac,
                                "discovery_type": "bluetooth",
                            })
                except Exception:
                    pass
        except Exception:
            pass

        return discovered

    def run_discovery(
        self,
        scan_lan: bool = True,
        scan_wifi: bool = True,
        scan_bluetooth: bool = True,
        ingest_to_ulpf: bool = True,
    ) -> dict[str, Any]:
        """
        Execute full authorized discovery across requested capabilities,
        update inventory, generate authentic ULPF logs, and pass through
        the normalization pipeline into the PostgreSQL database.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        current_devices = self._load_devices()
        new_discoveries: list[dict[str, Any]] = []

        if scan_lan:
            new_discoveries.extend(self.scan_lan())
        if scan_wifi:
            new_discoveries.extend(self.scan_wifi())
        if scan_bluetooth:
            new_discoveries.extend(self.scan_bluetooth())

        updated_count = 0
        new_count = 0
        generated_events: list[dict[str, Any]] = []

        for item in new_discoveries:
            dev_id = item["id"]
            if dev_id in current_devices:
                # Update existing device record
                dev = current_devices[dev_id]
                dev["last_seen"] = now_iso
                dev["name"] = item.get("name") or dev.get("name")
                if item.get("ip"):
                    dev["ip"] = item["ip"]
                if item.get("hardware_id"):
                    dev["hardware_id"] = item["hardware_id"]
                updated_count += 1
            else:
                # New device discovered
                dev = {
                    "id": dev_id,
                    "name": item.get("name", "Unknown Device"),
                    "ip": item.get("ip"),
                    "hardware_id": item.get("hardware_id"),
                    "discovery_type": item.get("discovery_type", "lan"),
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                    "status": "new",
                }
                current_devices[dev_id] = dev
                new_count += 1

            # Ingest to ULPF normalization pipeline
            if ingest_to_ulpf:
                try:
                    # Clean strings for structured key-value payload
                    clean_name = re.sub(r"[^\w\.-]", "_", dev["name"])
                    ip_val = dev.get("ip") or "0.0.0.0"
                    mac_val = dev.get("hardware_id") or "00:00:00:00:00:00"
                    status_val = dev.get("status", "unknown")
                    disc_type = dev.get("discovery_type", "lan")

                    raw_log = (
                        f"{now_iso} DISCOVERY "
                        f"type={disc_type} "
                        f"ip={ip_val} "
                        f"mac={mac_val} "
                        f"hostname={clean_name} "
                        f"status={status_val} "
                        f"vendor=ULPF-Scanner"
                    )

                    result = self.processor.process(raw_log)
                    if result.get("processing", {}).get("valid"):
                        store_event(result)
                        trace_id = result.get("provenance", {}).get("trace_id")
                        dev["event_id"] = result.get("event", {}).get("id")
                        dev["trace_id"] = trace_id
                        generated_events.append({
                            "device_id": dev_id,
                            "event_id": dev.get("event_id"),
                            "trace_id": trace_id,
                            "valid": True,
                        })
                except Exception as err:
                    generated_events.append({
                        "device_id": dev_id,
                        "error": str(err),
                        "valid": False,
                    })

        self._save_devices(current_devices)

        return {
            "status": "success",
            "timestamp": now_iso,
            "scanned_types": {
                "lan": scan_lan,
                "wifi": scan_wifi,
                "bluetooth": scan_bluetooth,
            },
            "summary": {
                "total_devices": len(current_devices),
                "discovered_this_scan": len(new_discoveries),
                "new_devices": new_count,
                "updated_devices": updated_count,
                "ulpf_events_generated": len(generated_events),
            },
            "devices": list(current_devices.values()),
            "events": generated_events,
        }

    def list_devices(self) -> list[dict[str, Any]]:
        """Return the current inventory of discovered devices."""
        devices = self._load_devices()
        return list(devices.values())

    def update_device_status(self, device_id: str, status: str) -> dict[str, Any]:
        """Update device status (known, new, unknown)."""
        valid_statuses = {"known", "new", "unknown"}
        if status.lower() not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}")

        devices = self._load_devices()
        if device_id not in devices:
            raise KeyError(f"Device '{device_id}' not found in inventory")

        devices[device_id]["status"] = status.lower()
        self._save_devices(devices)
        return devices[device_id]
