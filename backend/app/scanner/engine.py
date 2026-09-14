import json
import os
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.processing.processor import get_processor
from app.storage.event_store import store_events_batch, upsert_devices_batch
from app.storage.database import get_connection


class DeviceScanner:
    """
    Legitimate local network discovery engine.
    Uses host OS ARP/neighbor cache, local interfaces, and 802.11 subsystems without intrusive port scanning.
    Cross-platform: Windows and Linux / Docker container.
    """

    CACHE_FILE = (
        Path(__file__).resolve().parent.parent
        / "storage"
        / "discovered_devices.json"
    )

    OUI_VENDORS: dict[str, tuple[str, str, float]] = {
        # Virtualization / Hypervisors
        "00:15:5D": ("Microsoft", "workstation", 0.90),
        "00:50:56": ("VMware", "server", 0.95),
        "00:0C:29": ("VMware", "server", 0.95),
        "08:00:27": ("Oracle VirtualBox", "workstation", 0.90),
        "52:54:00": ("QEMU / KVM", "server", 0.90),

        # Network Gateways, Routers & Switches
        "1C:FD:08": ("Sagemcom Broadband", "router", 0.95),
        "32:F8:56": ("Local Network Gateway", "router", 0.90),
        "C0:25:A5": ("Cisco Systems", "switch", 0.95),
        "00:1E:13": ("Cisco Systems", "switch", 0.95),
        "00:1A:2B": ("Cisco Systems", "router", 0.95),
        "00:0C:E6": ("Juniper Networks", "router", 0.95),
        "F0:9F:C2": ("Ubiquiti Networks", "access_point", 0.95),
        "78:8A:20": ("Ubiquiti Networks", "access_point", 0.95),
        "00:14:D1": ("TP-Link Technologies", "router", 0.92),
        "50:C7:BF": ("TP-Link Technologies", "router", 0.92),
        "20:4E:7F": ("Netgear", "router", 0.92),
        "2C:30:33": ("Netgear", "access_point", 0.92),
        "04:D9:F5": ("ASUSTeK Computer", "router", 0.90),
        "D4:01:C3": ("MikroTik", "router", 0.95),

        # Printers & Peripherals
        "00:1E:0B": ("HP Inc", "printer", 0.95),
        "3C:D9:2B": ("HP Inc", "printer", 0.95),
        "00:00:48": ("Epson", "printer", 0.95),
        "00:26:AB": ("Epson", "printer", 0.95),
        "00:1E:8F": ("Canon", "printer", 0.95),
        "00:80:77": ("Brother Industries", "printer", 0.95),

        # Cameras & Surveillance
        "00:40:8C": ("Axis Communications", "camera", 0.95),
        "AC:CC:8E": ("Axis Communications", "camera", 0.95),
        "BC:5E:5C": ("Hangzhou Hikvision", "camera", 0.95),
        "E4:54:E8": ("Zhejiang Dahua", "camera", 0.95),

        # Mobile Devices
        "E6:39:BC": ("Motorola Mobility", "mobile", 0.95),
        "AC:D1:B8": ("Samsung Electronics", "mobile", 0.92),
        "30:07:4D": ("Samsung Electronics", "mobile", 0.92),
        "F0:F6:C1": ("Apple", "mobile", 0.85),
        "DC:A9:04": ("Apple", "mobile", 0.85),
        "3C:06:30": ("Apple", "mobile", 0.85),
        "2C:F0:EE": ("Google", "mobile", 0.92),
        "50:8A:06": ("OnePlus", "mobile", 0.95),
        "64:A2:F9": ("Xiaomi Communications", "mobile", 0.92),

        # Workstations & Servers
        "B4:2E:99": ("Intel Corporate", "workstation", 0.85),
        "4C:D5:77": ("Intel Corporate", "workstation", 0.85),
        "00:1A:A0": ("Dell Inc", "server", 0.88),
        "D4:BE:D9": ("Dell Inc", "workstation", 0.88),
        "70:85:C2": ("HP Inc", "workstation", 0.85),
        "54:E1:AD": ("Lenovo", "workstation", 0.88),

        # IoT & Microcontrollers
        "B8:27:EB": ("Raspberry Pi Foundation", "iot", 0.95),
        "DC:A6:32": ("Raspberry Pi Foundation", "iot", 0.95),
        "E4:5F:01": ("Raspberry Pi Foundation", "iot", 0.95),
        "24:6F:28": ("Espressif Inc (ESP32)", "iot", 0.98),
        "30:AE:A4": ("Espressif Inc (ESP32)", "iot", 0.98),
        "D8:BF:C0": ("Tuya Smart", "iot", 0.95),
    }

    def __init__(self) -> None:
        self.os_type = platform.system().lower()
        self.processor = get_processor()
        self._ensure_cache()

    def _ensure_cache(self) -> None:
        try:
            self.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            if not self.CACHE_FILE.exists():
                self._save_cache({})
        except Exception:
            pass

    def _load_cache(self) -> dict[str, dict[str, Any]]:
        try:
            if self.CACHE_FILE.exists():
                with self.CACHE_FILE.open("r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_cache(self, devices: dict[str, dict[str, Any]]) -> None:
        try:
            with self.CACHE_FILE.open("w", encoding="utf-8") as f:
                json.dump(devices, f, indent=2)
        except Exception:
            pass

    def resolve_vendor(self, mac: str | None) -> tuple[str | None, str | None, float]:
        """Resolves vendor, device type, and confidence from MAC OUI prefix."""
        if not mac:
            return None, None, 0.30
        clean_mac = mac.strip().upper().replace("-", ":")
        if len(clean_mac) >= 8:
            prefix = clean_mac[:8]
            if prefix in self.OUI_VENDORS:
                v, dtype, conf = self.OUI_VENDORS[prefix]
                return v, dtype, conf
        return None, None, 0.40

    def infer_device_type(
        self,
        discovery_type: str,
        name: str,
        vendor: str | None = None,
        mac: str | None = None,
    ) -> tuple[str, float]:
        """Classifies device type accurately into canonical peripheral models with confidence."""
        name_lower = (name or "").lower()

        # Check OUI first
        _, oui_type, conf = self.resolve_vendor(mac)
        if oui_type:
            return oui_type, conf

        # Peripheral & keyword heuristics
        if any(w in name_lower for w in ["printer", "laserjet", "deskjet", "epson", "canon", "brother"]):
            return "printer", 0.90
        if any(w in name_lower for w in ["camera", "cam", "cctv", "dvr", "nvr", "hikvision", "dahua"]):
            return "camera", 0.90
        if any(w in name_lower for w in ["gateway", "router", "modem", "firewall", "pfsense", "unifi"]):
            return "router", 0.90
        if any(w in name_lower for w in ["switch", "managed-sw", "catalyst"]):
            return "switch", 0.90
        if any(w in name_lower for w in ["ap", "accesspoint", "wifi-ap", "hotspot", "wlan"]):
            return "access_point", 0.88
        if any(w in name_lower for w in ["phone", "galaxy", "iphone", "pixel", "android", "mobile"]):
            return "mobile", 0.85
        if any(w in name_lower for w in ["server", "srv", "dc-", "esxi", "proxmox"]):
            return "server", 0.85
        if any(w in name_lower for w in ["desktop", "laptop", "pc", "workstation", "macbook"]):
            return "workstation", 0.85
        if any(w in name_lower for w in ["esp_", "tasmota", "wled", "shelly", "smart", "plug", "sensor"]):
            return "iot", 0.90

        if discovery_type == "wifi":
            return "access_point", 0.70

        return "unknown", 0.50

    def get_capabilities(self) -> dict[str, Any]:
        """Reports system discovery capabilities."""
        is_win = self.os_type == "windows"
        return {
            "os": platform.system(),
            "os_release": platform.release(),
            "lan": {
                "supported": True,
                "method": "Local ARP / Neighbor Table Inspection",
                "details": "Inspects host neighbor table and resolves PTR hostnames non-intrusively",
            },
            "wifi": {
                "supported": is_win,
                "method": "802.11 WLAN Interface Query" if is_win else "Unavailable in container",
                "details": "Queries local wireless adapter for BSSID beacons" if is_win else "Container host isolation",
            },
            "bluetooth": {
                "supported": is_win,
                "method": "Bluetooth Radio Discovery" if is_win else "Unavailable in container",
                "details": "Queries local Bluetooth controllers" if is_win else "Container host isolation",
            },
        }

    def scan_lan(self) -> list[dict[str, Any]]:
        """Non-intrusive inspection of ARP / neighbor table."""
        discovered: list[dict[str, Any]] = []
        raw_entries: list[tuple[str, str, str]] = []  # (ip, mac, interface)

        # 1. Linux / Docker container inspection (/proc/net/arp or `ip neigh`)
        proc_arp = Path("/proc/net/arp")
        if proc_arp.exists():
            try:
                with proc_arp.open("r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip, flags, raw_mac, iface = parts[0], parts[2], parts[3], parts[5]
                        if flags != "0x0" and raw_mac != "00:00:00:00:00:00":
                            raw_entries.append((ip, raw_mac.upper(), iface))
            except Exception:
                pass

        # 2. Fallback to `ip neigh` or `arp -a`
        if not raw_entries:
            try:
                # Try arp -a first (available on Windows and many Linux distros)
                res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=4)
                if res.returncode == 0:
                    ip_mac_pattern = re.compile(
                        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{11,17})"
                    )
                    current_iface = "eth0"
                    for line in res.stdout.splitlines():
                        if "Interface:" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                current_iface = parts[1]
                        match = ip_mac_pattern.search(line)
                        if match:
                            ip, mac_str = match.groups()
                            clean_mac = mac_str.replace("-", ":").upper()
                            if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                                if clean_mac != "FF:FF:FF:FF:FF:FF" and not clean_mac.startswith("01:00:5E"):
                                    raw_entries.append((ip, clean_mac, current_iface))
            except Exception:
                pass

        # Concurrent DNS hostname resolution with tight timeout
        def resolve_entry(entry):
            ip, mac, iface = entry
            hostname = f"host-{ip.replace('.', '-')}"
            try:
                socket.setdefaulttimeout(0.25)
                res, _, _ = socket.gethostbyaddr(ip)
                if res:
                    hostname = res
            except Exception:
                pass
            return ip, mac, iface, hostname

        with ThreadPoolExecutor(max_workers=8) as pool:
            resolved = list(pool.map(resolve_entry, raw_entries))

        for ip, mac, iface, hostname in resolved:
            dev_id = f"lan-{mac.replace(':', '').lower()}"
            discovered.append({
                "id": dev_id,
                "name": hostname,
                "ip": ip,
                "hardware_id": mac,
                "discovery_type": "lan",
                "interface": iface,
            })

        return discovered

    def scan_wifi(self) -> list[dict[str, Any]]:
        """Queries local Wi-Fi interface if on Windows."""
        discovered: list[dict[str, Any]] = []
        if self.os_type != "windows":
            return discovered

        try:
            res_iface = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res_iface.returncode == 0:
                ssid_m = re.search(r"SSID\s*:\s*(.+)", res_iface.stdout)
                bssid_m = re.search(r"AP BSSID\s*:\s*(.+)", res_iface.stdout)
                if ssid_m and bssid_m:
                    ssid = ssid_m.group(1).strip()
                    bssid = bssid_m.group(1).strip().upper()
                    device_id = f"wifi-{bssid.replace(':', '').lower()}"
                    discovered.append({
                        "id": device_id,
                        "name": f"{ssid} (Connected)",
                        "ip": None,
                        "hardware_id": bssid,
                        "discovery_type": "wifi",
                    })

            res_nets = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=6,
            )
            if res_nets.returncode == 0:
                current_ssid = "Wireless AP"
                for line in res_nets.stdout.splitlines():
                    s_line = line.strip()
                    if s_line.startswith("SSID "):
                        parts = s_line.split(":", 1)
                        if len(parts) == 2:
                            current_ssid = parts[1].strip() or "Wireless AP"
                    elif s_line.startswith("BSSID "):
                        parts = s_line.split(":", 1)
                        if len(parts) == 2:
                            bssid = parts[1].strip().upper()
                            dev_id = f"wifi-{bssid.replace(':', '').lower()}"
                            if not any(d["hardware_id"] == bssid for d in discovered):
                                discovered.append({
                                    "id": dev_id,
                                    "name": current_ssid,
                                    "ip": None,
                                    "hardware_id": bssid,
                                    "discovery_type": "wifi",
                                })
        except Exception:
            pass

        return discovered

    def scan_bluetooth(self) -> list[dict[str, Any]]:
        """Queries local Bluetooth if on Windows host."""
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
                timeout=6,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    items = [data] if isinstance(data, dict) else data if isinstance(data, list) else []
                    for item in items:
                        name = item.get("FriendlyName", "").strip()
                        instance_id = item.get("InstanceId", "").strip()
                        if not name:
                            continue
                        mac_match = re.search(r"DEV_([0-9A-Fa-f]{12})", instance_id)
                        if mac_match:
                            raw_hex = mac_match.group(1).upper()
                            mac = ":".join(raw_hex[i:i+2] for i in range(0, 12, 2))
                        else:
                            mac = instance_id.split("\\")[-1] if "\\" in instance_id else instance_id
                        dev_id = f"bt-{mac.replace(':', '').lower()}"
                        if not any(d["id"] == dev_id for d in discovered):
                            discovered.append({
                                "id": dev_id,
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
        scan_bluetooth: bool = False,
        ingest_to_ulpf: bool = True,
    ) -> dict[str, Any]:
        """
        Executes non-intrusive discovery, updates PostgreSQL devices inventory,
        generates authentic canonical ULPF events, and records them to normalized_events.
        """
        scan_start = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()
        current_cache = self._load_cache()
        new_discoveries: list[dict[str, Any]] = []

        scan_tasks = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            if scan_lan:
                scan_tasks[executor.submit(self.scan_lan)] = "lan"
            if scan_wifi:
                scan_tasks[executor.submit(self.scan_wifi)] = "wifi"
            if scan_bluetooth:
                scan_tasks[executor.submit(self.scan_bluetooth)] = "bluetooth"

            for future in as_completed(scan_tasks):
                try:
                    results = future.result()
                    new_discoveries.extend(results)
                except Exception:
                    pass

        devices_to_upsert: list[dict[str, Any]] = []
        valid_events_to_store: list[dict[str, Any]] = []
        generated_events: list[dict[str, Any]] = []
        new_count = 0
        updated_count = 0

        for item in new_discoveries:
            dev_id = item["id"]
            mac = item.get("hardware_id")
            name = item.get("name") or "Unknown Device"
            disc_type = item.get("discovery_type", "lan")
            resolved_vendor, _, _ = self.resolve_vendor(mac)
            inferred_type, type_confidence = self.infer_device_type(disc_type, name, resolved_vendor, mac)

            is_new = dev_id not in current_cache
            if is_new:
                new_count += 1
                status_str = "new"
            else:
                updated_count += 1
                status_str = current_cache[dev_id].get("status", "known")

            dev_record = {
                "id": dev_id,
                "name": name,
                "ip_address": item.get("ip"),
                "mac_address": mac,
                "manufacturer": resolved_vendor or "Generic Vendor",
                "device_type": inferred_type,
                "device_type_confidence": type_confidence,
                "discovery_method": f"Authorized local {disc_type.upper()} inspection",
                "status": status_str,
                "metadata": {
                    "interface": item.get("interface"),
                    "discovery_type": disc_type,
                },
                "first_seen": now_iso if is_new else current_cache[dev_id].get("first_seen", now_iso),
                "last_seen": now_iso,
            }

            current_cache[dev_id] = dev_record
            devices_to_upsert.append(dev_record)

            # Generate canonical ULPF Discovery Event
            if ingest_to_ulpf:
                try:
                    clean_name = re.sub(r"[^\w\.-]", "_", name)
                    ip_val = item.get("ip") or "0.0.0.0"
                    mac_val = mac or "00:00:00:00:00:00"
                    vendor_val = resolved_vendor or "ULPF-Scanner"

                    raw_log = (
                        f"{now_iso} DISCOVERY "
                        f"action=device_discovered "
                        f"event_type=discovery "
                        f"type={disc_type} "
                        f"ip={ip_val} "
                        f"mac={mac_val} "
                        f"hostname={clean_name} "
                        f"status={status_str} "
                        f"vendor={vendor_val}"
                    )

                    result = self.processor.process(raw_log)
                    if result.get("processing", {}).get("valid"):
                        valid_events_to_store.append(result)
                        trace_id = result.get("provenance", {}).get("trace_id")
                        dev_record["event_id"] = result.get("event", {}).get("id")
                        dev_record["trace_id"] = trace_id
                        generated_events.append({
                            "device_id": dev_id,
                            "event_id": dev_record["event_id"],
                            "trace_id": trace_id,
                            "valid": True,
                        })
                except Exception as err:
                    generated_events.append({
                        "device_id": dev_id,
                        "error": str(err),
                        "valid": False,
                    })

        # Persist to PostgreSQL
        try:
            if devices_to_upsert:
                upsert_devices_batch(devices_to_upsert)
            if valid_events_to_store:
                store_events_batch(valid_events_to_store)
        except Exception as db_err:
            print(f"[Scanner] Notice: DB batch insert deferred ({db_err})")

        self._save_cache(current_cache)

        return {
            "status": "success",
            "timestamp": now_iso,
            "summary": {
                "total_devices": len(current_cache),
                "discovered_this_scan": len(new_discoveries),
                "new_devices": new_count,
                "updated_devices": updated_count,
                "ulpf_events_generated": len(generated_events),
                "scan_duration_ms": round((time.perf_counter() - scan_start) * 1000, 2),
            },
            "devices": list(current_cache.values()),
            "events": generated_events,
        }

    def list_devices(self) -> list[dict[str, Any]]:
        """Queries devices from PostgreSQL or local cache."""
        try:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT id, name, ip_address, mac_address, manufacturer,
                               device_type, device_type_confidence, discovery_method,
                               first_seen, last_seen, status, metadata
                        FROM devices
                        ORDER BY last_seen DESC;
                        """
                    )
                    rows = cursor.fetchall()
                    if rows:
                        devices = []
                        for r in rows:
                            devices.append({
                                "id": r[0],
                                "name": r[1],
                                "ip_address": str(r[2]) if r[2] else None,
                                "ip": str(r[2]) if r[2] else None,
                                "mac_address": r[3],
                                "hardware_id": r[3],
                                "manufacturer": r[4],
                                "vendor": r[4],
                                "device_type": r[5],
                                "device_type_confidence": float(r[6]),
                                "discovery_method": r[7],
                                "first_seen": r[8].isoformat() if r[8] else None,
                                "last_seen": r[9].isoformat() if r[9] else None,
                                "status": r[10],
                                "metadata": r[11] if isinstance(r[11], dict) else {},
                            })
                        return devices
        except Exception:
            pass
        return list(self._load_cache().values())

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        """Retrieves a single device by ID."""
        devices = self.list_devices()
        for d in devices:
            if d.get("id") == device_id or d.get("hardware_id") == device_id:
                return d
        return None

    def update_device_status(self, device_id: str, status: str) -> dict[str, Any]:
        """Updates device status."""
        valid_statuses = {"known", "new", "unknown"}
        if status.lower() not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}")

        try:
            with get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE devices SET status = %s WHERE id = %s RETURNING id;",
                        (status.lower(), device_id),
                    )
                    conn.commit()
        except Exception:
            pass

        cache = self._load_cache()
        if device_id in cache:
            cache[device_id]["status"] = status.lower()
            self._save_cache(cache)
            return cache[device_id]

        dev = self.get_device(device_id)
        if dev:
            dev["status"] = status.lower()
            return dev
        raise KeyError(f"Device '{device_id}' not found")


scanner = DeviceScanner()


def get_device_scanner() -> DeviceScanner:
    return scanner
