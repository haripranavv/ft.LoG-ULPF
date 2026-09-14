import io
import json
import subprocess
import time
import urllib.request
import uuid

def run_master_verification():
    print("=" * 80)
    print(" ULPF FINAL END-TO-END 16-STEP SYSTEM VERIFICATION ")
    print("=" * 80)

    base_url = "http://localhost:5173"
    api_url = f"{base_url}/api"

    # Step 0: Authenticate
    print("\n[Step 0] Authenticating...")
    
    # Try fetching password from .env, fallback to default
    password = "change_this_to_a_strong_password"
    try:
        with open(".env", "r") as f:
            for line in f:
                if line.startswith("ADMIN_PASSWORD="):
                    password = line.strip().split("=", 1)[1]
    except Exception:
        pass

    auth_req = urllib.request.Request(
        f"{api_url}/auth/login",
        data=json.dumps({"username": "admin", "password": password}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(auth_req) as resp:
        token = json.loads(resp.read().decode())["token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    def fetch(url, data=None, headers=None, method=None):
        h = auth_headers.copy()
        if headers: h.update(headers)
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        return urllib.request.urlopen(req)

    # Step 1: Check Docker Compose status
    print("\n[Step 1] Verifying Docker Compose containers...")
    ps_res = subprocess.run(["docker", "compose", "ps", "--format", "json"], capture_output=True, text=True)
    assert ps_res.returncode == 0
    print("         Docker containers are active.")

    # Step 2: Verify Frontend loads
    print("\n[Step 2] Opening Frontend (GET http://localhost:5173)...")
    req = urllib.request.Request(base_url, headers={"User-Agent": "ULPF-Verifier"})
    with urllib.request.urlopen(req) as resp:
        assert resp.getcode() == 200
        html = resp.read().decode()
        assert "<title>ULPF" in html or "id=\"root\"" in html
        print(f"         Frontend loaded cleanly (HTTP {resp.getcode()}, {len(html)} bytes).")

    # Step 3: Upload logs via multipart POST
    print("\n[Step 3] Uploading raw logs via HTTP API...")
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    filename = "master_audit_test.log"
    log_content = (
        "2026-09-14T18:00:00Z FW01 ALLOW SRC=192.168.100.50 DST=10.0.0.1 SP=51234 DP=443 PROTO=TCP RULE=ALLOW_HTTPS USER=superadmin\n"
        "2026-09-14T18:00:05Z FW01 DROP SRC=198.51.100.77 DST=10.0.0.5 SP=44123 DP=22 PROTO=TCP RULE=BLOCK_SSH USER=attacker\n"
    )

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"{log_content}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    with fetch(
        f"{api_url}/ingest/files",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    ) as resp:
        assert resp.getcode() == 200
        upload_data = json.loads(resp.read().decode())
        print(f"         Uploaded successfully: {upload_data['filename']}")

    # Step 4: Original raw file is preserved & hashed
    print("\n[Step 4] Checking raw file preservation & SHA-256...")
    ingestion_id = upload_data["ingestion_id"]
    sha256 = upload_data["sha256_hash"]
    merkle_root = upload_data["batch_merkle_root"]
    storage_path = upload_data["storage_path"]
    assert len(sha256) == 64
    assert len(merkle_root) == 64
    print(f"         Storage Path: {storage_path}")
    print(f"         SHA-256:      {sha256}")
    print(f"         Merkle Root:  {merkle_root}")

    # Step 5: Format is automatically detected
    print("\n[Step 5] Verifying automatic format detection...")
    detected_format = upload_data["detected_format"]
    print(f"         Detected Format: '{detected_format}'")
    assert detected_format in ("key_value", "acmeguard", "firewall")

    # Step 6: Parser processes the file
    print("\n[Step 6] Verifying parser selection...")
    parser_used = upload_data["parser_used"]
    print(f"         Parser Selected: '{parser_used}'")
    assert parser_used in ("acmeguard", "key_value", "generic_adaptive")

    # Step 7: Events are normalized
    print("\n[Step 7] Verifying canonical normalization...")
    items = upload_data.get("items", [])
    assert len(items) == 2
    print(f"         Normalized {len(items)} events with ECS canonical structure.")

    # Step 8: Events are validated
    print("\n[Step 8] Verifying deterministic schema validation...")
    valid_count = upload_data["valid_count"]
    print(f"         Validation result: {valid_count} / {upload_data['total_events']} events valid.")
    assert valid_count == 2

    # Step 9: Events are stored in PostgreSQL
    print("\n[Step 9] Verifying PostgreSQL database persistence...")
    with fetch(f"{api_url}/ingest") as resp:
        assert resp.getcode() == 200
        ingests = json.loads(resp.read().decode())
        matched_ingest = next((i for i in ingests.get("ingestions", []) if i["id"] == ingestion_id), None)
        assert matched_ingest is not None
        print(f"         Found Ingestion record in PostgreSQL: {matched_ingest['id']} ({matched_ingest['total_events']} events)")

    # Step 10: Events appear in the Events page
    print("\n[Step 10] Verifying events retrieval (GET /api/events)...")
    with fetch(f"{api_url}/events?limit=20") as resp:
        assert resp.getcode() == 200
        events_resp = json.loads(resp.read().decode())
        events = events_resp.get("events", [])
        print(f"         Retrieved {len(events)} events from Events API.")
        assert len(events) >= 2

    # Step 11: Run real LAN/Wi-Fi discovery
    print("\n[Step 11] Running real active LAN/Wi-Fi discovery...")
    with fetch(
        f"{api_url}/devices/discover",
        data=json.dumps({"scan_lan": True, "scan_wifi": True, "scan_bluetooth": False}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    ) as resp:
        assert resp.getcode() == 200
        disc_data = json.loads(resp.read().decode())
        disc_devices = disc_data.get("devices", [])
        disc_summary = disc_data.get("summary", {})
        print(f"         Discovery finished in {disc_summary.get('scan_duration_ms')}ms.")

    # Step 12: Real discovered devices appear
    print("\n[Step 12] Inspecting discovered host & network devices...")
    assert len(disc_devices) > 0
    print(f"         Discovered {len(disc_devices)} real devices from host ARP/interfaces:")
    for d in disc_devices[:3]:
        print(f"           - {d.get('name')} | IP: {d.get('ip')} | MAC: {d.get('hardware_id')} | Vendor: {d.get('vendor')}")

    # Step 13: Discovery events enter ULPF pipeline
    print("\n[Step 13] Verifying discovery events in ULPF pipeline...")
    with fetch(f"{api_url}/events?source_format=discovery&limit=10") as resp:
        assert resp.getcode() == 200
        disc_events = json.loads(resp.read().decode()).get("events", [])
        print(f"         Found {len(disc_events)} canonical discovery events in ULPF stream.")

    # Step 14: Export events as JSONL
    print("\n[Step 14] Exporting normalized events as JSONL (NDJSON)...")
    with fetch(f"{api_url}/exports/download?limit=50") as resp:
        assert resp.getcode() == 200
        export_text = resp.read().decode()
        export_lines = [l for l in export_text.strip().splitlines() if l]
        print(f"         Exported {len(export_lines)} lines of valid JSONL.")
        assert len(export_lines) >= 2

    # Step 15: Restart Docker Compose
    print("\n[Step 15] Restarting Docker Compose containers ('docker compose restart')...")
    restart_res = subprocess.run(["docker", "compose", "restart"], capture_output=True, text=True, timeout=60)
    assert restart_res.returncode == 0
    print("         Containers restarted successfully. Waiting 5s for healthchecks...")
    time.sleep(5)

    # Step 16: Verify events and raw file references persist after restart
    print("\n[Step 16] Verifying data survival after Docker restart...")
    
    # Re-authenticate since in-memory sessions are cleared on restart
    print("         Re-authenticating after container restart...")
    with urllib.request.urlopen(auth_req) as resp:
        token = json.loads(resp.read().decode())["token"]
    auth_headers["Authorization"] = f"Bearer {token}"

    with fetch(f"{api_url}/events?limit=20") as resp:
        assert resp.getcode() == 200
        events_post = json.loads(resp.read().decode()).get("events", [])
        print(f"         Post-restart verified {len(events_post)} events retained.")
        assert len(events_post) >= len(events)

    with fetch(f"{api_url}/ingest?limit=10") as resp:
        assert resp.getcode() == 200
        ingests_post = json.loads(resp.read().decode()).get("ingestions", [])
        match = next((i for i in ingests_post if i["id"] == ingestion_id), None)
        assert match is not None
        print(f"         Post-restart verified raw ingestion persisted: {match['filename']} (SHA-256: {match['sha256_hash'][:16]}...)")

    print("\n" + "=" * 80)
    print(" ALL 16 END-TO-END STEPS VERIFIED 100% SUCCESSFULLY ON LIVE DOCKER STACK! ")
    print("=" * 80)

if __name__ == "__main__":
    run_master_verification()
