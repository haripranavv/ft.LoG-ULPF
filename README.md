# ULPF — Universal Log Processing Framework

## Overview
ULPF (Universal Log Processing Framework) is a **local-first, deterministic telemetry ingestion and normalization platform**. 

It is designed to cleanly intake logs across dozens of formats (Syslog, CEF, JSON, CSV, Cisco IOS, Suricata, OpenVPN, Custom Firewalls, etc.), deterministically parse them into canonical structures (ECS/CIM-inspired), cryptographically preserve the original raw payloads, and index the validated outputs into PostgreSQL for immediate analysis or downstream export.

If ULPF encounters a format it does not recognize, it features an **Adaptive Parser** capable of mapping unknown telemetry formats using local hardware-accelerated AI mapping (running purely on CPU/GPU without cloud dependencies), converting complex unknown formats into robust deterministic parsing rules.

## Core Features
1. **Multi-Format Ingestion**: Drag-and-drop or API-based ingestion of single or batched log payloads.
2. **Deterministic Parsing Pipeline**: Bypasses AI completely for known formats, running purely in Python for ultra-fast normalization.
3. **Cryptographic Preservation**: Automatically calculates **SHA-256** signatures for all raw uploads and computes **Merkle Tree Batch Roots** to ensure data integrity and tamper evidence.
4. **Active Network Discovery**: Passively and actively discovers LAN devices using native ARP/IP scans, directly mapping inventory into canonical discovery events inside the ULPF pipeline.
5. **Robust Database Storage**: Persists raw artifacts on disk and canonical events in PostgreSQL efficiently without ORM bloat.
6. **Data Portability**: Supports direct extraction via UI, streaming Webhooks, JSONL exports, and direct injection into Elasticsearch/OpenSearch.
7. **Stateless JWT Security**: The API is entirely secured by stateless JWT authentication, ensuring cluster survivability during container restarts.

## Architecture

ULPF is fundamentally lightweight. It completely eschews complex enterprise stream processors (no Kafka, Flink, or Kubernetes overhead) in favor of a robust fast-path REST architecture.

**Backend**: `FastAPI` + `Pydantic` + `psycopg`
**Frontend**: `React` + `Vite` + `TypeScript`
**Database**: `PostgreSQL 16`
**AI Inference**: GGUF Models mounted locally via standard volumes

## Quick Start (Docker)

1. Ensure you have Docker and Docker Compose installed.
2. Copy the environment variables:
   ```bash
   cp .env.example .env
   ```
3. Update `.env` with secure credentials (specifically `JWT_SECRET`, `ADMIN_PASSWORD`, and `POSTGRES_PASSWORD`).
4. Build and start the cluster:
   ```bash
   docker compose up --build -d
   ```
5. Open the frontend dashboard: `http://localhost:5173`
6. Authenticate using the credentials you defined in `.env`.

## Environment Variables

| Variable | Description |
|---|---|
| `ADMIN_USERNAME` | The SoC Admin username for the dashboard |
| `ADMIN_PASSWORD` | The SoC Admin password |
| `JWT_SECRET` | A secure cryptographically random string for token generation |
| `POSTGRES_USER` | PostgreSQL Username |
| `POSTGRES_PASSWORD` | PostgreSQL Password |
| `POSTGRES_DB` | PostgreSQL Database name |

## Testing
Run the Python test suite natively on your host environment:
```bash
cd backend
python -m pytest tests/
```

To run the master 16-step integration script against a live Docker cluster:
```bash
cd backend
python verify_final_16_steps.py
```

## Known Limitations

- **Docker Discovery Constraints**: Running ULPF inside Docker on Windows or macOS restricts the Active LAN Discovery capabilities since the container is abstracted behind an internal Docker bridge network. For full discovery sweeps, the scanner must be run directly on the host machine or attached to `--network host` on a Linux box.
- **AI Processing Latency**: The adaptive local AI mappings take several seconds to process depending on hardware. ULPF is designed to offload this via localized models only during the *definition phase*; subsequent ingestions of the newly learned format are strictly deterministic.
