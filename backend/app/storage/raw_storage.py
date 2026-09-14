import os
import hashlib
from pathlib import Path
from typing import Any
from datetime import datetime, timezone
import uuid


# Default raw storage directory (mounted Docker volume at /data/raw, or ./storage/raw locally)
RAW_STORAGE_DIR = Path(
    os.getenv(
        "RAW_STORAGE_DIR",
        str(Path(__file__).resolve().parent.parent.parent / "storage" / "raw"),
    )
)


class RawStorageManager:
    """
    Manages local-first raw log file storage and Merkle tamper-evident batch provenance.
    Preserves original uploaded bytes intact, generates cryptographic hashes, and avoids duplication.
    """

    def __init__(self, storage_dir: Path | None = None) -> None:
        self.storage_dir = storage_dir or RAW_STORAGE_DIR
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save_raw_file(
        self,
        filename: str,
        content_bytes: bytes,
        content_type: str = "text/plain",
    ) -> dict[str, Any]:
        """
        Saves raw file content to the mounted storage volume.
        Computes SHA-256 hash, stores file named after hash, and returns storage metadata.
        """
        self._ensure_dir()
        file_id = str(uuid.uuid4())
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        file_size = len(content_bytes)

        # Name storage file using hash to guarantee deduplication and integrity
        safe_ext = Path(filename).suffix or ".log"
        target_filename = f"{sha256_hash}{safe_ext}"
        storage_path = self.storage_dir / target_filename

        # Store file only if not already existing
        if not storage_path.exists():
            with storage_path.open("wb") as f:
                f.write(content_bytes)

        return {
            "id": file_id,
            "filename": filename,
            "sha256_hash": sha256_hash,
            "file_size_bytes": file_size,
            "content_type": content_type,
            "storage_path": str(storage_path),
            "ingestion_timestamp": datetime.now(timezone.utc),
        }

    def compute_merkle_root(self, hashes: list[str]) -> str:
        """
        Calculates a deterministic Merkle tree root for an event batch.
        Provides mathematical tamper evidence for the ingestion batch.
        """
        if not hashes:
            return hashlib.sha256(b"").hexdigest()

        current_level = [h.lower() for h in hashes]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of leaves, duplicate the last leaf
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
                next_level.append(combined)
            current_level = next_level

        return current_level[0]

    def read_raw_file(self, storage_path_str: str) -> bytes:
        """Reads preserved raw file bytes from storage."""
        path = Path(storage_path_str)
        if not path.exists():
            raise FileNotFoundError(f"Raw storage file not found: {storage_path_str}")
        with path.open("rb") as f:
            return f.read()


raw_storage = RawStorageManager()
