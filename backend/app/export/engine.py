import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any
import requests

from app.storage.event_store import record_export

logger = logging.getLogger("ulpf.export")


class BaseExporter(ABC):
    """Abstract base class for ULPF export destinations."""

    @property
    @abstractmethod
    def target_type(self) -> str:
        pass

    @abstractmethod
    def export(self, events: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
        pass


class JSONLinesExporter(BaseExporter):
    target_type = "jsonl"

    def export(self, events: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
        """Formats events as newline-delimited JSON (NDJSON / JSONL)."""
        lines = []
        for ev in events:
            # Use normalized_event if available, otherwise raw event dict
            payload = ev.get("normalized_event") if isinstance(ev.get("normalized_event"), dict) else ev
            lines.append(json.dumps(payload, default=str))

        jsonl_content = "\n".join(lines)
        if jsonl_content:
            jsonl_content += "\n"

        return {
            "status": "success",
            "target_type": self.target_type,
            "event_count": len(events),
            "content": jsonl_content,
            "size_bytes": len(jsonl_content.encode("utf-8")),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class WebhookExporter(BaseExporter):
    target_type = "webhook"

    def export(self, events: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
        """Pushes events via HTTP POST to an external webhook endpoint."""
        url = config.get("url")
        if not url:
            raise ValueError("Webhook export requires 'url' in configuration")

        headers = config.get("headers", {})
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("User-Agent", "ULPF-Telemetry-Exporter/1.0")

        timeout_sec = float(config.get("timeout_sec", 10.0))

        payload = {
            "source": "ULPF",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "batch_size": len(events),
            "events": [
                ev.get("normalized_event") if isinstance(ev.get("normalized_event"), dict) else ev
                for ev in events
            ],
        }

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout_sec)
            resp.raise_for_status()
            return {
                "status": "success",
                "target_type": self.target_type,
                "url": url,
                "http_status": resp.status_code,
                "event_count": len(events),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as err:
            logger.error(f"Webhook export failed: {err}")
            raise RuntimeError(f"Webhook delivery failed: {err}") from err


class ElasticsearchExporter(BaseExporter):
    target_type = "elasticsearch"

    def export(self, events: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
        """Formats and pushes bulk events to an Elasticsearch or OpenSearch cluster."""
        endpoint = config.get("endpoint", "http://localhost:9200").rstrip("/")
        index_name = config.get("index_name", "ulpf-events")
        bulk_url = f"{endpoint}/_bulk"

        lines = []
        for ev in events:
            event_id = ev.get("id") or ev.get("event", {}).get("id")
            header = {"index": {"_index": index_name}}
            if event_id:
                header["index"]["_id"] = str(event_id)
            lines.append(json.dumps(header))
            data = ev.get("normalized_event") if isinstance(ev.get("normalized_event"), dict) else ev
            lines.append(json.dumps(data, default=str))

        bulk_payload = "\n".join(lines) + "\n"
        headers = {"Content-Type": "application/x-ndjson"}

        # Dry-run allows formatting and testing without requiring live cluster
        if config.get("dry_run"):
            return {
                "status": "success",
                "target_type": self.target_type,
                "endpoint": endpoint,
                "index": index_name,
                "event_count": len(events),
                "content": bulk_payload,
                "size_bytes": len(bulk_payload.encode("utf-8")),
                "dry_run": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        auth_user = config.get("username")
        auth_pass = config.get("password")
        auth = (auth_user, auth_pass) if auth_user and auth_pass else None

        timeout_sec = float(config.get("timeout_sec", 15.0))

        try:
            resp = requests.post(
                bulk_url,
                data=bulk_payload.encode("utf-8"),
                headers=headers,
                auth=auth,
                timeout=timeout_sec,
            )
            resp.raise_for_status()
            res_json = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            return {
                "status": "success",
                "target_type": self.target_type,
                "endpoint": endpoint,
                "index": index_name,
                "event_count": len(events),
                "content": bulk_payload,
                "size_bytes": len(bulk_payload.encode("utf-8")),
                "errors": res_json.get("errors", False),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as err:
            logger.error(f"Elasticsearch export failed: {err}")
            raise RuntimeError(f"Elasticsearch bulk push failed: {err}") from err


class ExportEngine:
    """Central export dispatcher supporting extensible connectors."""

    def __init__(self) -> None:
        self.exporters: dict[str, BaseExporter] = {
            "jsonl": JSONLinesExporter(),
            "webhook": WebhookExporter(),
            "elasticsearch": ElasticsearchExporter(),
            "opensearch": ElasticsearchExporter(),
        }

    def run_export(
        self,
        target_type: str,
        events: list[dict[str, Any]],
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        target_lower = target_type.lower().strip()
        exporter = self.exporters.get(target_lower)
        if not exporter:
            valid_types = list(self.exporters.keys())
            raise ValueError(f"Unsupported export target '{target_type}'. Must be one of {valid_types}")

        cfg = config or {}
        destination = cfg.get("url") or cfg.get("endpoint") or cfg.get("filename") or f"{target_lower}_stream"

        try:
            result = exporter.export(events, cfg)
            export_id = record_export(
                target_type=target_lower,
                destination=destination,
                event_count=len(events),
                status="completed",
                config=cfg,
            )
            result["export_id"] = export_id
            return result
        except Exception as err:
            record_export(
                target_type=target_lower,
                destination=destination,
                event_count=len(events),
                status="failed",
                config=cfg,
                error_message=str(err),
            )
            raise


export_engine = ExportEngine()
