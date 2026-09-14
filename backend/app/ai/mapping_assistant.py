import os
import json
import re
from pathlib import Path
from typing import Any


class MappingAssistant:
    """
    Local AI Schema Assistant.
    Provides optional assistive schema inference for unknown log structures.
    Lazy-loads local GGUF model and provides zero-delay graceful fallback if model is unavailable.
    """

    MODEL_PATHS = [
        Path(os.getenv("AI_MODEL_PATH", "")),
        Path(r"C:\Users\harip\ulpf\models\qwen2.5-3b-instruct-q4_k_m.gguf"),
        Path(__file__).resolve().parents[3] / "models" / "qwen2.5-3b-instruct-q4_k_m.gguf",
        Path("/models/qwen2.5-3b-instruct-q4_k_m.gguf"),
    ]

    FIELD_SUGGESTIONS = {
        "timestamp": "event.timestamp",
        "time": "event.timestamp",
        "date": "event.timestamp",
        "action": "event.action",
        "event": "event.action",
        "src": "source.ip",
        "source": "source.ip",
        "src_ip": "source.ip",
        "srcaddr": "source.ip",
        "dst": "destination.ip",
        "dest": "destination.ip",
        "destination": "destination.ip",
        "dst_ip": "destination.ip",
        "dstaddr": "destination.ip",
        "sport": "source.port",
        "src_port": "source.port",
        "dport": "destination.port",
        "dst_port": "destination.port",
        "protocol": "network.protocol",
        "proto": "network.protocol",
        "user": "user.name",
        "username": "user.name",
        "severity": "event.severity",
        "message": "event.message",
        "threat": "security.threat",
        "signature": "security.threat",
    }

    ALLOWED_TARGETS = [
        "event.timestamp",
        "event.action",
        "event.severity",
        "event.message",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "network.protocol",
        "user.name",
        "security.threat",
        None,
    ]

    _shared_llm: Any = None
    _init_attempted: bool = False

    def __init__(self) -> None:
        self.enabled = os.getenv("ENABLE_LOCAL_AI", "true").lower() in ("true", "1", "yes")

    def _resolve_model_path(self) -> Path | None:
        for p in self.MODEL_PATHS:
            if p and str(p) != "." and p.exists() and p.is_file():
                return p
        return None

    def _get_llm(self) -> Any:
        if not self.enabled:
            return None
        if not MappingAssistant._init_attempted:
            MappingAssistant._init_attempted = True
            model_path = self._resolve_model_path()
            if model_path:
                try:
                    from llama_cpp import Llama
                    MappingAssistant._shared_llm = Llama(
                        model_path=str(model_path),
                        n_ctx=2048,
                        n_gpu_layers=0,
                        verbose=False,
                    )
                except Exception as e:
                    print(f"[MappingAssistant] Could not load local LLM: {e}")
                    MappingAssistant._shared_llm = None
        return MappingAssistant._shared_llm

    def is_available(self) -> bool:
        """Returns True if local AI model is accessible."""
        return self._resolve_model_path() is not None

    def analyze(self, raw_payload: str) -> dict[str, Any]:
        fields = self._extract_fields(raw_payload)
        field_values = self._extract_field_values(raw_payload)

        proposals = []
        unknown_fields = []

        for field in fields:
            normalized_name = field.lower()
            target = self.FIELD_SUGGESTIONS.get(normalized_name)
            if target:
                proposals.append({
                    "source_field": field,
                    "suggested_target": target,
                    "confidence": 0.95,
                    "source": "rule_based",
                    "requires_human_approval": True,
                })
            else:
                unknown_fields.append(field)

        # AI assistance for remaining unknown fields if model available
        llm = self._get_llm()
        if unknown_fields and llm is not None:
            ai_proposals = self._ask_ai(llm, unknown_fields, field_values)
            proposals.extend(ai_proposals)
        elif unknown_fields:
            # Fallback when AI model is not loaded
            for uf in unknown_fields:
                proposals.append({
                    "source_field": uf,
                    "suggested_target": None,
                    "confidence": 0.25,
                    "source": "deterministic_fallback",
                    "requires_human_approval": True,
                })

        return {
            "status": "proposal_generated",
            "mode": "ai_assisted" if (unknown_fields and llm is not None) else "rule_based",
            "candidate_fields": fields,
            "mapping_proposals": proposals,
            "auto_approved": False,
        }

    def _ask_ai(self, llm: Any, fields: list[str], field_values: dict[str, str]) -> list[dict[str, Any]]:
        field_data = {field: field_values.get(field, "") for field in fields}
        prompt = f"""You are a cybersecurity log schema mapping engine.
Map unknown source log fields to a canonical cybersecurity schema.

SOURCE FIELDS AND EXAMPLE VALUES:
{json.dumps(field_data, indent=2)}

AVAILABLE TARGETS:
- event.timestamp, event.action, event.severity, event.message
- source.ip, source.port, destination.ip, destination.port
- network.protocol, user.name, security.threat, null

Return valid JSON object mapping source_field -> canonical.target or null."""

        try:
            response = llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": "You are a precise cybersecurity schema mapping engine. Return only JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                response_format={"type": "json_object"},
            )
            content = response["choices"][0]["message"]["content"]
            result = json.loads(content)

            proposals = []
            for field in fields:
                target = result.get(field)
                if target == "null" or target not in self.ALLOWED_TARGETS:
                    target = None
                proposals.append({
                    "source_field": field,
                    "suggested_target": target,
                    "confidence": 0.85 if target else 0.30,
                    "source": "local_ai",
                    "requires_human_approval": True,
                })
            return proposals
        except Exception as error:
            return [
                {
                    "source_field": field,
                    "suggested_target": None,
                    "confidence": 0.0,
                    "source": "ai_error",
                    "error": str(error),
                    "requires_human_approval": True,
                }
                for field in fields
            ]

    def _extract_fields(self, payload: str) -> list[str]:
        pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", payload)
        return sorted(set(pairs))

    def _extract_field_values(self, payload: str) -> dict[str, str]:
        pairs = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)=["\']?([^"\']\S*)["\']?', payload)
        return {k: v for k, v in pairs}