import json
import re
from pathlib import Path
from typing import Any

from llama_cpp import Llama


class MappingAssistant:

    MODEL_PATH = (
        Path(__file__).resolve().parents[3]
        / "models"
        / "qwen2.5-3b-instruct-q4_k_m.gguf"
    )

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

    def __init__(self) -> None:

        self.llm = Llama(
            model_path=str(self.MODEL_PATH),
            n_ctx=2048,
            n_gpu_layers=0,
            verbose=False,
        )

    def analyze(
        self,
        raw_payload: str,
    ) -> dict[str, Any]:

        fields = self._extract_fields(raw_payload)

        field_values = self._extract_field_values(
            raw_payload
        )

        proposals = []

        unknown_fields = []

        for field in fields:

            normalized_name = field.lower()

            target = self.FIELD_SUGGESTIONS.get(
                normalized_name
            )

            if target:

                proposals.append(
                    {
                        "source_field": field,
                        "suggested_target": target,
                        "confidence": 0.95,
                        "source": "rule_based",
                        "requires_human_approval": True,
                    }
                )

            else:

                unknown_fields.append(field)

        if unknown_fields:

            ai_proposals = self._ask_ai(
                unknown_fields,
                field_values,
            )

            proposals.extend(ai_proposals)

        return {
            "status": "proposal_generated",
            "mode": "hybrid_ai_assisted",
            "candidate_fields": fields,
            "mapping_proposals": proposals,
            "auto_approved": False,
        }

    def _ask_ai(
        self,
        fields: list[str],
        field_values: dict[str, str],
    ) -> list[dict[str, Any]]:

        field_data = {
            field: field_values.get(field, "")
            for field in fields
        }

        prompt = f"""
You are a cybersecurity log schema mapping engine.

ULPF means Universal Log Pre-processing Framework.

Your task is to map unknown source log fields
to a canonical cybersecurity schema.

SOURCE FIELDS AND EXAMPLE VALUES:

{json.dumps(field_data, indent=2)}

AVAILABLE CANONICAL TARGETS:

- event.timestamp
- event.action
- event.severity
- event.message
- source.ip
- source.port
- destination.ip
- destination.port
- network.protocol
- user.name
- security.threat
- null

STRICT RULES:

1. Map a field ONLY when its meaning clearly matches.
2. Never force unrelated fields into a target.
3. Device names are NOT IP addresses.
4. Severity fields map to event.severity.
5. Threat or attack names map to security.threat.
6. If no correct target exists, use null.
7. Every input field must appear exactly once.
8. Return ONLY valid JSON.
9. Do not include markdown.
10. Do not explain your answer.

EXPECTED FORMAT:

{{
    "source_field": "canonical.target",
    "another_field": null
}}
"""

        try:

            response = self.llm.create_chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a precise cybersecurity "
                            "schema mapping engine. "
                            "Return only valid JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0,
                response_format={
                    "type": "json_object"
                },
            )

            content = (
                response["choices"][0]
                ["message"]["content"]
            )

            result = json.loads(content)

            proposals = []

            for field in fields:

                target = result.get(field)

                if target == "null":
                    target = None

                if target not in self.ALLOWED_TARGETS:
                    target = None

                confidence = self._calculate_confidence(
                    field,
                    target,
                    field_values.get(field, ""),
                )

                proposals.append(
                    {
                        "source_field": field,
                        "suggested_target": target,
                        "confidence": confidence,
                        "source": "local_ai",
                        "requires_human_approval": True,
                    }
                )

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

    def _calculate_confidence(
        self,
        field: str,
        target: str | None,
        value: str,
    ) -> float:

        if target is None:
            return 0.30

        field_lower = field.lower()

        if (
            "severity" in field_lower
            and target == "event.severity"
        ):
            return 0.90

        if (
            "threat" in field_lower
            and target == "security.threat"
        ):
            return 0.90

        if (
            self._is_ip(value)
            and target in [
                "source.ip",
                "destination.ip",
            ]
        ):
            return 0.90

        return 0.75

    def _extract_fields(
        self,
        payload: str,
    ) -> list[str]:

        fields = set()

        pairs = re.findall(
            r"([A-Za-z_][A-Za-z0-9_]*)=",
            payload,
        )

        for field in pairs:
            fields.add(field)

        return sorted(fields)

    def _extract_field_values(
        self,
        payload: str,
    ) -> dict[str, str]:

        pairs = re.findall(
            r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)",
            payload,
        )

        return {
            key: value
            for key, value in pairs
        }

    def _is_ip(
        self,
        value: str,
    ) -> bool:

        pattern = (
            r"^(?:\d{1,3}\.){3}\d{1,3}$"
        )

        return bool(
            re.match(pattern, value)
        )