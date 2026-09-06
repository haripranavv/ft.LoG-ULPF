from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EventIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    category: str
    type: str
    action: str | None = None
    severity: int | None = Field(default=None, ge=0, le=10)
    outcome: str | None = None


class NetworkEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    hostname: str | None = None


class NetworkInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: str | None = None
    protocol: str | None = None
    direction: str | None = None
    bytes_in: int | None = Field(default=None, ge=0)
    bytes_out: int | None = Field(default=None, ge=0)


class Observer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    hostname: str | None = None
    ip: str | None = None
    device_type: str | None = None


class UserInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    name: str | None = None
    domain: str | None = None


class SecurityInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threat: str | None = None
    signature: str | None = None
    rule_id: str | None = None
    classification: str | None = None


class ULPFMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    source_format: str
    parser_name: str | None = None
    parser_version: str | None = None
    mapping_id: str | None = None
    mapping_version: str | None = None
    normalization_status: Literal["success", "partial", "failed"]
    processing_mode: Literal[
        "deterministic",
        "ai_assisted",
        "replay",
    ] = "deterministic"


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    raw_event_hash: str
    hash_algorithm: Literal["SHA-256"]
    ingestion_timestamp: datetime | None = None
    processing_timestamp: datetime | None = None
    collector_id: str | None = None
    parent_event_id: str | None = None


class RawEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preserved: Literal[True]
    encoding: str
    content_type: str | None = None
    payload: str
    storage_ref: str | None = None


class ULPFEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: EventIdentity
    timestamp: datetime
    source: NetworkEndpoint | None = None
    destination: NetworkEndpoint | None = None
    network: NetworkInfo | None = None
    observer: Observer | None = None
    user: UserInfo | None = None
    security: SecurityInfo | None = None
    labels: list[str] = Field(default_factory=list)
    extensions: dict[str, Any] = Field(default_factory=dict)
    ulpf: ULPFMetadata
    provenance: Provenance
    raw: RawEvent