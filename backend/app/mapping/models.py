from pydantic import BaseModel, Field


class FieldMapping(BaseModel):
    source_field: str
    target_field: str
    confidence: float = Field(ge=0.0, le=1.0)
    required: bool = False


class MappingDefinition(BaseModel):
    mapping_id: str
    version: str
    source_format: str
    vendor: str | None = None
    product: str | None = None
    fields: list[FieldMapping]