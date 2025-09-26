from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional


class AnalyzeConfig(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_version: Optional[str] = Field(default=None)
    compliance_mode: Optional[str] = Field(default=None)


class AnalyzeRequest(BaseModel):
    text: str
    config: Optional[AnalyzeConfig] = Field(default=None)


class Threat(BaseModel):
    category: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    details: Optional[str] = None


class AnalyzeMetadata(BaseModel):
    is_ai_generated: Optional[bool] = None
    language: Optional[str] = None


class AnalyzeResult(BaseModel):
    risk_score: int
    threats_detected: List[Threat]
    metadata: AnalyzeMetadata


class AnalyzeResponse(AnalyzeResult):
    request_id: str



