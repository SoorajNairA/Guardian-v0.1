"""
Models for Gemini integration
"""

from pydantic import BaseModel, Field, validator
from typing import List


class ThreatAnalysisResult(BaseModel):
    """Result of a threat analysis from Gemini"""
    threat_level: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Threat level score between 0 and 1"
    )
    threat_type: List[str] = Field(
        ...,
        description="List of identified threat categories"
    )
    justification: str = Field(
        ...,
        min_length=1,
        description="Explanation of the analysis"
    )
    recommendation: str = Field(
        "No specific recommendations provided",
        min_length=1,
        description="Suggested actions. Optional for quick analysis mode."
    )

    @validator('threat_type')
    def validate_threat_type(cls, v):
        """Ensure threat_type is not empty"""
        if not v:
            raise ValueError("threat_type cannot be empty")
        return v


class ModelResponseError(Exception):
    """Exception raised for Gemini model errors"""
    pass