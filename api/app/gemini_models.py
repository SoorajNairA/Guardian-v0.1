"""
Models for Gemini integration
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional


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
    recommendation: Optional[str] = Field(
        None,
        description="Optional suggested actions."
    )

    @validator('threat_type')
    def validate_threat_type(cls, v):
        """Ensure threat_type is a list of strings (can be empty for no threats)"""
        if not isinstance(v, list):
            raise ValueError("threat_type must be a list")
        
        # Validate all elements are strings
        if not all(isinstance(x, str) for x in v):
            raise ValueError("all elements in threat_type must be strings")
            
        # For no threats detected, return a list with "none" as the category
        if not v and isinstance(v, list):
            return ["none"]
            
        return v
        
    @validator('recommendation')
    def validate_recommendation(cls, v):
        """Ensure recommendation is either None or a non-empty string"""
        if v is not None and not isinstance(v, str):
            raise ValueError("recommendation must be a string or None")
        if isinstance(v, str) and not v.strip():
            return None  # Convert empty strings to None
        return v


class ModelResponseError(Exception):
    """Exception raised for Gemini model errors"""
    pass