from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator, ValidationError
from typing import List, Optional
import re


def sanitize_text(text: str) -> str:
    """
    Sanitize text input to prevent XSS and injection attacks.
    Removes HTML tags, escapes special characters, removes control characters,
    and normalizes whitespace.
    """
    if not isinstance(text, str):
        raise ValueError("Text must be a string")
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Remove JavaScript patterns
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    
    # Remove SQL injection patterns
    text = re.sub(r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)', '', text, flags=re.IGNORECASE)
    
    # Escape HTML entities
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#x27;')
    
    # Remove null bytes and control characters except newlines and tabs
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
    
    # Normalize whitespace (replace multiple spaces/tabs with single space)
    text = re.sub(r'[ \t]+', ' ', text)
    
    # Remove leading/trailing whitespace
    text = text.strip()
    
    return text


class AnalyzeConfig(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_version: Optional[str] = Field(default=None, pattern=r'^[a-zA-Z0-9._-]+$', max_length=50)
    compliance_mode: Optional[str] = Field(default=None, pattern=r'^[a-zA-Z0-9_-]+$', max_length=30)
    
    @field_validator('compliance_mode')
    @classmethod
    def validate_compliance_mode(cls, v):
        if v is not None:
            allowed_modes = ['strict', 'moderate', 'permissive']
            if v.lower() not in allowed_modes:
                raise ValueError(f"compliance_mode must be one of: {', '.join(allowed_modes)}")
        return v


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=100000)
    sanitized_text: str = Field(default="", exclude=True) # For internal use
    config: Optional[AnalyzeConfig] = Field(default=None)
    
    @model_validator(mode='after')
    def validate_and_sanitize_text(self) -> 'AnalyzeRequest':
        v = self.text
        if not isinstance(v, str):
            raise ValueError("Text must be a string")
        
        # Check for UTF-8 encoding
        try:
            v.encode('utf-8')
        except UnicodeEncodeError:
            raise ValueError("Text must be valid UTF-8 encoded")
        
        # Check for null bytes
        if '\x00' in v:
            raise ValueError("Text cannot contain null bytes")
        
        # Check for excessive control characters (excluding newlines and tabs)
        control_chars = sum(1 for char in v if ord(char) < 32 and char not in '\n\t')
        if control_chars > len(v) * 0.1:  # More than 10% control characters
            raise ValueError("Text contains too many control characters")
        
        # Sanitize the text and store it
        try:
            self.sanitized_text = sanitize_text(v)
        except Exception as e:
            raise ValueError(f"Text sanitization failed: {str(e)}")
        
        # Return the model with the original text intact
        return self


class Threat(BaseModel):
    category: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    details: Optional[str] = None


class AnalyzeMetadata(BaseModel):
    is_ai_generated: Optional[bool] = None
    language: Optional[str] = None
    gemini_error: Optional[str] = None
    forensic_watermark: Optional[str] = None
    attribution: Optional[str] = None
    privacy_preserving: Optional[bool] = None
    explainability: Optional[str] = None
    graph_entities: Optional[list] = None
    graph_score: Optional[float] = None
    gemini_analysis: Optional[str] = None  # Detailed analysis from Gemini
    propaganda_score: Optional[float] = Field(None, ge=0.0, le=1.0)  # Propaganda/disinformation confidence from Gemini


class AnalyzeResult(BaseModel):
    risk_score: int
    threats_detected: List[Threat]
    metadata: AnalyzeMetadata


class AnalyzeResponse(AnalyzeResult):
    request_id: str


class GeminiPart(BaseModel):
    text: str


class GeminiContent(BaseModel):
    parts: List[GeminiPart]


class GeminiCandidate(BaseModel):
    content: GeminiContent


class GeminiResponse(BaseModel):
    candidates: List[GeminiCandidate]


class ThreatAnalysisResult(BaseModel):
    threat_level: float = Field(ge=0.0, le=1.0)
    threat_type: List[str]
    justification: str
    recommendation: Optional[str] = None




