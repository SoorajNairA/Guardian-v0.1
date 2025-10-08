import re
from typing import Dict, List, Optional, Pattern
from .config import settings

def compile_pii_patterns() -> Dict[str, Pattern]:
    """Compile regex patterns for PII detection"""
    return {
        'email': re.compile(r'[\w\.-]+@[\w\.-]+\.\w+'),
        'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
        'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    }

def redact_pii(text: str, enabled_patterns: List[str] = None) -> str:
    """Redact PII from text based on enabled patterns"""
    if not settings.pii_redaction_enabled:
        return text
        
    patterns = compile_pii_patterns()
    enabled_patterns = enabled_patterns or settings.pii_patterns
    
    redacted = text
    for pattern_name in enabled_patterns:
        if pattern_name in patterns:
            redacted = patterns[pattern_name].sub('[REDACTED]', redacted)
    
    return redacted

def apply_privacy_preserving_transforms(text: str) -> Dict[str, str]:
    """Apply privacy-preserving transformations based on privacy mode"""
    transforms = {}
    
    if settings.privacy_mode == "strict":
        # Apply k-anonymity by generalizing specific details
        transforms["k_anonymized"] = re.sub(r'\b\d+\b', '[NUMBER]', text)
        transforms["l_diversified"] = redact_pii(transforms["k_anonymized"])
        final_text = transforms["l_diversified"]
    elif settings.privacy_mode == "minimal":
        # Only redact critical PII
        transforms["minimal_redacted"] = redact_pii(text, ["ssn", "credit_card"])
        final_text = transforms["minimal_redacted"]
    else:  # standard mode
        transforms["redacted"] = redact_pii(text)
        final_text = transforms["redacted"]
        
    return {
        "text": final_text,
        "transforms": transforms,
        "privacy_mode": settings.privacy_mode
    }

def get_explainability_info(
    text: str,
    threats: List[dict],
    graph_features: dict,
    base_score: int
) -> Dict[str, any]:
    """Generate detailed explainability information based on configured detail level"""
    if not settings.xai_enabled:
        return {}
        
    xai_info = {
        "analysis_summary": {
            "input_length": len(text),
            "threat_count": len(threats),
            "risk_score": base_score,
            "risk_factors": []
        }
    }
    
    # Add threat detection explanations
    if settings.xai_detail_level in ["medium", "full"]:
        xai_info["threat_explanations"] = []
        for threat in threats:
            explanation = {
                "category": threat.category,
                "confidence": threat.confidence_score,
                "reasoning": threat.details if hasattr(threat, 'details') else "",
                "evidence": [m.pattern for m in threat.matched_patterns] if hasattr(threat, 'matched_patterns') else []
            }
            xai_info["threat_explanations"].append(explanation)
            
    # Add graph analysis insights
    if settings.xai_detail_level == "full" and graph_features:
        xai_info["graph_analysis"] = {
            "entity_breakdown": graph_features.get("entity_categories", {}),
            "coordination_analysis": {
                "detected": graph_features.get("coordination_detected", False),
                "risk_factors": graph_features.get("risk_factors", {})
            }
        }
        
    return xai_info
