import re
from typing import List, Optional
from .models import AnalyzeResult, Threat, AnalyzeMetadata
from .gemini import gemini_enrich


PHISHING_PATTERNS = [
    re.compile(r"reset your password", re.I),
    re.compile(r"verify your account", re.I),
    re.compile(r"click here", re.I),
]

PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN pattern
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),  # credit card-ish
]

MALWARE_PATTERNS = [
    re.compile(r"powershell.*-enc", re.I),
    re.compile(r"rm -rf /", re.I),
]

JAILBREAK_PATTERNS = [
    re.compile(r"ignore previous instructions", re.I),
    re.compile(r"bypass the guardrails", re.I),
]

SELF_HARM_PATTERNS = [
    re.compile(r"i want to die", re.I),
    re.compile(r"kill myself", re.I),
]

TOXIC_PATTERNS = [
    re.compile(r"\bidiot\b", re.I),
    re.compile(r"\bstupid\b", re.I),
]


async def analyze_text(
    text: str,
    model_version: Optional[str] = None,
    compliance_mode: Optional[str] = None,
) -> AnalyzeResult:
    threats: List[Threat] = []

    def maybe_add(patterns: List[re.Pattern], category: str, details: str):
        for p in patterns:
            if p.search(text or ""):
                threats.append(Threat(category=category, confidence_score=0.8, details=details))
                break

    maybe_add(PHISHING_PATTERNS, "phishing_attempt", "Suspicious phrase detected")
    maybe_add(PII_PATTERNS, "pii_exfiltration", "Potential PII pattern detected")
    maybe_add(MALWARE_PATTERNS, "malware_instruction", "Potential malware command detected")
    maybe_add(JAILBREAK_PATTERNS, "jailbreak_prompting", "Jailbreak attempt phrasing")
    maybe_add(SELF_HARM_PATTERNS, "self_harm_risk", "Self-harm risk language")
    maybe_add(TOXIC_PATTERNS, "toxic_content", "Toxic language detected")

    metadata = AnalyzeMetadata(is_ai_generated=None, language="en")

    # Basic risk: sum of category weights (capped)
    base_score = min(100, int(len(threats) * 20))

    # Gemini enrichment (best-effort)
    enriched = await gemini_enrich(text=text, threats=threats, base_score=base_score)

    return AnalyzeResult(
        risk_score=enriched["risk_score"],
        threats_detected=enriched["threats"],
        metadata=metadata,
    )



