import re
from typing import List, Optional, Dict, Tuple
from langdetect import detect, LangDetectException
from .models import AnalyzeResult, Threat, AnalyzeMetadata
from .gemini import gemini_enrich


# Category weights based on severity (higher = more severe)
CATEGORY_WEIGHTS = {
    "malware_instruction": 0.95,
    "code_injection": 0.92,
    "prompt_injection": 0.90,
    "credential_harvesting": 0.88,
    "financial_fraud": 0.85,
    "phishing_attempt": 0.82,
    "social_engineering": 0.80,
    "jailbreak_prompting": 0.78,
    "pii_exfiltration": 0.75,
    "privacy_violation": 0.70,
    "toxic_content": 0.65,
    "hate_speech": 0.68,
    "misinformation": 0.60,
    "self_harm_risk": 0.85,
}

# Comprehensive threat patterns organized by language and category
THREAT_PATTERNS = {
    "en": {
        "phishing_attempt": [
            {"pattern": r"\breset\s+(?:your\s+)?password\b.*?(?:urgent|immediately|expire)", "weight": 0.9, "context": "urgency"},
            {"pattern": r"\bverify\s+(?:your\s+)?account\b.*?(?:suspended|locked|closed)", "weight": 0.85, "context": "threat"},
            {"pattern": r"\bclick\s+here\b.*?(?:verify|confirm|update)", "weight": 0.7, "context": "action"},
            {"pattern": r"\b(?:win|won|prize|reward)\b.*?(?:click|visit|claim)", "weight": 0.8, "context": "incentive"},
            {"pattern": r"\b(?:limited\s+time|act\s+now|expires\s+soon)\b.*?(?:click|visit)", "weight": 0.75, "context": "urgency"},
        ],
        "social_engineering": [
            {"pattern": r"\b(?:pretend|act\s+as|roleplay|simulate)\b.*?(?:admin|moderator|official)", "weight": 0.85, "context": "authority"},
            {"pattern": r"\b(?:trust\s+me|believe\s+me|i\s+swear)\b.*?(?:password|login|account)", "weight": 0.8, "context": "persuasion"},
            {"pattern": r"\b(?:urgent|emergency|asap)\b.*?(?:send|provide|give)\s+(?:me\s+)?(?:password|pin|code)", "weight": 0.9, "context": "urgency"},
            {"pattern": r"\b(?:ceo|boss|manager)\b.*?(?:needs|wants|requires).*?(?:immediately|urgent)", "weight": 0.8, "context": "authority"},
        ],
        "credential_harvesting": [
            {"pattern": r"\b(?:enter|input|provide|give)\s+(?:your\s+)?(?:password|pin|passcode|credential)", "weight": 0.9, "context": "direct_request"},
            {"pattern": r"\b(?:username|login|email)\s+and\s+(?:password|pin|passcode)", "weight": 0.85, "context": "pair_request"},
            {"pattern": r"\b(?:two\s+factor|2fa|mfa)\s+(?:code|token|pin)", "weight": 0.8, "context": "mfa_request"},
            {"pattern": r"\b(?:authentication|auth)\s+(?:code|token|key|pin)", "weight": 0.75, "context": "auth_request"},
        ],
        "financial_fraud": [
            {"pattern": r"\b(?:wire\s+transfer|send\s+money|payment\s+required)\b.*?(?:urgent|immediately)", "weight": 0.9, "context": "payment_urgency"},
            {"pattern": r"\b(?:gift\s+card|itunes|google\s+play)\s+(?:code|pin|number)", "weight": 0.8, "context": "gift_card"},
            {"pattern": r"\b(?:bitcoin|crypto|ethereum)\s+(?:address|wallet|send)", "weight": 0.85, "context": "crypto_payment"},
            {"pattern": r"\b(?:refund|rebate|cash\s+back)\b.*?(?:click|visit|claim)", "weight": 0.7, "context": "fake_refund"},
        ],
        "malware_instruction": [
            {"pattern": r"\bpowershell\b.*?(?:-enc|-command|-c)\b", "weight": 0.95, "context": "encoded_command"},
            {"pattern": r"\brm\s+-rf\s+/\b", "weight": 0.9, "context": "destructive_command"},
            {"pattern": r"\b(?:download|wget|curl)\s+(?:http|https|ftp)://.*?\.(?:exe|bat|sh|ps1)", "weight": 0.85, "context": "suspicious_download"},
            {"pattern": r"\b(?:chmod\s+777|sudo\s+rm)\b", "weight": 0.8, "context": "privilege_escalation"},
            {"pattern": r"\b(?:net\s+user|adduser|useradd)\b.*?(?:administrator|admin)", "weight": 0.75, "context": "user_creation"},
        ],
        "code_injection": [
            {"pattern": r"\b(?:<script|javascript:|on\w+\s*=)", "weight": 0.9, "context": "javascript_injection"},
            {"pattern": r"\b(?:union\s+select|drop\s+table|delete\s+from)\b", "weight": 0.95, "context": "sql_injection"},
            {"pattern": r"\b(?:eval\s*\(|exec\s*\(|system\s*\()", "weight": 0.9, "context": "code_execution"},
            {"pattern": r"\b(?:base64_decode|base64_decode)\s*\(", "weight": 0.8, "context": "obfuscated_code"},
        ],
        "prompt_injection": [
            {"pattern": r"\bignore\s+(?:previous|all)\s+(?:instructions|prompts)\b", "weight": 0.95, "context": "instruction_override"},
            {"pattern": r"\bbypass\s+(?:the\s+)?(?:guardrails|safety|restrictions)\b", "weight": 0.9, "context": "safety_bypass"},
            {"pattern": r"\b(?:jailbreak|break\s+free)\b.*?(?:mode|persona)", "weight": 0.85, "context": "jailbreak_attempt"},
            {"pattern": r"\b(?:pretend|act\s+as|roleplay)\b.*?(?:developer|admin|root)", "weight": 0.8, "context": "privilege_assumption"},
        ],
        "pii_exfiltration": [
            {"pattern": r"\b\d{3}-\d{2}-\d{4}\b", "weight": 0.9, "context": "ssn_pattern"},
            {"pattern": r"\b(?:\d[ -]*?){13,19}\b", "weight": 0.8, "context": "credit_card_pattern"},
            {"pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "weight": 0.6, "context": "email_pattern"},
            {"pattern": r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b", "weight": 0.7, "context": "phone_pattern"},
        ],
        "privacy_violation": [
            {"pattern": r"\b(?:track|monitor|surveil|spy)\b.*?(?:user|customer|person)", "weight": 0.8, "context": "surveillance"},
            {"pattern": r"\b(?:collect|gather|harvest)\s+(?:personal|private|sensitive)\s+(?:data|info)", "weight": 0.85, "context": "data_collection"},
            {"pattern": r"\b(?:breach|leak|expose)\s+(?:personal|private|confidential)", "weight": 0.9, "context": "data_exposure"},
        ],
        "toxic_content": [
            {"pattern": r"\b(?:idiot|stupid|moron|retard)\b", "weight": 0.6, "context": "insult"},
            {"pattern": r"\b(?:kill|murder|destroy)\s+(?:yourself|himself|herself)\b", "weight": 0.9, "context": "violence_encouragement"},
            {"pattern": r"\b(?:hate|despise|loathe)\b.*?(?:you|them|people)", "weight": 0.7, "context": "hatred"},
        ],
        "hate_speech": [
            {"pattern": r"\b(?:racist|sexist|homophobic)\b.*?(?:slur|epithet)", "weight": 0.9, "context": "discriminatory_language"},
            {"pattern": r"\b(?:inferior|superior)\b.*?(?:race|gender|religion)", "weight": 0.8, "context": "discriminatory_belief"},
            {"pattern": r"\b(?:genocide|ethnic\s+cleansing)\b", "weight": 0.95, "context": "extreme_violence"},
        ],
        "misinformation": [
            {"pattern": r"\b(?:fake\s+news|conspiracy|hoax)\b.*?(?:believe|trust|share)", "weight": 0.7, "context": "misinformation_promotion"},
            {"pattern": r"\b(?:vaccines\s+cause|climate\s+change\s+hoax)\b", "weight": 0.8, "context": "scientific_denial"},
            {"pattern": r"\b(?:government\s+coverup|hidden\s+truth)\b", "weight": 0.6, "context": "conspiracy_theory"},
        ],
        "self_harm_risk": [
            {"pattern": r"\bi\s+want\s+to\s+(?:die|kill\s+myself|end\s+it)\b", "weight": 0.9, "context": "direct_self_harm"},
            {"pattern": r"\b(?:suicide|self\s+harm|cutting)\b.*?(?:plan|method|way)", "weight": 0.85, "context": "self_harm_planning"},
            {"pattern": r"\b(?:worthless|useless|burden)\b.*?(?:life|existence)", "weight": 0.7, "context": "self_worth_issues"},
        ],
        "jailbreak_prompting": [
            {"pattern": r"\bignore\s+previous\s+instructions\b", "weight": 0.9, "context": "instruction_override"},
            {"pattern": r"\bbypass\s+the\s+guardrails\b", "weight": 0.85, "context": "safety_bypass"},
            {"pattern": r"\b(?:dan|do\s+anything\s+now)\b", "weight": 0.8, "context": "jailbreak_persona"},
        ],
    },
    "es": {
        "phishing_attempt": [
            {"pattern": r"\brestablecer\s+(?:su\s+)?contraseña\b.*?(?:urgente|inmediatamente)", "weight": 0.9, "context": "urgency"},
            {"pattern": r"\bverificar\s+(?:su\s+)?cuenta\b.*?(?:suspendida|bloqueada)", "weight": 0.85, "context": "threat"},
            {"pattern": r"\bhaga\s+clic\s+aquí\b.*?(?:verificar|confirmar)", "weight": 0.7, "context": "action"},
        ],
        "social_engineering": [
            {"pattern": r"\b(?:fingir|actuar\s+como|simular)\b.*?(?:admin|moderador|oficial)", "weight": 0.85, "context": "authority"},
            {"pattern": r"\b(?:confíe\s+en\s+mí|crea\s+en\s+mí)\b.*?(?:contraseña|login)", "weight": 0.8, "context": "persuasion"},
        ],
        "malware_instruction": [
            {"pattern": r"\bpowershell\b.*?(?:-enc|-comando)", "weight": 0.95, "context": "encoded_command"},
            {"pattern": r"\brm\s+-rf\s+/\b", "weight": 0.9, "context": "destructive_command"},
        ],
        "toxic_content": [
            {"pattern": r"\b(?:idiota|estúpido|imbécil)\b", "weight": 0.6, "context": "insult"},
            {"pattern": r"\b(?:matar|asesinar)\s+(?:a\s+tí\s+mismo|suicidarse)\b", "weight": 0.9, "context": "violence_encouragement"},
        ],
    },
    "fr": {
        "phishing_attempt": [
            {"pattern": r"\bréinitialiser\s+(?:votre\s+)?mot\s+de\s+passe\b.*?(?:urgent|immédiatement)", "weight": 0.9, "context": "urgency"},
            {"pattern": r"\bvérifier\s+(?:votre\s+)?compte\b.*?(?:suspendu|bloqué)", "weight": 0.85, "context": "threat"},
        ],
        "malware_instruction": [
            {"pattern": r"\bpowershell\b.*?(?:-enc|-commande)", "weight": 0.95, "context": "encoded_command"},
        ],
        "toxic_content": [
            {"pattern": r"\b(?:idiot|stupide|imbécile)\b", "weight": 0.6, "context": "insult"},
        ],
    },
    "de": {
        "phishing_attempt": [
            {"pattern": r"\bpasswort\s+zurücksetzen\b.*?(?:dringend|sofort)", "weight": 0.9, "context": "urgency"},
            {"pattern": r"\bkonto\s+verifizieren\b.*?(?:gesperrt|blockiert)", "weight": 0.85, "context": "threat"},
        ],
        "malware_instruction": [
            {"pattern": r"\bpowershell\b.*?(?:-enc|-befehl)", "weight": 0.95, "context": "encoded_command"},
        ],
        "toxic_content": [
            {"pattern": r"\b(?:idiot|dumm|blöd)\b", "weight": 0.6, "context": "insult"},
        ],
    },
    "pt": {
        "phishing_attempt": [
            {"pattern": r"\bredefinir\s+(?:sua\s+)?senha\b.*?(?:urgente|imediatamente)", "weight": 0.9, "context": "urgency"},
            {"pattern": r"\bverificar\s+(?:sua\s+)?conta\b.*?(?:suspensa|bloqueada)", "weight": 0.85, "context": "threat"},
        ],
        "malware_instruction": [
            {"pattern": r"\bpowershell\b.*?(?:-enc|-comando)", "weight": 0.95, "context": "encoded_command"},
        ],
        "toxic_content": [
            {"pattern": r"\b(?:idiota|estúpido|imbecil)\b", "weight": 0.6, "context": "insult"},
        ],
    },
}


def detect_language(text: str) -> str:
    """
    Detect the language of the input text using langdetect library.
    Returns language code or 'en' as fallback.
    """
    try:
        # Clean text for better detection
        clean_text = re.sub(r'[^\w\s]', ' ', text.lower())
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()
        
        # Minimum text length for reliable detection
        if len(clean_text.split()) < 3:
            return 'en'
            
        detected = detect(clean_text)
        # Map to supported languages or fallback to English
        supported_languages = ['en', 'es', 'fr', 'de', 'pt']
        return detected if detected in supported_languages else 'en'
    except (LangDetectException, Exception):
        return 'en'


def calculate_confidence(
    match: re.Match,
    pattern_info: Dict,
    text: str,
    category: str
) -> float:
    """
    Calculate dynamic confidence score based on pattern strength, context, and category weight.
    """
    base_confidence = pattern_info.get("weight", 0.5)
    category_weight = CATEGORY_WEIGHTS.get(category, 0.5)
    
    # Start with base confidence
    confidence = base_confidence
    
    # Apply category weight
    confidence *= category_weight
    
    # Context-based adjustments
    context = pattern_info.get("context", "")
    matched_text = match.group(0).lower()
    
    # Urgency indicators increase confidence
    if "urgency" in context and any(word in matched_text for word in ["urgent", "immediately", "asap", "now"]):
        confidence *= 1.1
    
    # Authority indicators increase confidence for social engineering
    if "authority" in context and any(word in matched_text for word in ["admin", "manager", "boss", "ceo"]):
        confidence *= 1.15
    
    # Multiple indicators in same text increase confidence
    text_lower = text.lower()
    if category == "phishing_attempt":
        urgency_words = ["urgent", "immediately", "expire", "limited", "now"]
        authority_words = ["official", "security", "admin", "support"]
        if sum(1 for word in urgency_words if word in text_lower) > 1:
            confidence *= 1.1
        if sum(1 for word in authority_words if word in text_lower) > 1:
            confidence *= 1.05
    
    # Text length factor (longer suspicious texts are more likely to be threats)
    if len(text) > 100:
        confidence *= 1.05
    
    # Cap at 1.0
    return min(1.0, confidence)


def analyze_patterns(text: str, language: str) -> List[Threat]:
    """
    Analyze text against all threat patterns for the detected language.
    Returns list of detected threats with confidence scores.
    """
    threats = []
    matched_positions = set()  # Track matched positions to avoid overlaps
    
    # Get patterns for the detected language, fallback to English
    language_patterns = THREAT_PATTERNS.get(language, THREAT_PATTERNS.get("en", {}))
    
    for category, patterns in language_patterns.items():
        for pattern_info in patterns:
            pattern = re.compile(pattern_info["pattern"], re.IGNORECASE | re.MULTILINE)
            
            for match in pattern.finditer(text):
                # Check for position overlap with previous matches
                match_start, match_end = match.span()
                overlap = any(
                    start <= match_start < end or start < match_end <= end
                    for start, end in matched_positions
                )
                
                if not overlap:
                    confidence = calculate_confidence(match, pattern_info, text, category)
                    
                    # Only add threat if confidence is above threshold
                    if confidence >= 0.3:  # Minimum confidence threshold
                        threat_details = f"{pattern_info.get('context', 'Pattern detected')}: '{match.group(0)}'"
                        threats.append(Threat(
                            category=category,
                            confidence_score=confidence,
                            details=threat_details
                        ))
                        
                        # Mark this position as matched
                        matched_positions.add((match_start, match_end))
                        break  # Only take first match per pattern to avoid spam
    
    return threats


async def analyze_text(
    text: str,
    model_version: Optional[str] = None,
    compliance_mode: Optional[str] = None,
) -> AnalyzeResult:
    """
    Enhanced threat analysis with multi-language support and dynamic confidence scoring.
    """
    # Detect language first
    detected_language = detect_language(text)
    
    # Analyze patterns for detected language
    threats = analyze_patterns(text, detected_language)
    
    # Create metadata with detected language
    metadata = AnalyzeMetadata(
        is_ai_generated=None,
        language=detected_language
    )
    
    # Calculate weighted risk score
    if not threats:
        base_score = 0
    else:
        # Use weighted sum with diminishing returns for multiple threats in same category
        category_scores = {}
        for threat in threats:
            category = threat.category
            confidence = threat.confidence_score
            
            # Diminishing returns for multiple threats in same category
            if category in category_scores:
                category_scores[category] = min(1.0, category_scores[category] + (confidence * 0.3))
            else:
                category_scores[category] = confidence
        
        # Calculate weighted sum
        weighted_sum = sum(
            score * CATEGORY_WEIGHTS.get(category, 0.5)
            for category, score in category_scores.items()
        )
        
        # Convert to 0-100 scale with some scaling
        base_score = min(100, int(weighted_sum * 80))
    
    # Gemini enrichment (best-effort)
    enriched = await gemini_enrich(text=text, threats=threats, base_score=base_score)

    # Update metadata with Gemini results
    metadata.is_ai_generated = enriched.get("is_ai_generated")
    metadata.language = enriched.get("language", detected_language)
    if "error" in enriched:
        metadata.gemini_error = enriched["error"]
    
    return AnalyzeResult(
        risk_score=enriched["risk_score"],
        threats_detected=enriched["threats"],
        metadata=metadata,
    )



