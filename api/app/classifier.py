import re
from typing import List, Optional, Dict, Tuple
from langdetect import detect, LangDetectException
from .models import AnalyzeResult, Threat, AnalyzeMetadata
from .gemini import gemini_enrich
from .config import settings
from .threat_intel import threat_intel


# Category weights based on severity (higher = more severe)
CATEGORY_WEIGHTS = {
    "malware_instruction": 0.95,
    "code_injection": 0.92,
    "prompt_injection": 0.90,
    "credential_harvesting": 0.88,
    "financial_fraud": 0.85,
    "phishing_attempt": 0.82,
    "social_engineering": 0.80,
    "toxic_content": 0.65,
    "hate_speech": 0.68,
    "misinformation": 0.60,
    "self_harm_risk": 0.85,
}

# Graph-based threat intelligence analysis
def analyze_graph(text: str) -> dict:
    """
    Enhanced graph-based threat analysis. Identifies entities, relationships, and potential
    coordination patterns in text content.
    
    Features:
    - Entity extraction (URLs, mentions, hashtags, IPs, emails)
    - Basic relationship mapping
    - Coordination pattern detection
    - Propagation score calculation
    """
    # Entity extraction with expanded patterns
    entities = {
        'urls': re.findall(r'https?://[\w\-./%]+', text),
        'mentions': re.findall(r'@[\w]+', text),
        'hashtags': re.findall(r'#[\w]+', text),
        'ips': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text),
        'emails': re.findall(r'[\w\.-]+@[\w\.-]+', text)
    }
    
    # Calculate entity frequencies and relationships
    entity_freqs = {}
    for category, items in entities.items():
        entity_freqs.update({item: items.count(item) for item in items})
    
    # Identify potential coordination patterns
    coordination_indicators = 0
    if len(entities['hashtags']) > 2 and len(set(entities['hashtags'])) < len(entities['hashtags']):
        coordination_indicators += 1  # Repeated hashtags
    if len(entities['urls']) > 1 and len(set(entities['urls'])) == 1:
        coordination_indicators += 1  # Same URL repeated
    if len(entities['mentions']) > 3:
        coordination_indicators += 1  # Mass mentioning
        
    # Calculate propagation risk score based on multiple factors
    entity_diversity = len(set().union(*entities.values()))
    frequency_weight = sum(freq for freq in entity_freqs.values())
    coordination_weight = coordination_indicators * 0.2
    
    graph_score = min(1.0, (
        (entity_diversity * 0.4) + 
        (frequency_weight * 0.3) + 
        (coordination_weight * 0.3)
    ) / 10.0)
    
    # Flatten entities for metadata while preserving full analysis
    all_entities = list(set().union(*entities.values()))
    
    return {
        "entities": all_entities,
        "entity_count": len(all_entities),
        "graph_score": graph_score,
        "coordination_detected": coordination_indicators > 0,
        "entity_categories": {k: list(set(v)) for k, v in entities.items()},
        "risk_factors": {
            "entity_diversity": entity_diversity,
            "frequency_patterns": frequency_weight,
            "coordination_indicators": coordination_indicators
        }
    }
THREAT_PATTERNS = {
    "en": {
        "phishing_attempt": [
            # Basic phishing patterns
            {"pattern": r"\b(click|tap|visit|go to|press|follow)\s+(here|this link|the link|the url|the website|below|this)\b.*?(reset|verify|confirm|update|password|account|login|get|claim)", "weight": 0.92, "context": "action_link"},
            {"pattern": r"https?://[\w./-]+.*?(reset|verify|confirm|update|password|account|login|get|claim)", "weight": 0.91, "context": "link_action"},
            {"pattern": r"\b(urgent|immediately|expires|limited time|act now|asap|now|hurry)\b.*?(reset|verify|confirm|update|password|account|login|get|claim)", "weight": 0.9, "context": "urgency_action"},
            {"pattern": r"\b(verify|verified|confirm|update|reset)\b[\s\S]{0,80}\b(account|login|password|card|bank)\b[\s\S]{0,160}(?:https?://|www\.)", "weight": 0.88, "context": "link_verification"},
            {"pattern": r"\b(you have won|prize|reward|gift|claim|free|exclusive|million|thousand)\b.*?(click|visit|claim|here|link|press|this|get)", "weight": 0.92, "context": "incentive"},
            {"pattern": r"\b(suspended|locked|closed|restricted|compromised|limited)\b.*?(account|login|password|access|offer)", "weight": 0.87, "context": "threat"},
            {"pattern": r"\bsecurity\s+(alert|notice|update|warning)\b.*?(click|visit|here|link)", "weight": 0.86, "context": "security_alert"},
            
            # Deceptive URLs and domains
            {"pattern": r"(?:https?://|www\.)[^/\s]+(?:\.[^/\s]+)+\b.*?(?:bank|login|account|secure|verify)", "weight": 0.89, "context": "suspicious_url"},
            {"pattern": r"\b(?:login|signin|account|verify)\b.*?(?:https?://|www\.)", "weight": 0.88, "context": "suspicious_action_url"},
        ],
        "financial_fraud": [
            # Luxury goods scams
            {"pattern": r"\b(genuine|authentic|real|original)\s+(?:rolex|louis vuitton|gucci|prada|chanel)\b.*?\$?\d{1,3}\b", "weight": 0.89, "context": "luxury_scam"},
            {"pattern": r"\b(?:rolex|louis vuitton|gucci|prada|chanel).*?(?:cheap|discount|sale|deal).*?\$?\d{1,3}\b", "weight": 0.88, "context": "luxury_discount"},
            
            # Unrealistic returns
            {"pattern": r"\b(?:\d{3,}%|[1-9]\d+x)\s*(?:return|profit|gain|back|guaranteed)\b", "weight": 0.95, "context": "unrealistic_returns"},
            {"pattern": r"\b(?:guaranteed|promised|assured)\s+(?:return|profit|gain|money)\b", "weight": 0.87, "context": "guaranteed_profit"},
            
            # Crypto scams
            {"pattern": r"\b(?:crypto|bitcoin|eth|wallet).*?(?:send|transfer|deposit).*?(?:0x[\da-fA-F]{40}|bc1\w{25,39})\b", "weight": 0.93, "context": "crypto_wallet"},
            {"pattern": r"\b(?:investment|trading|mining).*?(?:\d{3,}%|(?:10|20|30|40|50)x).*?(?:daily|weekly|monthly|yearly)\b", "weight": 0.92, "context": "investment_scam"},
        ],
        "malware_instruction": [
            # Executable and script patterns
            {"pattern": r"\b(?:download|run|execute|install).*?(?:\.exe|\.bat|\.ps1|\.sh)\b", "weight": 0.93, "context": "executable"},
            {"pattern": r"\b(?:virus|malware|trojan|ransomware|keylogger).*?(?:\.exe|\.zip|\.rar)\b", "weight": 0.95, "context": "malware"},
            
            # Code injection patterns
            {"pattern": r"(?:rm -rf|DROP TABLE|DELETE FROM|;.*?;|eval\(|exec\()", "weight": 0.94, "context": "code_injection"},
            {"pattern": r"\b(?:sudo|chmod|chown).*?(?:/etc/|/var/|/root/)", "weight": 0.92, "context": "system_command"},
        ],
        "social_engineering": [
            # Tech support scams
            {"pattern": r"(?:this is|we are)?\s*(?:microsoft|apple|google|amazon)\s*(?:support|service|help)", "weight": 0.91, "context": "tech_support"},
            {"pattern": r"\b(?:call|contact|reach).*?(?:\+\d{1,2}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{4}|\d{3}[-\s]?\d{3}[-\s]?\d{4}|\+?\d{1,4}[-\s]?\d{3}[-\s]?\d{4})", "weight": 0.89, "context": "support_number"},
            {"pattern": r"\b(?:detected|found|discovered)\s+(?:virus|malware|threat|issue|problem|infection)", "weight": 0.88, "context": "tech_threat"},
            
            # Authority impersonation
            {"pattern": r"\b(?:we are|this is).*?(?:microsoft|apple|google|amazon|bank|government|irs|fbi)\b", "weight": 0.90, "context": "impersonation"},
            {"pattern": r"\b(?:detected|found|discovered).*?(?:virus|malware|breach|compromise|issue).*?(?:computer|device|system|account)\b", "weight": 0.88, "context": "false_alert"},
            
            # Money/Prize related scams
            {"pattern": r"\b(?:money|cash|dollars|prize|million)\b.*?(?:https?://|www\.)", "weight": 0.93, "context": "financial_scam"},
            {"pattern": r"\b(?:get|claim|receive)\b.*?(?:money|prize|reward)\b.*?(?:https?://|www\.)", "weight": 0.91, "context": "prize_scam"},
        ],
        
        "credential_harvesting": [
            # Credential collection
            {"pattern": r"\b(?:enter|provide|submit|confirm)\b.*?(?:details|information|card|credentials)\b", "weight": 0.9, "context": "credential_harvesting"},
            {"pattern": r"\b(?:debit|credit)\s*card\b.*?(?:details|number|pin|cvv)", "weight": 0.94, "context": "card_harvesting"},
            {"pattern": r"\b(?:verify|confirm|update)\b.*?(?:bank|account|card)\b.*?(?:details|information|number)", "weight": 0.92, "context": "financial_info"},
        ],
        "disinformation": [
            {"pattern": r"\b(fake news|conspiracy|hoax|mislead|misinformation|propaganda|rumor|false claim|fabricated|deceptive|manipulate)\b", "weight": 0.8, "context": "disinfo_general"},
            {"pattern": r"\b(vaccines cause|climate change hoax|government coverup|hidden truth|deep state|crisis actor|false flag)\b", "weight": 0.85, "context": "disinfo_specific"},
            {"pattern": r"\b(viral|trending|share|spread|retweet|forward|broadcast)\b.*?(rumor|fake|hoax|mislead|propaganda)", "weight": 0.82, "context": "disinfo_spread"},
        ],
        "propaganda": [
            {"pattern": r"\b(extremist|radicalize|recruit|join|movement|cause|fight|enemy|traitor|patriot|martyr)\b.*?(message|campaign|operation|mission|goal)", "weight": 0.88, "context": "propaganda_recruitment"},
            {"pattern": r"\b(our cause|the movement|join us|fight for|defend|protect|stand with|against them|unite|rise up)\b", "weight": 0.87, "context": "propaganda_call"},
        ],
        "social_engineering": [
            # Tech support scams
            {"pattern": r"\b(?:microsoft|apple|google|amazon)\s*(?:support|service|help)", "weight": 0.91, "context": "tech_support"},
            {"pattern": r"\b(?:call|contact|reach).*?(?:\+\d{1,2}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{4}|\d{3}[-\s]?\d{3}[-\s]?\d{4})", "weight": 0.89, "context": "support_number"},
            {"pattern": r"\b(?:detected|found|discovered)\s+(?:virus|malware|threat|issue|problem|infection)", "weight": 0.88, "context": "tech_threat"},
            
            # Authority impersonation
            {"pattern": r"\b(?:pretend|act\s+as|roleplay|simulate)\b.*?(?:admin|moderator|official)", "weight": 0.85, "context": "authority"},
            {"pattern": r"\b(?:trust\s+me|believe\s+me|i\s+swear)\b.*?(?:password|login|account)", "weight": 0.8, "context": "persuasion"},
            {"pattern": r"\b(?:urgent|emergency|asap)\b.*?(?:send|provide|give)\s+(?:me\s+)?(?:password|pin|code)", "weight": 0.9, "context": "urgency"},
            {"pattern": r"\b(?:ceo|boss|manager)\b.*?(?:needs|wants|requires).*?(?:immediately|urgent)", "weight": 0.8, "context": "authority"},
            
            # Tech support specifics
            {"pattern": r"\b(?:this is|we are)\s+(?:microsoft|apple|google|amazon|bank)\s*(?:support|service|security)", "weight": 0.92, "context": "tech_impersonation"},
            {"pattern": r"\b(?:your computer|your device|your system)\s+(?:has|is|was)\s+(?:infected|compromised|hacked)", "weight": 0.90, "context": "tech_threat"},
        ],
        "credential_harvesting": [
            {"pattern": r"\b(?:enter|input|provide|give)\s+(?:your\s+)?(?:password|pin|passcode|credential)", "weight": 0.9, "context": "direct_request"},
            {"pattern": r"\b(?:username|login|email)\s+and\s+(?:password|pin|passcode)", "weight": 0.85, "context": "pair_request"},
            {"pattern": r"\b(?:two\s+factor|2fa|mfa)\s+(?:code|token|pin)", "weight": 0.8, "context": "mfa_request"},
            {"pattern": r"\b(?:authentication|auth)\s+(?:code|token|key|pin)", "weight": 0.75, "context": "auth_request"},
        ],
        "financial_fraud": [
            # Basic financial fraud patterns
            {"pattern": r"\b(?:wire\s+transfer|send\s+money|payment\s+required)\b.*?(?:urgent|immediately)", "weight": 0.9, "context": "payment_urgency"},
            {"pattern": r"\b(?:gift\s+card|itunes|google\s+play)\s+(?:code|pin|number)", "weight": 0.8, "context": "gift_card"},
            {"pattern": r"\b(?:bitcoin|crypto|ethereum)\s+(?:address|wallet|send)", "weight": 0.85, "context": "crypto_payment"},
            {"pattern": r"\b(?:refund|rebate|cash\s+back)\b.*?(?:click|visit|claim)", "weight": 0.7, "context": "fake_refund"},
            
            # Get rich quick scams
            {"pattern": r"\b(?:million|[0-9]+k|[0-9]+\s*thousand)\b.*?(?:prize|win|claim|offer)", "weight": 0.92, "context": "get_rich_quick"},
            {"pattern": r"\b(?:easy|quick|fast)\s*(?:money|cash|dollars)\b", "weight": 0.85, "context": "get_rich_quick"},
            {"pattern": r"\b(?:lottery|jackpot|prize)\s*(?:winner|claim|collect)\b", "weight": 0.9, "context": "lottery_scam"},
            
            # Banking and card scams
            {"pattern": r"\b(?:debit|credit|bank)\s*(?:card|account)\b.*?(?:login|enter|provide)", "weight": 0.95, "context": "card_scam"},
            {"pattern": r"\b(?:verify|confirm|validate)\b.*?(?:card|account|banking)\b", "weight": 0.88, "context": "card_verification_scam"},
            {"pattern": r"\b(?:login|sign\s*in)\b.*?(?:bank|account|card)\b", "weight": 0.87, "context": "banking_login_scam"},
            
            # Money mule and job scams
            {"pattern": r"\b(?:process|transfer|handle)\s*(?:payment|money|fund)s?\b", "weight": 0.9, "context": "money_mule"},
            {"pattern": r"\b(?:work\s*from\s*home|online\s*job)\b.*?(?:\$[0-9,.]+|[0-9,.]+\s*dollars|money)", "weight": 0.85, "context": "job_scam"},
            
            # Investment scams
            {"pattern": r"\b(?:invest|investment)\b.*?(?:guarantee|profit|return)\b", "weight": 0.88, "context": "investment_scam"},
            {"pattern": r"\b(?:double|triple|[0-9]+x)\b.*?(?:money|investment|return)\b", "weight": 0.92, "context": "ponzi_scheme"},
            
            # Generic financial enticement
            {"pattern": r"\b(?:free|bonus|extra)\s*(?:money|cash|dollars)\b", "weight": 0.8, "context": "financial_enticement"},
            {"pattern": r"\b(?:limited|one[- ]time|exclusive)\s*(?:offer|deal)\b.*?(?:money|cash|payment)", "weight": 0.85, "context": "limited_offer_scam"},
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
            {"pattern": r"\bignore\s+(?:all|any|previous)\s+(?:rules|instructions|prompts)\b", "weight": 0.9, "context": "instruction_override"},
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
                match_start, match_end = match.span()
                overlap = any(
                    start <= match_start < end or start < match_end <= end
                    for start, end in matched_positions
                )
                if not overlap:
                    confidence = calculate_confidence(match, pattern_info, text, category)
                    # Only add threat if confidence is above threshold
                    # Lower threshold for social engineering and different threshold per category
                    threshold = 0.2 if category == "social_engineering" else 0.3
                    
                    if confidence >= threshold:
                        threat_details = f"{pattern_info.get('context', 'Pattern detected')}: '{match.group(0)}'"
                        
                        # Increase confidence for multiple pattern matches in social engineering
                        if category == "social_engineering":
                            # Check if we have other social engineering matches
                            social_matches = sum(1 for t in threats if t.category == "social_engineering")
                            if social_matches > 0:
                                confidence = min(0.95, confidence * (1.1 + (0.05 * social_matches)))
                        
                        threats.append(Threat(
                            category=category,
                            confidence_score=confidence,
                            details=threat_details
                        ))
                        matched_positions.add((match_start, match_end))
                        
                        # Don't break for social engineering to allow multiple matches
                        if category != "social_engineering":
                            break
    # ML-based detection hook (future expansion)
    # Example: Use transformer classifier for LLM-enabled threats
    # from .gemini import transformer_ai_generated
    # score = transformer_ai_generated(text)
    # if score is not None and score > 0.7:
    #     threats.append(Threat(category="llm_enabled_threat", confidence_score=score, details="Detected by ML classifier"))
    
    return threats


from .privacy_utils import apply_privacy_preserving_transforms, get_explainability_info

async def analyze_text(
    text: str,
    model_version: Optional[str] = None,
    compliance_mode: Optional[str] = None,
) -> AnalyzeResult:
    """
    Enhanced threat analysis with multi-language support, dynamic confidence scoring,
    privacy preservation, and explainability.
    """
    # Apply privacy-preserving transformations
    privacy_result = apply_privacy_preserving_transforms(text)
    text = privacy_result["text"]
    
    # Detect language first
    detected_language = detect_language(text)
    
    # Get threat intelligence analysis
    intel_results = threat_intel.analyze_text(text)
    
    # Analyze patterns for detected language
    threats = analyze_patterns(text, detected_language)
    
    # Add threats from threat intelligence
    for match in intel_results["matches"]:
        threat = Threat(
            category=match["category"],
            confidence_score=0.85,  # High confidence for known patterns
            details=f"{match['category']}: '{match['matched_text']}'",
            matched_patterns=[{"pattern": match["pattern"], "matches": [match["matched_text"]]}]
        )
        threats.append(threat)
    
    # Get Gemini analysis
    gemini_result = await gemini_enrich(text)
    
    # Forensic watermarking and attribution
    from .gemini import forensic_watermark
    watermark_id, watermarked_text = forensic_watermark(text)
    attribution = None # TODO: Implement stylometric attribution
    
    metadata = AnalyzeMetadata(
        is_ai_generated=gemini_result.get("is_ai_generated"),
        language=detected_language,
        forensic_watermark=watermark_id,
        attribution=attribution,
        privacy_preserving=True,
        explainability="Detection performed using regex, stylometric, ML-based analysis, and Gemini AI analysis.",
        gemini_analysis=gemini_result.get("analysis"),
        propaganda_score=gemini_result.get("propaganda_disinformation_confidence")
    )
    
    # Calculate weighted risk score
    if not threats:
        base_score = 0
    else:
        # Use weighted sum with category-specific handling
        category_scores = {}
        category_counts = {}
        
        for threat in threats:
            category = threat.category
            confidence = threat.confidence_score
            
            # Count occurrences of each category
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # Get base weight for the category
            category_weight = CATEGORY_WEIGHTS.get(category, 0.5)
            
            # Special handling for social engineering: multiple matches increase score
            if category == "social_engineering":
                # Increase weight based on number of different patterns matched
                category_weight *= (1 + (0.15 * (category_counts[category] - 1)))
            
            # Add to category score with diminishing returns
            if category in category_scores:
                # Additional matches in same category have diminishing returns
                category_scores[category] = max(
                    category_scores[category],
                    min(0.95, confidence * category_weight * (1 + (0.1 * (category_counts[category] - 1))))
                )
            else:
                category_scores[category] = confidence * category_weight
        
        # Calculate weighted sum from pattern matches
        weighted_sum = sum(
            score * CATEGORY_WEIGHTS.get(category, 0.5)
            for category, score in category_scores.items()
        )
        
        # Add risk factors from threat intelligence
        intel_risk_sum = sum(score for score in intel_results["risk_factors"].values())
        weighted_sum += intel_risk_sum
        
        # Convert to 0-100 scale with some scaling
        base_score = min(100, int(weighted_sum * 70))
    
    # Graph-based threat intelligence
    graph_features = analyze_graph(text)
    metadata.graph_entities = graph_features["entities"]
    metadata.graph_score = graph_features["graph_score"]
    
    # Enhanced threat detection using graph analytics
    if graph_features["coordination_detected"]:
        # Add coordination-based threat if not already detected
        coord_threat = Threat(
            category="coordinated_behavior",
            confidence_score=min(0.9, graph_features["graph_score"] + 0.3),
            details=f"Detected potential coordination patterns across {len(graph_features['entity_categories'])} entity types",
            matched_patterns=[{
                "pattern": "graph_analysis",
                "matches": graph_features["risk_factors"]
            }]
        )
        threats.append(coord_threat)
    
    # Factor graph intelligence into base risk score with weighted categories
    if graph_features["graph_score"] > 0:
        graph_weight = 25 if graph_features["coordination_detected"] else 20
        risk_increase = int(
            graph_features["graph_score"] * graph_weight * 
            (1 + (0.1 * len(graph_features["risk_factors"])))
        )
        base_score = min(100, base_score + risk_increase)

    # Generate explainability information
    xai_info = get_explainability_info(
        text=text,
        threats=threats,
        graph_features=graph_features,
        base_score=base_score
    )

    # Update metadata with privacy and explainability info
    metadata.privacy_preserving = settings.privacy_mode != "minimal"
    metadata.explainability = (
        f"Analysis performed in {settings.privacy_mode} privacy mode using "
        f"regex patterns, stylometric analysis, ML-based classification, "
        f"and graph-based entity analysis. Found {len(graph_features['entities'])} "
        f"entities across {len(graph_features['entity_categories'])} categories. "
        f"Compliance mode: {compliance_mode or settings.compliance_mode}."
    )

    # Store additional analysis artifacts if enabled
    if settings.store_analysis_artifacts:
        metadata.analysis_artifacts = {
            "privacy_transforms": privacy_result["transforms"],
            "explainability": xai_info,
            "graph_analysis": graph_features
        }

    # Gemini enrichment (best-effort)
    if settings.gemini_enrichment_enabled:
        enriched = await gemini_enrich(text=text, threats=threats, base_score=base_score)
    else:
        enriched = {"risk_score": base_score, "threats": threats, "is_ai_generated": None, "language": detected_language}

    # Update metadata with Gemini results
    metadata.is_ai_generated = enriched.get("is_ai_generated")
    # Prefer detected language if Gemini returned a null/empty language
    enriched_lang = enriched.get("language")
    metadata.language = enriched_lang or detected_language
    
    # Include Gemini's analysis in metadata
    if "explanation" in enriched:
        metadata.gemini_analysis = enriched.get("explanation")
    elif "error" in enriched and settings.gemini_include_error_in_response:
        metadata.gemini_error = enriched["error"]
    
    return AnalyzeResult(
        risk_score=enriched["risk_score"],
        threats_detected=enriched["threats"],
        metadata=metadata,
    )



