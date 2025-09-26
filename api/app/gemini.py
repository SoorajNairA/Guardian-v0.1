from typing import List, Dict, Any
from .models import Threat
from .config import settings
import httpx


async def gemini_enrich(text: str, threats: List[Threat], base_score: int) -> Dict[str, Any]:
    # Fallback to heuristic-only if key missing
    if not settings.gemini_api_key:
        return {"risk_score": base_score, "threats": threats}

    try:
        prompt = (
            "You are a security classifier assistant. Given the input text, "
            "return JSON with fields: propaganda_disinformation_confidence (0-1), "
            "is_ai_generated (true/false), language (BCP-47 code). Keep it concise."
        )
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
                        {"text": f"TEXT:\n{text}"},
                    ]
                }
            ]
        }

        model = settings.gemini_model
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings.gemini_api_key}"
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        # naive parse: look for JSON blob in responseText
        response_text = ""
        try:
            candidates = data.get("candidates") or []
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    response_text = parts[0].get("text", "")
        except Exception:
            response_text = ""

        disinfo = 0.0
        is_ai = None
        lang = None
        if response_text:
            # Very conservative parse without external deps
            if "propaganda_disinformation_confidence" in response_text:
                try:
                    import re
                    m = re.search(r"propaganda_disinformation_confidence[^0-9]*([01]?(?:\.\d+)?)", response_text)
                    if m:
                        disinfo = float(m.group(1))
                except Exception:
                    pass
            if "is_ai_generated" in response_text:
                is_ai = "true" in response_text.lower()
            if "language" in response_text:
                try:
                    import re
                    m = re.search(r"language[^A-Za-z-]*([A-Za-z-]{2,})", response_text)
                    if m:
                        lang = m.group(1)
                except Exception:
                    pass

        # Adjust risk and threats
        adjusted_threats: List[Threat] = list(threats)
        if disinfo and disinfo > 0.5:
            adjusted_threats.append(Threat(category="propaganda_disinformation", confidence_score=float(disinfo), details="Gemini"))

        score = min(100, int(base_score + (disinfo * 20)))
        return {"risk_score": score, "threats": adjusted_threats, "is_ai_generated": is_ai, "language": lang}

    except Exception:
        return {"risk_score": base_score, "threats": threats}


