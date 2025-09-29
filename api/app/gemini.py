import asyncio
import json
import logging
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional

import httpx
from pydantic import ValidationError

from .config import settings
from .models import GeminiAnalysis, GeminiCandidate, GeminiContent, GeminiPart, GeminiResponse, Threat

# Configure structured logging
logger = logging.getLogger(__name__)

# In-memory cache with TTL
_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_TTL_SECONDS = 3600  # 1 hour


# Custom Exception Types
class GeminiAPIError(Exception):
    """Custom exception for Gemini API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class GeminiParsingError(Exception):
    """Custom exception for errors parsing Gemini API response."""


class GeminiTimeoutError(Exception):
    """Custom exception for Gemini API timeouts."""


def retry_with_backoff(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 10.0,
):
    """
    Decorator that retries a function with exponential backoff.
    """

    def decorator(func: Callable[..., Coroutine[Any, Any, Any]]):
        async def wrapper(*args, **kwargs):
            delay = base_delay
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except (GeminiAPIError, GeminiTimeoutError) as e:
                    if isinstance(e, GeminiAPIError) and e.status_code not in [
                        429,  # Rate limit
                        500,  # Internal server error
                        503,  # Service unavailable
                        504,  # Gateway timeout
                    ]:
                        raise  # Don't retry on non-transient client errors
                    logger.warning(
                        f"Attempt {attempt + 1}/{max_attempts} failed: {e}. Retrying in {delay:.2f}s..."
                    )
                    if attempt + 1 == max_attempts:
                        logger.error(f"All {max_attempts} retry attempts failed.")
                        raise  # Re-raise the last exception
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, max_delay)

        return wrapper

    return decorator


def _get_from_cache(key: str) -> Optional[Dict[str, Any]]:
    """Retrieves an item from the cache if it exists and has not expired."""
    if key not in _CACHE:
        return None
    
    entry = _CACHE[key]
    if time.time() - entry["timestamp"] > _CACHE_TTL_SECONDS:
        logger.info(f"Cache entry for key '{key[:50]}...' has expired.")
        del _CACHE[key]
        return None
    
    logger.info(f"Cache hit for key '{key[:50]}...'.")
    return entry["data"]

def _set_in_cache(key: str, data: Dict[str, Any]):
    """Sets an item in the cache with the current timestamp."""
    _CACHE[key] = {"timestamp": time.time(), "data": data}
    logger.info(f"Cached result for key '{key[:50]}...'.")

def detect_ai_generated_local(text: str) -> bool | None:
    """
    Fallback heuristic to detect AI-generated text.
    Looks for repetitive phrases, unnatural language, and excessive punctuation.
    """
    # Repetitive phrases (example: "as a large language model")
    if "as a large language model" in text.lower():
        return True
    # Unnatural sentence starters
    if text.strip().startswith(("In conclusion,", "In summary,", "Furthermore,")):
        return True
    # Excessive punctuation
    if text.count("!") > 5 or text.count("?") > 5:
        return True
    return None

def _parse_gemini_response(response_data: Dict[str, Any]) -> GeminiAnalysis:
    """
    Parses and validates the raw Gemini API response.
    """
    try:
        # Validate the main response structure
        gemini_response = GeminiResponse.model_validate(response_data)
        
        # Extract the text content from the first candidate
        if not gemini_response.candidates:
            raise GeminiParsingError("No candidates found in Gemini response.")
        
        response_text = gemini_response.candidates[0].content.parts[0].text
        
        # The response text itself is expected to be a JSON string
        # Clean the text to remove markdown code block fences
        cleaned_text = response_text.strip().removeprefix("```json").removesuffix("```").strip()

        # Parse the JSON content within the text
        parsed_json = json.loads(cleaned_text)
        
        # Validate the nested JSON against the GeminiAnalysis model
        analysis = GeminiAnalysis.model_validate(parsed_json)
        return analysis

    except (ValidationError, KeyError, IndexError, json.JSONDecodeError) as e:
        logger.error(f"Failed to parse or validate Gemini response: {e}")
        raise GeminiParsingError("Invalid response structure from Gemini API.") from e


@retry_with_backoff()
async def gemini_enrich(
    text: str, threats: List[Threat], base_score: int
) -> Dict[str, Any]:
    """
    Enriches analysis with Gemini, including robust error handling, retries, and fallbacks.
    """
    if not settings.gemini_api_key:
        logger.warning("Gemini API key not configured. Skipping enrichment.")
        return {
            "risk_score": base_score,
            "threats": threats,
            "is_ai_generated": detect_ai_generated_local(text),
            "language": None,
            "error": "Gemini API key not configured.",
        }

    # Check cache first
    cached_result = _get_from_cache(text)
    if cached_result:
        return cached_result

    prompt = (
        "You are a security classifier assistant. Given the input text, "
        "return a single minified JSON object with fields: "
        "propaganda_disinformation_confidence (float, 0.0-1.0), "
        "is_ai_generated (boolean), and language (string, BCP-47 code). "
        "Example: {\"propaganda_disinformation_confidence\":0.8,\"is_ai_generated\":true,\"language\":\"en-US\"}."
        "Ensure the output is only the JSON object, without any markdown formatting."
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}, {"text": f"TEXT:\n{text}"}]}]
    }
    model = settings.gemini_model
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings.gemini_api_key}"
    timeouts = httpx.Timeout(5.0, read=15.0)  # 5s connect, 15s read

    try:
        async with httpx.AsyncClient(timeout=timeouts) as client:
            logger.info(f"Sending request to Gemini API model {model} for text '{text[:50]}...'.")
            resp = await client.post(url, json=payload)
            logger.debug(f"Request payload: {payload}")
            
            if resp.status_code >= 300:
                logger.error(f"Gemini API request failed with status {resp.status_code}: {resp.text}")
            resp.raise_for_status()

            logger.info(f"Received response from Gemini API with status {resp.status_code}.")
            logger.debug(f"Response body: {resp.text}")
            
            data = resp.json()
            analysis = _parse_gemini_response(data)

        # Adjust risk and threats based on analysis
        adjusted_threats = list(threats)
        if analysis.propaganda_disinformation_confidence > 0.6:
            adjusted_threats.append(
                Threat(
                    category="propaganda_disinformation",
                    confidence_score=analysis.propaganda_disinformation_confidence,
                    details="Detected by Gemini analysis.",
                )
            )

        # Increase score based on confidence, with a cap
        score_increase = int(analysis.propaganda_disinformation_confidence * 25)
        score = min(100, base_score + score_increase)
        
        result = {
            "risk_score": score,
            "threats": adjusted_threats,
            "is_ai_generated": analysis.is_ai_generated,
            "language": analysis.language,
        }
        
        # Cache the successful result
        _set_in_cache(text, result)
        return result

    except httpx.TimeoutException as e:
        logger.error(f"Gemini API request timed out: {e}")
        raise GeminiTimeoutError("Request to Gemini API timed out.") from e
    except httpx.HTTPStatusError as e:
        raise GeminiAPIError(
            f"Gemini API error: {e.response.status_code}",
            status_code=e.response.status_code,
        ) from e
    except (GeminiParsingError, GeminiAPIError) as e:
        logger.error(f"Caught a specific Gemini error: {e}")
        raise  # Re-raise to be handled by the retry decorator or the final fallback
    except Exception as e:
        logger.error(f"An unexpected error occurred during Gemini enrichment: {e}", exc_info=True)
        # Graceful degradation: return base analysis with local fallback
        return {
            "risk_score": base_score,
            "threats": threats,
            "is_ai_generated": detect_ai_generated_local(text),
            "language": None,
            "error": "Gemini enrichment failed due to an unexpected error.",
        }
