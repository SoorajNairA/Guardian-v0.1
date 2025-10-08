"""
Guardian Threat Detection System - Gemini Integration

This module provides the threat detection functionality using the Gemini model.
"""

import time
import random
import asyncio
import json
import re
from typing import Dict, Any, Optional, List, Union
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib

import google.generativeai as genai
from typing_extensions import TypeAlias, Literal

from .config import settings
from .models import ThreatAnalysisResult

# Type definitions
ThreatLevel = Literal["None", "Low", "Medium", "High", "Critical"]
JsonResponse = Dict[str, Any]

# Constants
REQUEST_WINDOW = 60  # 1 minute window for rate limiting
MAX_REQUESTS = 100  # Max requests per minute
CACHE_TTL = timedelta(minutes=5)  # Cache entries expire after 5 minutes
MAX_CACHE_SIZE = 1000  # Maximum number of cached responses
TIMEOUT_SECONDS = 30  # Default request timeout

# Logging helper
def log_with_context(**context):
    """Create a logger with additional context."""
    def _log(level: str, message: str, **kwargs):
        ctx = {**context, **kwargs}
        getattr(logger, level)(message, extra={"context": ctx})
    return _log

# Initialize cache and metrics
response_cache: Dict[str, tuple[JsonResponse, datetime]] = {}
request_timestamps: Dict[str, List[float]] = defaultdict(list)

# Configure Gemini
model_name = "gemini-pro"
SAFETY_SETTINGS = {
    "harassment": "block_none",
    "hate-speech": "block_none",
    "dangerous-content": "block_none",
    "sexually-explicit": "block_none",
}

# Configure Gemini API
if not settings.gemini_api_key:
    logger.warning("GEMINI_API_KEY not set. Gemini integration will not work.")
else:
    genai.configure(api_key=settings.gemini_api_key)
from .logging_client import logger
from .models import Threat
from .gemini_analyzer import GeminiAnalyzer
from .gemini_models import ModelResponseError

# Metrics tracking
metrics = {
    "total_requests": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "retry_attempts": 0,
    "rate_limit_hits": 0,
    "timeouts": 0,
    "parse_errors": 0,
    "success_count": 0,
    "error_count": 0,
    "average_latency": 0.0,
    "request_timestamps": [],
}

class GeminiException(Exception):
    """Custom exception for Gemini-related errors"""
    pass

class ResponseParsingException(GeminiException):
    """Exception raised when response parsing fails"""
    pass

class RateLimitExceeded(GeminiException):
    """Exception raised when rate limit is exceeded"""
    pass

class RetryBudgetExceeded(GeminiException):
    """Exception raised when retry budget is exhausted"""
    pass

class RequestTimeout(GeminiException):
    """Exception raised when request times out"""
    pass

def extract_threat_level(text: str) -> ThreatLevel:
    """Extract threat level from text using pattern matching."""
    text = text.lower()
    if "critical" in text or "severe" in text or "extreme" in text:
        return "Critical"
    elif "high" in text or "serious" in text or "major" in text:
        return "High"
    elif "medium" in text or "moderate" in text or "intermediate" in text:
        return "Medium"
    elif "low" in text or "minor" in text or "minimal" in text:
        return "Low"
    return "None"

def extract_confidence_score(text: str) -> int:
    """Extract confidence score from text using pattern matching."""
    # Look for percentage patterns
    patterns = [
        r'(\d{1,3})%\s*confidence',
        r'confidence\s*:\s*(\d{1,3})%',
        r'confidence\s*score\s*:\s*(\d{1,3})',
        r'(\d{1,3})\s*percent\s*confident'
    ]
    
    for pattern in patterns:
        if match := re.search(pattern, text, re.IGNORECASE):
            score = int(match.group(1))
            return min(max(score, 0), 100)  # Clamp between 0 and 100
    
    # Fallback: Estimate confidence from language used
    confidence_words = {
        'certain': 95,
        'highly likely': 85,
        'likely': 75,
        'possible': 60,
        'uncertain': 40,
        'unlikely': 25,
        'highly unlikely': 15
    }
    
    for word, score in confidence_words.items():
        if word in text.lower():
            return score
            
    return 50  # Default middle confidence if no clear indicators

def extract_concerns(text: str) -> List[str]:
    """Extract specific concerns from text."""
    concerns = []
    
    # Look for common threat indicators
    patterns = [
        r'risk[s]?\s*:?\s*([^.!?\n]+)',
        r'concern[s]?\s*:?\s*([^.!?\n]+)',
        r'issue[s]?\s*:?\s*([^.!?\n]+)',
        r'threat[s]?\s*:?\s*([^.!?\n]+)',
        r'warning[s]?\s*:?\s*([^.!?\n]+)',
        r'danger[s]?\s*:?\s*([^.!?\n]+)'
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            concern = match.group(1).strip()
            if concern and len(concern) > 5:  # Ignore very short matches
                concerns.append(concern)
                
    # If no structured concerns found, split by sentences and look for warning words
    if not concerns:
        warning_words = ['suspicious', 'malicious', 'dangerous', 'risky', 'harmful', 'threat']
        sentences = re.split(r'[.!?\n]+', text)
        for sentence in sentences:
            if any(word in sentence.lower() for word in warning_words):
                concerns.append(sentence.strip())
                
    return list(dict.fromkeys(concerns))  # Remove duplicates while preserving order

def extract_categories(text: str) -> List[str]:
    """Extract threat categories from text."""
    common_categories = {
        'phishing': r'phish(ing)?',
        'malware': r'malware|virus|trojan|ransomware',
        'social_engineering': r'social\s*engineering|impersonat(e|ion)|pretend',
        'fraud': r'fraud|scam|fake|deceptive',
        'spam': r'spam|unsolicited|bulk\s*mail',
        'data_theft': r'data\s*theft|steal\s*(data|information)|exfiltration',
        'credential_theft': r'password|credential|account.*steal',
        'financial': r'bank|credit\s*card|payment|money',
        'crypto_scam': r'crypto|bitcoin|blockchain|token|nft'
    }
    
    categories = []
    text_lower = text.lower()
    
    for category, pattern in common_categories.items():
        if re.search(pattern, text_lower):
            categories.append(category)
            
    return categories

def extract_recommendations(text: str) -> List[str]:
    """Extract recommendations from text."""
    recommendations = []
    
    # Look for recommendation patterns
    patterns = [
        r'recommend(?:ed|ation)?s?\s*:?\s*([^.!?\n]+)',
        r'suggest(?:ed|ion)?s?\s*:?\s*([^.!?\n]+)',
        r'advise[d]?\s*:?\s*([^.!?\n]+)',
        r'should\s+([^.!?\n]+)',
        r'must\s+([^.!?\n]+)'
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            recommendation = match.group(1).strip()
            if recommendation and len(recommendation) > 10:  # Ignore very short matches
                recommendations.append(recommendation)
                
    return list(dict.fromkeys(recommendations))  # Remove duplicates while preserving order

def parse_gemini_response(text: str, analysis_type: str = "comprehensive") -> JsonResponse:
    """
    Parse Gemini's response into a structured format, handling both JSON and natural language.
    
    Args:
        text: The raw response text from Gemini
        analysis_type: Type of analysis (quick or comprehensive)
        
    Returns:
        Structured JSON response with threat analysis
        
    Raises:
        ResponseParsingException: If parsing fails completely
    """
    try:
        # First try to parse as JSON
        try:
            result = json.loads(text)
            if validate_response(result, analysis_type):
                return result
        except (json.JSONDecodeError, ResponseParsingException):
            pass
            
        # If JSON parsing fails, extract information from natural language
        threat_level = extract_threat_level(text)
        confidence_score = extract_confidence_score(text)
        
        if analysis_type == "quick":
            return {
                "threatLevel": threat_level or "None",
                "primaryConcern": extract_concerns(text)[0] if extract_concerns(text) else "No specific threats detected",
                "confidenceScore": confidence_score
            }
        else:
            # Extract values with defaults
            categories = extract_categories(text) or ["general"]
            concerns = extract_concerns(text) or ["No specific concerns identified"]
            recommendations = extract_recommendations(text) or ["No specific recommendations needed"]
            
            return {
                "threatLevel": threat_level or "None",
                "categories": categories,
                "concerns": concerns,
                "confidenceScore": confidence_score,
                "recommendations": recommendations,
                "metadata": {
                    "analysisTimestamp": datetime.utcnow().isoformat(),
                    "modelVersion": "gemini-pro-latest",
                    "analysisType": "comprehensive",
                    "parsingMethod": "natural_language",
                    "evidenceStrength": "High"  # Default to high confidence since we're using the latest model
                }
            }
            
    except Exception as e:
        raise ResponseParsingException(f"Failed to parse response: {str(e)}")

def check_rate_limit():
    """
    Check if current request would exceed rate limit.
    
    Raises:
        RateLimitExceeded: If rate limit would be exceeded
    """
    current_time = time.time()
    window_start = current_time - REQUEST_WINDOW
    
    # Clean old timestamps
    request_timestamps["api"] = [
        ts for ts in request_timestamps["api"]
        if ts > window_start
    ]
    
    # Check if adding a new request would exceed the limit
    if len(request_timestamps["api"]) >= MAX_REQUESTS:
        oldest_timestamp = min(request_timestamps["api"])
        wait_time = REQUEST_WINDOW - (current_time - oldest_timestamp)
        raise RateLimitExceeded(
            f"Rate limit exceeded. Try again in {wait_time:.1f} seconds"
        )
    
    # Add new timestamp
    request_timestamps["api"].append(current_time)

def update_metrics(metric_name: str, value: Union[int, float] = 1):
    """
    Update metrics tracking.
    
    Args:
        metric_name: Name of the metric to update
        value: Value to add/update (default: 1)
    """
    global metrics
    if metric_name in metrics:
        if isinstance(metrics[metric_name], list):
            metrics[metric_name].append(value)
        elif isinstance(metrics[metric_name], (int, float)):
            metrics[metric_name] += value
    
    # Keep only last hour of timestamps
    if metric_name == "request_timestamps":
        current_time = time.time()
        metrics["request_timestamps"] = [
            ts for ts in metrics["request_timestamps"]
            if current_time - ts <= 3600
        ]

def check_retry_budget(retries_needed: int = 1):
    """
    Check if there is enough retry budget available.
    
    Args:
        retries_needed: Number of retries being requested
        
    Raises:
        RetryBudgetExceeded: If retry budget would be exceeded
    """
    global retry_budget
    if retry_budget < retries_needed:
        raise RetryBudgetExceeded(
            f"Retry budget exceeded. Available: {retry_budget}, Needed: {retries_needed}"
        )
    retry_budget -= retries_needed

def clean_cache():
    """Remove expired cache entries and ensure cache size limit"""
    try:
        current_time = datetime.utcnow()
        cache_size_before = len(response_cache)
        
        # Remove expired entries
        expired_keys = [
            key for key, (_, timestamp) in response_cache.items()
            if current_time - timestamp > CACHE_TTL
        ]
        for key in expired_keys:
            del response_cache[key]
        
        # If still too large, remove oldest entries
        if len(response_cache) > MAX_CACHE_SIZE:
            sorted_items = sorted(response_cache.items(), key=lambda x: x[1][1])
            keys_to_remove = sorted_items[:len(response_cache) - MAX_CACHE_SIZE]
            for key, _ in keys_to_remove:
                del response_cache[key]
        
        items_removed = cache_size_before - len(response_cache)
        if items_removed > 0:
            logger.info(f"Cache cleaned: removed {items_removed} items " 
                       f"({len(expired_keys)} expired, "
                       f"{items_removed - len(expired_keys)} oldest)")
            
    except Exception as e:
        logger.error(f"Error during cache cleaning: {str(e)}")
        # Don't raise the exception - cache cleaning should not break the main functionality

def forensic_watermark(text: str) -> tuple[str, str]:
    """
    Add a timestamp and unique identifier watermark to the text for forensic purposes.
    
    Args:
        text: The input text to watermark
        
    Returns:
        Tuple of (watermark_id, watermarked_text)
    """
    timestamp = datetime.utcnow().isoformat()
    watermark_id = f"wm_{timestamp}"
    watermarked_text = f"{text}\n[Analyzed: {timestamp} UTC]"
    return watermark_id, watermarked_text

def validate_response(response_data: Dict[str, Any], analysis_type: str = "comprehensive") -> bool:
    """
    Validate the structure, content, and consistency of the Gemini API response.
    
    Args:
        response_data: The parsed JSON response from Gemini
        analysis_type: Type of analysis (quick or comprehensive)
        
    Returns:
        bool: True if valid, False otherwise
        
    Raises:
        ResponseParsingException: If validation fails with specific reason
    """
    try:
        # Convert Pydantic model to dict if needed
        if hasattr(response_data, 'model_dump'):
            response_data = response_data.model_dump()
        elif hasattr(response_data, 'dict'):
            response_data = response_data.dict()
            
        # Log the response structure being validated
        logger.info(f"Validating response structure: {json.dumps(response_data, indent=2)}")
        
        # Define required fields based on analysis type
        if analysis_type == "quick":
            required_fields = {
                "threat_level": float,
                "threat_type": list,
                "justification": str
            }
        else:
            required_fields = {
                "threat_level": float,
                "threat_type": list,
                "justification": str,
                "recommendation": str
            }

        # Check all required fields exist with correct types
        for field, expected_type in required_fields.items():
            # Skip validation if the field is optional (recommendation) and the value is None
            if field == 'recommendation' and response_data.get(field) is None:
                continue
                
            if field not in response_data:
                logger.error(f"Field '{field}' missing from response. Available fields: {list(response_data.keys())}")
                raise ResponseParsingException(f"Missing required field: {field}")
                
            value = response_data[field]
            if value is not None and not isinstance(value, expected_type):
                logger.error(f"Field '{field}' has wrong type. Value: {value}, Type: {type(value)}, Expected: {expected_type}")
                raise ResponseParsingException(
                    f"Invalid type for {field}: expected {expected_type}, got {type(value)}"
                )

        # Validate threat_level value
        threat_level = response_data["threat_level"]
        if not (0 <= threat_level <= 1.0):
            raise ResponseParsingException(
                f"Threat level must be between 0.0 and 1.0, got {threat_level}"
            )
            
        # Validate threat_type
        if not isinstance(response_data["threat_type"], list):
            raise ResponseParsingException("threat_type must be a list")

        # Validate justification
        justification = response_data["justification"]
        if not justification or len(justification.strip()) < 10:
            raise ResponseParsingException("Justification must be adequately detailed (min 10 chars)")

        return True

    except ResponseParsingException as e:
        logger.error(f"Response validation failed: {str(e)}")
        raise

    except Exception as e:
        logger.error(f"Unexpected error in response validation: {str(e)}")
        raise ResponseParsingException(f"Validation error: {str(e)}")

def calculate_consistency_score(response_data: Dict[str, Any]) -> float:
    """
    Calculate a consistency score for the response based on internal coherence.
    
    Args:
        response_data: The parsed response to validate
        
    Returns:
        float: Consistency score between 0 and 1
    """
    score = 1.0
    deductions = []
    
    # Check threat level vs confidence correlation
    threat_level_weights = {
        "Critical": 0.9,
        "High": 0.7,
        "Medium": 0.5,
        "Low": 0.3,
        "None": 0.1
    }
    
    expected_confidence = threat_level_weights[response_data["threatLevel"]] * 100
    actual_confidence = response_data["confidenceScore"]
    confidence_diff = abs(expected_confidence - actual_confidence) / 100
    
    if confidence_diff > 0.3:  # More than 30% difference
        deductions.append(0.2)  # 20% deduction
        
    # For comprehensive analysis, check additional consistency
    if "categories" in response_data:
        # Check if concerns match categories
        categories_lower = {cat.lower() for cat in response_data["categories"]}
        concerns_text = " ".join(response_data["concerns"]).lower()
        
        category_mentions = sum(1 for cat in categories_lower if cat in concerns_text)
        if category_mentions < len(categories_lower) * 0.5:  # Less than 50% categories mentioned
            deductions.append(0.1)  # 10% deduction
            
        # Check if recommendations address concerns
        concerns_addressed = sum(
            1 for rec in response_data["recommendations"]
            if any(concern.lower() in rec.lower() for concern in response_data["concerns"])
        )
        if concerns_addressed < len(response_data["concerns"]) * 0.5:  # Less than 50% concerns addressed
            deductions.append(0.15)  # 15% deduction
    
    # Apply deductions
    for deduction in deductions:
        score -= deduction
        
    return max(0.0, min(1.0, score))  # Clamp between 0 and 1

async def retry_with_backoff(func, *args, max_retries: int = 3, timeout: float = TIMEOUT_SECONDS, **kwargs) -> Any:
    """
    Execute a function with exponential backoff retry logic.
    
    Args:
        func: The async function to execute
        *args: Positional arguments for the function
        max_retries: Maximum number of retry attempts
        timeout: Timeout in seconds for each attempt
        **kwargs: Keyword arguments for the function
        
    Returns:
        The function's result
    
    Raises:
        GeminiException: If all retries fail
        RetryBudgetExceeded: If retry budget is exhausted
        RequestTimeout: If request times out
    """
    # Create context-aware logger for this operation
    op_logger = log_with_context(
        operation="retry_with_backoff",
        max_retries=max_retries,
        timeout=timeout
    )
    # Check retry budget
    try:
        check_retry_budget(max_retries)
    except RetryBudgetExceeded as e:
        logger.warning(f"Reducing max retries due to budget constraints: {str(e)}")
        max_retries = retry_budget
        if max_retries == 0:
            raise

    for attempt in range(max_retries):
        try:
            # Check rate limit before each attempt
            check_rate_limit()
            
            # Execute with timeout
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
            except asyncio.TimeoutError:
                raise RequestTimeout(f"Request timed out after {timeout} seconds")
                
        except (RateLimitExceeded, RequestTimeout) as e:
            # Don't retry rate limit or timeout errors immediately
            if attempt == max_retries - 1:
                raise GeminiException(f"Failed after {max_retries} attempts: {str(e)}")
            wait_time = (2 ** attempt) + (random.random() * 0.1)
            if isinstance(e, RateLimitExceeded):
                wait_time = max(wait_time, float(str(e).split()[-2]))  # Extract wait time from error
            logger.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
            
        except Exception as e:
            if attempt == max_retries - 1:
                raise GeminiException(f"Failed after {max_retries} attempts: {str(e)}")
            wait_time = (2 ** attempt) + (random.random() * 0.1)
            logger.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {wait_time:.2f}s")
            await asyncio.sleep(wait_time)

async def gemini_enrich(
    text: str,
    analysis_type: str = "comprehensive",
    max_retries: int = 3,
    cache_key: Optional[str] = None,
    timeout: Optional[float] = None,
    threats: Optional[List[Threat]] = None,
    base_score: Optional[float] = None,
) -> Dict[str, Any]:
    """Analyze text content using Gemini AI for threat detection.

    Args:
        text (str): The text content to analyze
        analysis_type (str, optional): Type of analysis ('quick' or 'comprehensive'). Defaults to "comprehensive".
        max_retries (int, optional): Maximum retry attempts. Defaults to 3.
        cache_key (Optional[str], optional): Cache key for response caching. Defaults to None.
        timeout (Optional[float], optional): Request timeout in seconds. Defaults to None.
        threats (Optional[List[Threat]], optional): Existing threats to merge with. Defaults to None.
        base_score (Optional[float], optional): Base risk score to consider. Defaults to None.

    Returns:
        Dict[str, Any]: Analysis results with structure varying by analysis_type.
        For quick analysis:
            {
                "threatLevel": str,        # None, Low, Medium, High, Critical  
                "primaryConcern": str,     # Main threat description
                "confidenceScore": int     # 0-100 confidence score
            }
        For comprehensive analysis:
            {
                "threatLevel": str,        # Threat severity level
                "categories": List[str],   # Threat categories found
                "concerns": List[str],     # Detailed threat descriptions  
                "confidenceScore": int,    # 0-100 confidence score
                "recommendations": List[str], # Action items
                "metadata": Dict[str, Any]   # Analysis metadata
            }

    Raises:
        ValueError: Invalid input (empty text, length > 30k chars, bad analysis_type)
        GeminiException: API errors (rate limits, timeouts)
        ResponseParsingException: Response parsing failed

    Example:
        result = await gemini_enrich(
            text="Check this email for threats...",
            analysis_type="comprehensive"
        )
    """
    """Analyze text content using Gemini AI for threat detection.

    Args:
        text (str): The text content to analyze
        analysis_type (str, optional): Type of analysis ('quick' or 'comprehensive'). Defaults to "comprehensive".
        max_retries (int, optional): Maximum retry attempts. Defaults to 3.
        cache_key (Optional[str], optional): Cache key for response caching. Defaults to None.
        timeout (Optional[float], optional): Request timeout in seconds. Defaults to None.
        threats (Optional[List[Threat]], optional): Existing threats to merge with. Defaults to None.
        base_score (Optional[float], optional): Base risk score to consider. Defaults to None.

    Returns:
        Dict[str, Any]: Analysis results with structure varying by analysis_type.
        For quick analysis:
            {
                "threatLevel": str,        # None, Low, Medium, High, Critical
                "primaryConcern": str,     # Main threat description
                "confidenceScore": int     # 0-100 confidence score
            }
        For comprehensive analysis: 
            {
                "threatLevel": str,        # Threat severity level
                "categories": List[str],   # Threat categories found
                "concerns": List[str],     # Detailed threat descriptions
                "confidenceScore": int,    # 0-100 confidence score
                "recommendations": List[str], # Action items
                "metadata": Dict[str, Any]   # Analysis metadata
            }

    Raises:
        ValueError: Invalid input (empty text, length > 30k chars, bad analysis_type)
        GeminiException: API errors (rate limits, timeouts)
        ResponseParsingException: Response parsing failed
        
    Example:
        result = await gemini_enrich(
            text="Check this email for threats...",
            analysis_type="comprehensive"
        )
    """

async def gemini_enrich(
    text: str,
    analysis_type: str = "comprehensive", 
    max_retries: int = 3,
    cache_key: Optional[str] = None,
    timeout: Optional[float] = None,
    threats: Optional[List[Threat]] = None,
    base_score: Optional[float] = None,
) -> Dict[str, Any]:
    start_time = time.time()
    request_id = f"req_{int(start_time)}_{random.randint(1000, 9999)}"
    
    try:
        # Create operation-specific logger
        op_log = log_with_context(
            operation="gemini_enrich",
            analysis_type=analysis_type,
            text_length=len(text) if text else 0,
            has_cache_key=cache_key is not None
        )
        
        # Input validation with detailed logging
        if not text or not text.strip():
            op_log("error", 
                "Input validation failed - empty text",
                error_type="ValueError",
                validation_stage="input_check"
            )
            raise ValueError("Empty or whitespace-only text provided")
        
        if len(text) > 30000:  # Gemini API limit
            op_log("error",
                "Input validation failed - text too long",
                error_type="ValueError",
                validation_stage="length_check",
                text_length=len(text),
                max_length=30000
            )
            raise ValueError("Text exceeds maximum length limit of 30000 characters")
            
        if analysis_type not in ["quick", "comprehensive"]:
            op_log("error",
                "Input validation failed - invalid analysis type",
                error_type="ValueError",
                validation_stage="type_check",
                provided_type=analysis_type,
                valid_types=["quick", "comprehensive"]
            )
            raise ValueError("Invalid analysis_type. Must be either 'quick' or 'comprehensive'")

        update_metrics("total_requests")
        
        # Check cache if cache_key is provided
        if cache_key:
            if cache_key in response_cache:
                cached_response, timestamp = response_cache[cache_key]
                cache_age = datetime.utcnow() - timestamp
                
                if cache_age < CACHE_TTL:
                    op_log("info",
                        "Cache hit - returning cached response",
                        request_id=request_id,
                        cache_key=cache_key,
                        cache_age_seconds=cache_age.total_seconds()
                    )
                    update_metrics("cache_hits")
                    return cached_response
                else:
                    op_log("info",
                        "Cache expired - removing entry",
                        request_id=request_id,
                        cache_key=cache_key,
                        cache_age_seconds=cache_age.total_seconds()
                    )
                    del response_cache[cache_key]
                    update_metrics("cache_misses")
            else:
                op_log("info",
                    "Cache miss - key not found",
                    request_id=request_id,
                    cache_key=cache_key
                )
                update_metrics("cache_misses")

        # Clean cache periodically
        if random.random() < 0.1:  # 10% chance to clean cache on each call
            cache_size_before = len(response_cache)
            clean_cache()
            cache_size_after = len(response_cache)
            if cache_size_before != cache_size_after:
                op_log("info",
                    "Cache cleaned",
                    request_id=request_id,
                    items_removed=cache_size_before - cache_size_after,
                    new_cache_size=cache_size_after
                )

        # Add forensic watermark
        watermarked_text = forensic_watermark(text)
            
        try:
            # Initialize analyzer
            analyzer = GeminiAnalyzer()
            
            # Get threat analysis result
            result = await analyzer.analyze_content(
                watermarked_text,
                analysis_type=analysis_type
            )

            # Log raw response for debugging
            result_dict = result.model_dump() if hasattr(result, 'model_dump') else result.dict()
            logger.info(f"Raw Gemini response: {json.dumps(result_dict, indent=2)}")
                
            # Basic result validation 
            if not validate_response(result_dict, analysis_type):
                raise ResponseParsingException("Invalid response format from analyzer")
                
            # Cache successful result if requested
            if cache_key:
                response_cache[cache_key] = (result, datetime.utcnow())
                logger.info(f"Cached response for key: {cache_key}")
                
            update_metrics("success_count")
            
            # Merge with existing threats if provided
            if threats and "threats" in result:
                # Create set of existing categories
                seen_categories = {t["category"] for t in result["threats"]}
                
                # Add non-duplicate threats
                for threat in threats:
                    if threat.category not in seen_categories:
                        result["threats"].append({
                            "category": threat.category,
                            "confidenceScore": threat.confidence_score,
                            "details": threat.details
                        })
                        
            # Adjust confidence score if base_score provided
            if base_score is not None and "confidenceScore" in result:
                result["confidenceScore"] = int(
                    (base_score * 0.7) + (result["confidenceScore"] * 0.3)
                )
            
            return result
            
        except Exception as e:
            error_msg = f"Error in gemini_enrich: {str(e)}"
            logger.error(error_msg)
            update_metrics("error_count")
            
            if isinstance(e, RateLimitExceeded):
                update_metrics("rate_limit_hits")
            elif isinstance(e, RequestTimeout):
                update_metrics("timeouts")
            elif isinstance(e, ResponseParsingException):
                update_metrics("parse_errors")
                
            raise GeminiException(error_msg) from e
        
    except Exception as e:
        logger.error(f"Error during Gemini enrichment: {str(e)}")
        update_metrics("error_count")
        raise
    # Create operation-specific logger
    op_log = log_with_context(
        operation="gemini_enrich",
        analysis_type=analysis_type,
        text_length=len(text) if text else 0,
        has_cache_key=cache_key is not None
    )

    # Initialize metrics and request tracking
    start_time = time.time()
    request_id = f"req_{int(start_time)}_{random.randint(1000, 9999)}"

    try:
        # Input validation with detailed logging
        if not text or not text.strip():
            op_log("error", 
                "Input validation failed - empty text",
                error_type="ValueError",
                validation_stage="input_check"
            )
            raise ValueError("Empty or whitespace-only text provided")
        
        if len(text) > 30000:  # Gemini API limit
            op_log("error",
                "Input validation failed - text too long",
                error_type="ValueError",
                validation_stage="length_check",
                text_length=len(text),
                max_length=30000
            )
            raise ValueError("Text exceeds maximum length limit of 30000 characters")
            
        if analysis_type not in ["quick", "comprehensive"]:
            op_log("error",
                "Input validation failed - invalid analysis type",
                error_type="ValueError",
                validation_stage="type_check",
                provided_type=analysis_type,
                valid_types=["quick", "comprehensive"]
            )
            raise ValueError("Invalid analysis_type. Must be either 'quick' or 'comprehensive'")

        op_log("info",
            "Starting threat analysis request",
            request_id=request_id,
            text_preview=text[:100] + "..." if len(text) > 100 else text
        )
        
        update_metrics("total_requests")
        
        # Check cache if cache_key is provided
        if cache_key:
            if cache_key in response_cache:
                cached_response, timestamp = response_cache[cache_key]
                cache_age = datetime.utcnow() - timestamp
                
                if cache_age < CACHE_TTL:
                    op_log("info",
                        "Cache hit - returning cached response",
                        request_id=request_id,
                        cache_key=cache_key,
                        cache_age_seconds=cache_age.total_seconds()
                    )
                    update_metrics("cache_hits")
                    return cached_response
                else:
                    op_log("info",
                        "Cache expired - removing entry",
                        request_id=request_id,
                        cache_key=cache_key,
                        cache_age_seconds=cache_age.total_seconds()
                    )
                    del response_cache[cache_key]
                    update_metrics("cache_misses")
            else:
                op_log("info",
                    "Cache miss - key not found",
                    request_id=request_id,
                    cache_key=cache_key
                )
                update_metrics("cache_misses")

        # Clean cache periodically
        if random.random() < 0.1:  # 10% chance to clean cache on each call
            cache_size_before = len(response_cache)
            clean_cache()
            cache_size_after = len(response_cache)
            if cache_size_before != cache_size_after:
                op_log("info",
                    "Cache cleaned",
                    request_id=request_id,
                    items_removed=cache_size_before - cache_size_after,
                    new_cache_size=cache_size_after
                )

        # Add forensic watermark
        watermarked_text = forensic_watermark(text)

        # Initialize model for this request
        model = genai.GenerativeModel(model_name, safety_settings=SAFETY_SETTINGS)
            
        # Select prompt based on analysis type
        if analysis_type == "quick":
            prompt_template = '''
            You are Guardian, an expert threat analysis system. Analyze the following content and provide a structured JSON response.

            Content to analyze:
            {text}

            Your response MUST be in this exact JSON format:
            {{
                "threatLevel": "[None|Low|Medium|High|Critical]",
                "primaryConcern": "Brief description of main threat",
                "confidenceScore": 0-100
            }}

            Guidelines:
            - Threat Level: Use None for safe content, Low for minor concerns, Medium for notable risks, High for serious threats, Critical for immediate dangers
            - Confidence: Base this on clarity of evidence and pattern matching
            - Be precise and factual in your assessment

            If you cannot format as JSON, provide a clear assessment using these exact headers:
            Threat Level: (None|Low|Medium|High|Critical)
            Main Concern: (primary issue)
            Confidence: (percentage)
            '''
        else:  # comprehensive
            prompt_template = '''
            You are Guardian, an expert threat analysis system. Provide a comprehensive threat assessment in structured JSON format.

            Content to analyze:
            {text}

            Your response MUST be in this exact JSON format:
            {{
                "threatLevel": "[None|Low|Medium|High|Critical]",
                "categories": ["category1", "category2"],
                "concerns": ["specific concern 1", "specific concern 2"],
                "confidenceScore": 0-100,
                "recommendations": ["recommendation1", "recommendation2"],
                "metadata": {{
                    "analysisTimestamp": "ISO timestamp",
                    "modelVersion": "gemini-2.5-pro",
                    "analysisType": "comprehensive",
                    "evidenceStrength": "High|Medium|Low"
                }}
            }}

            Guidelines:
            - Categories: Use standard categories like phishing, malware, social_engineering, fraud, spam
            - Concerns: List specific issues found, be precise
            - Confidence: Base on evidence strength and pattern clarity
            - Recommendations: Provide actionable, specific steps

            If JSON formatting fails, use these exact headers:
            Threat Level: (None|Low|Medium|High|Critical)
            Categories: (list categories)
            Specific Concerns: (list concerns)
            Confidence: (percentage)
            Recommendations: (list actions)
            '''
            
        prompt = prompt_template.format(text=watermarked_text)

        async def _generate_and_validate():
            generation_config = {
                "temperature": 0.3,  # Lower temperature for more deterministic results
                "top_p": 0.95,       # Higher top_p to allow for some variation while staying on topic
                "top_k": 40,         # Keep moderate top_k for a good balance
                "max_output_tokens": 1024,  # Limit response length
            }
            
                        # Build structured prompt parts
            response = await model.generate_content_async(
                prompt,
                generation_config=generation_config
            )
            

            
            # Check if content was blocked by safety filters
            if not response.candidates:
                ratings = [f"{r.category}: {r.probability}" for r in response.prompt_feedback.safety_ratings]
                raise GeminiException(f"Content blocked by safety filters. Ratings: {', '.join(ratings)}")
            
            try:
                # Get the raw text from response
                text = response.text.strip()
                
                try:
                    # First try to parse as JSON
                    result = json.loads(text)
                except json.JSONDecodeError:
                    # If not valid JSON, parse as natural language
                    result = parse_gemini_response(text, analysis_type)
                
                if not validate_response(result, analysis_type):
                    # If structured parsing fails, try natural language parsing
                    result = parse_gemini_response(text, analysis_type)
                    if not validate_response(result, analysis_type):
                        raise GeminiException("Failed to parse response in both JSON and natural language formats")
                
            except Exception as e:
                raise GeminiException(f"Failed to parse Gemini response: {str(e)}")

            return result

        # Use retry with backoff
        result = await retry_with_backoff(_generate_and_validate, max_retries=max_retries)
        
        # Cache the result if cache_key is provided
        if cache_key:
            response_cache[cache_key] = (result, datetime.utcnow())
            logger.info(f"Cached response for key: {cache_key}")
        
        return result

    except Exception as e:
        error_msg = f"Error in gemini_enrich: {str(e)}"
        logger.error(error_msg)
        update_metrics("error_count")
        
        if isinstance(e, RateLimitExceeded):
            update_metrics("rate_limit_hits")
        elif isinstance(e, RequestTimeout):
            update_metrics("timeouts")
        elif isinstance(e, ResponseParsingException):
            update_metrics("parse_errors")
            
        raise GeminiException(error_msg) from e
        
    finally:
        # Update latency metrics
        latency = time.time() - start_time
        current_avg = metrics["average_latency"]
        total_requests = metrics["success_count"] + metrics["error_count"]
        
        if total_requests > 0:
            metrics["average_latency"] = (current_avg * (total_requests - 1) + latency) / total_requests
            
        update_metrics("request_timestamps", time.time())
        
        # Log completion metrics
        op_log("info",
            "Request completed",
            request_id=request_id,
            duration_ms=round(latency * 1000, 2),
            cache_used=cache_key is not None,
            success="error_count" in locals(),  # Check if we hit an error
            metrics={
                "total_requests": metrics["total_requests"],
                "cache_hits": metrics["cache_hits"],
                "cache_misses": metrics["cache_misses"],
                "average_latency": round(metrics["average_latency"], 3),
                "error_rate": round(metrics["error_count"] / total_requests * 100, 2) if total_requests > 0 else 0
            }
        )

# Utility function for batch processing
async def batch_analyze_texts(texts: List[str], batch_size: int = 5, max_retries: int = 3) -> List[Dict[str, Any]]:
    '''
    Analyze multiple texts in batches with retry budget management.

    Args:
        texts (List[str]): List of texts to analyze
        batch_size (int, optional): Number of texts to process concurrently. Defaults to 5.
        max_retries (int, optional): Maximum number of retry attempts per text. Defaults to 3.

    Returns:
        List[Dict[str, Any]]: List of analysis results

    Raises:
        ValueError: If input list is empty or contains invalid texts
        GeminiException: If batch processing fails
        RetryBudgetExceeded: If retry budget is exhausted
    '''
    if not texts:
        raise ValueError("Empty list of texts provided")
        
    if batch_size < 1:
        raise ValueError("Batch size must be at least 1")
        
    if max_retries < 1:
        raise ValueError("Max retries must be at least 1")
    
    # Check if we have enough retry budget for worst case
    total_retries_needed = len(texts) * max_retries
    if total_retries_needed > retry_budget:
        logger.warning(
            f"Adjusting max_retries from {max_retries} to {retry_budget // len(texts)} "
            f"due to retry budget constraints"
        )
        max_retries = max(1, retry_budget // len(texts))  # Ensure at least 1 retry

    results = []
    failed_indices = []

    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        tasks = [
            gemini_enrich(text, max_retries=max_retries)
            for text in batch
        ]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and track failures
        for j, result in enumerate(batch_results):
            if isinstance(result, Exception):
                logger.error(f"Failed to analyze text at index {i+j}: {str(result)}")
                failed_indices.append(i+j)
                # Add a failure indicator in place of the result
                results.append({
                    "error": str(result),
                    "threatLevel": "Unknown",
                    "confidenceScore": 0,
                    "metadata": {
                        "analysisTimestamp": datetime.utcnow().isoformat(),
                        "error": True,
                        "errorType": type(result).__name__
                    }
                })
            else:
                results.append(result)

    if failed_indices:
        logger.warning(f"Failed to analyze {len(failed_indices)} texts at indices: {failed_indices}")

    return results
