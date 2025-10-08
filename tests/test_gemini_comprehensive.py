"""
Comprehensive test suite for the Gemini API integration module.
Tests cover all major functionality including:
- Input validation
- Response parsing
- Error handling
- Rate limiting
- Caching
- Batch processing
- Safety filters
"""

import pytest
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any
from unittest.mock import patch, MagicMock
from api.app.gemini import (
    gemini_enrich, batch_analyze_texts, extract_threat_level,
    extract_confidence_score, validate_response, calculate_consistency_score,
    GeminiException, ResponseParsingException, RateLimitExceeded,
    RetryBudgetExceeded, RequestTimeout
)

# Test data
VALID_TEXT = "This is a test message for threat analysis."
LONG_TEXT = "x" * 31000  # Exceeds max length
EMPTY_TEXT = ""
WHITESPACE_TEXT = "   \n   \t   "

VALID_QUICK_RESPONSE = {
    "threatLevel": "Low",
    "primaryConcern": "No significant threats detected",
    "confidenceScore": 85
}

VALID_COMPREHENSIVE_RESPONSE = {
    "threatLevel": "Medium",
    "categories": ["phishing", "social_engineering"],
    "concerns": [
        "Attempts to collect sensitive information",
        "Uses urgency to prompt action"
    ],
    "confidenceScore": 90,
    "recommendations": [
        "Verify sender's identity",
        "Do not click on suspicious links"
    ],
    "metadata": {
        "analysisTimestamp": datetime.utcnow().isoformat(),
        "modelVersion": "gemini-2.5-pro",
        "analysisType": "comprehensive",
        "evidenceStrength": "High"
    }
}

@pytest.fixture
def mock_genai():
    """Mock the Google Generative AI client"""
    with patch("google.generativeai") as mock:
        yield mock

@pytest.fixture
def mock_model(mock_genai):
    """Mock the Gemini model with controlled responses"""
    model = MagicMock()
    mock_genai.GenerativeModel.return_value = model
    return model

@pytest.mark.asyncio
async def test_input_validation():
    """Test input validation for the gemini_enrich function"""
    # Test empty text
    with pytest.raises(ValueError, match="Empty or whitespace-only text provided"):
        await gemini_enrich(EMPTY_TEXT)

    # Test whitespace-only text
    with pytest.raises(ValueError, match="Empty or whitespace-only text provided"):
        await gemini_enrich(WHITESPACE_TEXT)

    # Test text exceeding length limit
    with pytest.raises(ValueError, match="Text exceeds maximum length limit"):
        await gemini_enrich(LONG_TEXT)

    # Test invalid analysis type
    with pytest.raises(ValueError, match="Invalid analysis_type"):
        await gemini_enrich(VALID_TEXT, analysis_type="invalid")

@pytest.mark.asyncio
async def test_quick_analysis(mock_model):
    """Test quick threat analysis functionality"""
    # Mock successful response
    mock_response = MagicMock()
    mock_response.text = json.dumps(VALID_QUICK_RESPONSE)
    mock_model.generate_content_async.return_value = mock_response

    result = await gemini_enrich(VALID_TEXT, analysis_type="quick")
    
    assert result["threatLevel"] == "Low"
    assert isinstance(result["confidenceScore"], int)
    assert 0 <= result["confidenceScore"] <= 100
    assert isinstance(result["primaryConcern"], str)

@pytest.mark.asyncio
async def test_comprehensive_analysis(mock_model):
    """Test comprehensive threat analysis functionality"""
    # Mock successful response
    mock_response = MagicMock()
    mock_response.text = json.dumps(VALID_COMPREHENSIVE_RESPONSE)
    mock_model.generate_content_async.return_value = mock_response

    result = await gemini_enrich(VALID_TEXT, analysis_type="comprehensive")
    
    assert result["threatLevel"] in ["None", "Low", "Medium", "High", "Critical"]
    assert isinstance(result["categories"], list)
    assert isinstance(result["concerns"], list)
    assert isinstance(result["recommendations"], list)
    assert isinstance(result["confidenceScore"], int)
    assert 0 <= result["confidenceScore"] <= 100
    assert "metadata" in result

@pytest.mark.asyncio
async def test_safety_filter_handling(mock_model):
    """Test handling of content blocked by safety filters"""
    # Mock safety filter block
    mock_response = MagicMock()
    mock_response.candidates = []
    mock_response.prompt_feedback.safety_ratings = [
        MagicMock(category="HARM_CATEGORY_DANGEROUS_CONTENT", probability="HIGH")
    ]
    mock_model.generate_content_async.return_value = mock_response

    with pytest.raises(GeminiException, match="Content blocked by safety filters"):
        await gemini_enrich(VALID_TEXT)

@pytest.mark.asyncio
async def test_rate_limiting():
    """Test rate limiting functionality"""
    # Reset request timestamps
    from api.app.gemini import request_timestamps
    request_timestamps.clear()

    # Add fake timestamps to simulate rate limit
    current_time = time.time()
    request_timestamps["api"].extend([current_time] * 100)  # Max requests

    with pytest.raises(RateLimitExceeded):
        await gemini_enrich(VALID_TEXT)

@pytest.mark.asyncio
async def test_retry_budget():
    """Test retry budget functionality"""
    # Reset retry budget
    from api.app.gemini import retry_budget, MAX_TOTAL_RETRIES
    global retry_budget
    retry_budget = 0  # Exhaust budget

    with pytest.raises(RetryBudgetExceeded):
        await gemini_enrich(VALID_TEXT, max_retries=3)

    # Reset budget for other tests
    retry_budget = MAX_TOTAL_RETRIES

@pytest.mark.asyncio
async def test_batch_processing(mock_model):
    """Test batch processing functionality"""
    # Mock successful responses
    mock_response = MagicMock()
    mock_response.text = json.dumps(VALID_QUICK_RESPONSE)
    mock_model.generate_content_async.return_value = mock_response

    texts = [VALID_TEXT] * 3
    results = await batch_analyze_texts(texts, batch_size=2)

    assert len(results) == len(texts)
    for result in results:
        assert "threatLevel" in result
        assert "confidenceScore" in result

@pytest.mark.asyncio
async def test_caching():
    """Test response caching functionality"""
    # First request - should miss cache
    cache_key = "test_key"
    result1 = await gemini_enrich(VALID_TEXT, cache_key=cache_key)

    # Second request - should hit cache
    result2 = await gemini_enrich(VALID_TEXT, cache_key=cache_key)

    assert result1 == result2  # Results should be identical

def test_threat_level_extraction():
    """Test threat level extraction from text"""
    assert extract_threat_level("Critical security issue") == "Critical"
    assert extract_threat_level("High risk detected") == "High"
    assert extract_threat_level("Medium severity") == "Medium"
    assert extract_threat_level("Low impact") == "Low"
    assert extract_threat_level("No threats found") == "None"

def test_confidence_score_extraction():
    """Test confidence score extraction from text"""
    assert extract_confidence_score("90% confidence") == 90
    assert extract_confidence_score("confidence: 85%") == 85
    assert extract_confidence_score("highly likely") == 85
    assert extract_confidence_score("uncertain") == 40

def test_response_validation():
    """Test response validation functionality"""
    # Test valid responses
    assert validate_response(VALID_QUICK_RESPONSE, "quick") is True
    assert validate_response(VALID_COMPREHENSIVE_RESPONSE, "comprehensive") is True

    # Test invalid responses
    invalid_response = {
        "threatLevel": "Invalid",
        "confidenceScore": 150  # Over 100
    }
    with pytest.raises(ResponseParsingException):
        validate_response(invalid_response, "quick")

def test_consistency_score():
    """Test response consistency scoring"""
    # Test high consistency
    high_consistency = {
        "threatLevel": "Critical",
        "confidenceScore": 95,
        "categories": ["malware"],
        "concerns": ["Malware detected in the system"],
        "recommendations": ["Remove detected malware immediately"]
    }
    assert calculate_consistency_score(high_consistency) > 0.8

    # Test low consistency
    low_consistency = {
        "threatLevel": "Critical",
        "confidenceScore": 30,  # Inconsistent with Critical threat
        "categories": ["spam"],  # Inconsistent category for Critical threat
        "concerns": ["Minor spelling errors"],  # Inconsistent concern
        "recommendations": ["Monitor for changes"]  # Weak recommendation
    }
    assert calculate_consistency_score(low_consistency) < 0.5