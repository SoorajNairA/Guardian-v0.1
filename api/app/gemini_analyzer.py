"""
Guardian Threat Detection System - Gemini Analyzer Class

This module provides a class-based interface for interacting with the Gemini API
for threat detection and analysis. It implements proper error handling, response validation,
and structured output processing.
"""

import json
import asyncio
import google.generativeai as genai
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from .logging_client import logger
from .config import settings
from .gemini_models import ThreatAnalysisResult, ModelResponseError

# Define safety settings
SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]

class GeminiAnalyzer:
    """
    A class to handle Gemini API interactions for threat detection.
    
    This class manages model initialization, prompt generation, 
    response handling, and error recovery for the Gemini API.
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize the GeminiAnalyzer with API key and settings.
        
        Args:
            api_key: Optional API key. If not provided, uses settings.gemini_api_key
        """
        # Configure the Gemini API
        api_key = api_key or settings.gemini_api_key
        genai.configure(api_key=api_key)
    
    def _get_available_models(self) -> List[str]:
        """List available Gemini models."""
        try:
            return [m.name for m in genai.list_models()]
        except Exception as e:
            logger.error(f"Error listing Gemini models: {str(e)}")
            return []
            
    def _initialize_model(self, model_name: Optional[str] = None) -> genai.GenerativeModel:
        """
        Initialize the Gemini model with proper configuration.
        
        Args:
            model_name: Optional specific model to use
            
        Returns:
            Configured GenerativeModel instance
        """
        try:
            # List available models
            available_models = self._get_available_models()
            logger.info(f"Available Gemini models: {available_models}")
            
            # Select model name
            model_name = (
                model_name or 
                settings.gemini_model if settings.gemini_model in available_models 
                else 'models/gemini-pro-latest'
            )
            logger.info(f"Using Gemini model: {model_name}")
            
            # Initialize with safety settings
            model = genai.GenerativeModel(model_name, safety_settings=SAFETY_SETTINGS)
            logger.info("Model initialized successfully")
            return model
            
        except Exception as e:
            logger.error(f"Error initializing Gemini model: {str(e)}")
            raise ModelResponseError(f"Failed to initialize Gemini model: {str(e)}")
    
    def _generate_prompt(self, content: str, analysis_type: str = "comprehensive") -> str:
        """
        Generate a structured prompt for threat analysis.
        
        Args:
            content: The text content to analyze
            analysis_type: Type of analysis ('quick' or 'comprehensive')
            
        Returns:
            Formatted prompt string
        """
        if analysis_type == "quick":
            return f"""You are Guardian, a threat analysis system. IMPORTANT: Respond with ONLY a JSON object - no markdown, no code blocks, no explanations.

Content to analyze:
{content}

Expected format (reference only - do not copy comments):
{
    "threat_level": 0.5,        /* Must be float between 0.0 and 1.0 */
    "threat_type": ["phishing"], /* Array with most relevant category */
    "justification": "Text"     /* Brief description of the threat */
}

Guidelines:
- Threat Level: 0.0=safe, 0.3=minor, 0.5=notable, 0.7=serious, 1.0=critical
- Threat Types: Use common categories (e.g., phishing, malware)
- Justification: Brief, factual explanation

IMPORTANT: Return ONLY the JSON object with your analysis. No comments, no explanation, no code blocks."""
        else:
            return f"""You are Guardian, a threat analysis system. IMPORTANT: Respond with ONLY a JSON object - no markdown, no code blocks, no explanations.

Content to analyze:
{content}

Expected format (reference only - do not copy comments):
{
    "threat_level": 0.5,        /* Must be float between 0.0 and 1.0 */
    "threat_type": [            /* Array of relevant categories */
        "phishing",
        "social_engineering"
    ],
    "justification": "Text",    /* Detailed explanation of threats */
    "recommendation": "Text"    /* Specific actions to take */
}

Guidelines:
- Threat Level: 0.0=safe, 0.3=minor, 0.5=notable, 0.7=serious, 1.0=critical
- Categories: phishing, malware, social_engineering, fraud, spam, etc.
- Justification: Specific evidence and concerns
- Recommendations: Clear actionable steps

IMPORTANT: Return ONLY the JSON object with your analysis. No comments, no explanation, no code blocks."""
            
    async def analyze_content(
        self,
        content: str,
        analysis_type: str = "comprehensive",
        max_retries: int = 3,
        timeout: Optional[float] = None
    ) -> ThreatAnalysisResult:
        """
        Analyzes the content using the Gemini model to detect potential threats.
        
        Args:
            content: The text content to analyze
            analysis_type: Type of analysis to perform ('quick' or 'comprehensive')
            max_retries: Maximum number of retry attempts
            timeout: Optional timeout in seconds
            
        Returns:
            ThreatAnalysisResult: The analysis results including threat level and details
        """
        try:
            # Initialize model
            model = self._initialize_model()
            
            # Generate and send prompt
            prompt = self._generate_prompt(content, analysis_type)
            response = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: model.generate_content(prompt)
            )
            logger.info("Received response from model")
            logger.debug(f"Raw response: {response}")

            # Check if response has candidates
            if not response.candidates or not response.candidates[0].content:
                raise ModelResponseError("No valid content in model response")

            # Get the text from the first candidate's content
            response_text = response.candidates[0].content.parts[0].text
            if not response_text:
                raise ModelResponseError("Empty response text from model")

            logger.debug(f"Response text: {response_text}")

            # Parse the JSON response
            try:
                json_result = json.loads(response_text)
                logger.info("Successfully parsed model response")
                
                # Validate required fields based on analysis type
                required_fields = ["threat_level", "threat_type", "justification"]
                if analysis_type == "comprehensive":
                    required_fields.append("recommendation")
                    
                missing_fields = [field for field in required_fields if field not in json_result]
                if missing_fields:
                    raise ModelResponseError(f"Missing required fields in response: {missing_fields}")

                # Create result with optional recommendation for quick mode
                recommendation = (json_result.get("recommendation") 
                               if analysis_type == "comprehensive" 
                               else "Quick analysis completed. Request comprehensive analysis for detailed recommendations.")
                
                result = ThreatAnalysisResult(
                    threat_level=float(json_result["threat_level"]),
                    threat_type=json_result["threat_type"],
                    justification=json_result["justification"],
                    recommendation=recommendation
                )
                logger.info(f"Analysis complete - Threat level: {result.threat_level}")
                return result
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse model response as JSON: {e}")
                logger.error(f"Invalid response content: {response_text}")
                raise ModelResponseError("Invalid JSON response from model")
                
        except asyncio.TimeoutError:
            logger.error("Model response timed out")
            raise ModelResponseError("Model response timed out")
            
        except Exception as e:
            logger.error(f"Error during content analysis: {str(e)}")
            if isinstance(e, ModelResponseError):
                raise
            raise ModelResponseError(f"Unexpected error during analysis: {str(e)}")