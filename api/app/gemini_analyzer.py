"""
Guardian Threat Detection System - Gemini Analyzer Class

This module provides a class-based interface for interacting with the Gemini API
for threat detection and analysis. It implements proper error handling, response validation,
and structured output processing.
"""

import json
import re
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
            
    def _clean_and_parse_json(self, response_text: str) -> Dict[str, Any]:
        """
        Clean and parse the model response to extract only the JSON content.
        
        Args:
            response_text: Raw response text that might contain JSON with markdown or comments
            
        Returns:
            Parsed JSON dictionary
            
        Raises:
            json.JSONDecodeError: If JSON parsing fails
        """
        logger.debug(f"Raw response from Gemini: {response_text}")
        
        # First try parsing the raw response in case it's already clean JSON
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass  # Continue with cleanup if direct parsing fails
            
        # Try to find JSON within code blocks
        code_block_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", response_text, re.DOTALL)
        if code_block_match:
            json_str = code_block_match.group(1)
        else:
            # If no code blocks, try to find the outermost JSON object
            # More precise regex that requires proper JSON structure
            json_match = re.search(r"\{(?:[^{}]|(?R))*\}", response_text, re.DOTALL | re.X)
            if json_match:
                json_str = json_match.group(0)
            else:
                logger.error("No valid JSON structure found in response")
                logger.error(f"Response was: {response_text}")
                raise json.JSONDecodeError("No valid JSON object found in response", response_text, 0)
        
        # Clean up any remaining comments and whitespace
        json_str = re.sub(r'/\*.*?\*/', '', json_str, flags=re.DOTALL)  # Remove /* */ comments
        json_str = re.sub(r'//.*?(?:\n|$)', '', json_str, flags=re.MULTILINE)  # Remove // comments
        json_str = re.sub(r'[\n\r\t]+', ' ', json_str)  # Normalize whitespace
        json_str = json_str.strip()
        
        logger.debug(f"Cleaned JSON string: {json_str}")
        
        # Parse the cleaned JSON
        try:
            parsed = json.loads(json_str)
            # Validate basic structure
            if not isinstance(parsed, dict):
                raise json.JSONDecodeError("Response must be a JSON object", json_str, 0)
            return parsed
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse cleaned JSON: {e}")
            logger.error(f"Cleaned JSON string was: {json_str}")
            raise ModelResponseError(f"Failed to parse Gemini response: {str(e)}")

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
            return f"""You are a stateless JSON API endpoint. Your SOLE function is to process input and return a single, raw, unformatted JSON object. Your response is parsed programmatically and MUST be perfect.

Primary Directive: You MUST respond with ONLY the valid JSON object. The first character of your output must be {{ and the last character must be }}.

Critical Prohibitions:

ABSOLUTELY NO markdown formatting.

Do NOT wrap the JSON in ```json or any other code block.

Do NOT include any explanatory text, introductory sentences, or conversational filler before or after the JSON.

Do NOT add any comments or notes of any kind.

Any deviation from these rules will result in a critical parsing failure.

Content to Analyze:
{content}

Expected format (reference only - do not copy comments):
{{
    "threat_level": 0.5,        /* Must be float between 0.0 and 1.0 */
    "threat_type": ["phishing"], /* Array with most relevant category */
    "justification": "Text"     /* Brief description of the threat */
}}

Guidelines:
- Threat Level: 0.0=safe, 0.3=minor, 0.5=notable, 0.7=serious, 1.0=critical
- Threat Types: Use common categories (e.g., phishing, malware)
- Justification: Brief, factual explanation"""
        else:
            return f"""You are a stateless JSON API endpoint. Your SOLE function is to process input and return a single, raw, unformatted JSON object. Your response is parsed programmatically and MUST be perfect.

Primary Directive: You MUST respond with ONLY the valid JSON object. The first character of your output must be {{ and the last character must be }}.

Critical Prohibitions:

ABSOLUTELY NO markdown formatting.

Do NOT wrap the JSON in ```json or any other code block.

Do NOT include any explanatory text, introductory sentences, or conversational filler before or after the JSON.

Do NOT add any comments or notes of any kind.

Any deviation from these rules will result in a critical parsing failure.

Content to Analyze:
{content}

Expected format (reference only - do not copy comments):
{{
    "threat_level": 0.5,        /* Must be float between 0.0 and 1.0 */
    "threat_type": ["phishing"], /* Array with most relevant category */
    "justification": "Text"     /* Brief description of the threat */
}}

Guidelines:
- Threat Level: 0.0=safe, 0.3=minor, 0.5=notable, 0.7=serious, 1.0=critical
- Threat Types: Use common categories (e.g., phishing, malware)
- Justification: Brief, factual explanation"""
            
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

            # Clean and parse the JSON response
            try:
                json_result = self._clean_and_parse_json(response_text)
                logger.info("Successfully cleaned and parsed model response")
                
                # Validate required core fields
                core_fields = ["threat_level", "threat_type", "justification"]
                missing_core = [field for field in core_fields if field not in json_result]
                if missing_core:
                    raise ModelResponseError(f"Missing required core fields in response: {missing_core}")
                    
                # Recommendation is optional - just use whatever is in the response
                recommendation = json_result.get("recommendation")
                
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