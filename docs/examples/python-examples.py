"""
This file contains a comprehensive collection of Python code examples for the Guardian SDK.

To run these examples, you must first install the SDK in development mode:
1. Navigate to the root of the Guardian project.
2. Run `pip install -e ./sdk/python`.

For more details, see the Development Setup section in the main README.md file.
"""

import os
import sys
import time
import asyncio

try:
    from guardian_sdk import (
        Guardian,
        GuardianConfig,
        GuardianError,
        GuardianAPIError,
        GuardianRateLimitError,
        GuardianTimeoutError,
    )
except ImportError:
    print("Error: The `guardian_sdk` is not installed.")
    print("Please install it by running `pip install -e ./sdk/python` from the project root.")
    sys.exit(1)

API_KEY = os.getenv("GUARDIAN_API_KEY", "your-api-key")

# ===================================
# 1. Basic Usage
# ===================================
def basic_analysis():
    print("--- 1. Basic Usage ---")
    with Guardian(api_key=API_KEY) as client:
        try:
            result = client.analyze("This is a test of the basic analysis.")
            print(f"Risk Score: {result['risk_score']}")
            print(f"Threats: {result['threats_detected']}")
        except GuardianError as e:
            print(f"An error occurred: {e}")

# ===================================
# 2. Error Handling
# ===================================
def error_handling_example():
    print("\n--- 2. Error Handling ---")
    # Using a non-existent server to force a timeout
    config = GuardianConfig(api_key=API_KEY, base_url="http://localhost:9999", max_retries=2)
    with Guardian(config=config) as client:
        try:
            client.analyze("This will time out.")
        except GuardianTimeoutError as e:
            print(f"Caught expected timeout error: {e}")
        except GuardianError as e:
            print(f"Caught unexpected error: {e}")

# ===================================
# 3. Batch Processing
# ===================================
async def batch_processing_example():
    print("\n--- 3. Batch Processing ---")
    texts_to_analyze = [
        "This is a benign text.",
        "Click here to win a prize: http://prize-scam.com",
        "My SSN is 123-45-6789.",
        "Another normal message."
    ]

    async def analyze_text_async(client, text):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: client.analyze(text))

    with Guardian(api_key=API_KEY) as client:
        tasks = [analyze_text_async(client, text) for text in texts_to_analyze]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for text, result in zip(texts_to_analyze, results):
            if isinstance(result, GuardianError):
                print(f'Error analyzing "{text[:20]}...": {result}')
            else:
                print(f'"{text[:20]}..." -> Risk Score: {result["risk_score"]}')

# ===================================
# 4. Integration with Flask
# ===================================
# This is a conceptual example of how you would integrate with Flask.
# To run this, you would need to install Flask (`pip install Flask`).

# from flask import Flask, request, jsonify
# from guardian_sdk import Guardian

# app = Flask(__name__)
# guardian_client = Guardian(api_key=API_KEY)

# @app.route("/analyze", methods=["POST"])
def analyze_endpoint():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "'text' field is required"}), 400
    
    try:
        result = guardian_client.analyze(data["text"])
        return jsonify(result)
    except GuardianError as e:
        return jsonify({"error": str(e)}), 500

# ===================================
# 5. Advanced Configuration
# ===================================
def advanced_configuration():
    print("\n--- 5. Advanced Configuration ---")
    config = GuardianConfig(
        api_key=API_KEY,
        timeout_seconds=20.0,
        max_retries=4,
        debug=True, # Enable verbose SDK logging
    )
    with Guardian(config=config) as client:
        print("Client created with advanced configuration and debug logging enabled.")
        # The SDK will now print detailed logs to the console.
        client.analyze("This analysis will be logged in detail.")


if __name__ == "__main__":
    basic_analysis()
    error_handling_example()
    asyncio.run(batch_processing_example())
    advanced_configuration()
    print("\nFlask example is commented out. See file for implementation details.")
