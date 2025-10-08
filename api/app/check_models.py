"""
Script to check available Gemini models for the configured API key
"""
import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure the Gemini API with the API key
api_key = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=api_key)

def main():
    try:
        # List available models
        print("Checking available models...")
        for model in genai.list_models():
            print(f"\nModel Name: {model.name}")
            print(f"Display Name: {model.display_name}")
            print(f"Description: {model.description}")
            print(f"Generation Methods: {', '.join(model.supported_generation_methods)}")
            print("-" * 80)
    except Exception as e:
        print(f"Error checking models: {str(e)}")

if __name__ == "__main__":
    main()