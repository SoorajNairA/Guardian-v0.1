"""
Development setup script for the Guardian Python SDK.

This script automates the installation of the Python SDK in development mode
and all required dependencies for testing.

Usage:
    python setup_dev.py
"""

import subprocess
import sys
import os

def run_command(command):
    """Runs a command and streams its output."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=True)
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    return process.poll()

def main():
    """Main function to run the development setup."""
    print("Starting development setup for the Guardian Python SDK...")

    # Install Python SDK in development mode
    sdk_path = os.path.join("sdk", "python")
    if not os.path.isdir(sdk_path):
        print(f"Error: SDK path not found at '{sdk_path}'")
        sys.exit(1)

    print(f"Installing Python SDK from '{sdk_path}' in development mode...")
    return_code = run_command(f"pip install -e {sdk_path}")
    if return_code != 0:
        print("Error: Failed to install the Python SDK.")
        sys.exit(1)

    # Install development dependencies
    requirements_path = os.path.join("api", "requirements-dev.txt")
    if not os.path.isfile(requirements_path):
        print(f"Error: '{requirements_path}' not found.")
        sys.exit(1)

    print(f"Installing development dependencies from '{requirements_path}'...")
    return_code = run_command(f"pip install -r {requirements_path}")
    if return_code != 0:
        print("Error: Failed to install development dependencies.")
        sys.exit(1)

    # Verify SDK import
    print("Verifying SDK installation...")
    try:
        from guardian_sdk import Guardian
        print("Successfully imported 'Guardian' from 'guardian_sdk'.")
    except ImportError:
        print("Error: Could not import 'guardian_sdk'.")
        print("Please ensure the SDK was installed correctly.")
        sys.exit(1)

    print("Development setup completed successfully!")

if __name__ == "__main__":
    main()
