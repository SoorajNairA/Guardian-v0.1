import subprocess
import os
import pytest

# Path to the Node.js SDK directory
SDK_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sdk", "node", "guardian-sdk"))

# A simple test to ensure the Node.js test script can run and the SDK can be imported.
# A full test suite would be written in JavaScript and run with a framework like Jest.

@pytest.mark.skipif(not os.path.exists(SDK_DIR), reason="Node.js SDK not found")
def test_node_sdk_basic_execution():
    """
    Executes a simple Node.js script to test basic SDK functionality.
    This is a proxy for a full JS-based test suite.
    """
    test_script_content = """
    import assert from 'assert';
    import { Guardian, GuardianValidationError } from './src/index.js';

    async function main() {
        console.log('Running Node.js SDK basic test...');

        // Test initialization
        try {
            new Guardian(); // Should throw validation error
            assert.fail('Expected GuardianValidationError for missing API key');
        } catch (e) {
            assert(e instanceof GuardianValidationError, 'Error should be GuardianValidationError');
            console.log('\u2713 Initialization test passed');
        }

        // Test successful analysis (mocked)
        const guardian = new Guardian({ apiKey: 'fake-key', baseUrl: 'http://fake-server.com' });

        // A real test suite would use a mock server (e.g., nock)
        // Here we just check if the method exists and can be called.
        assert.strictEqual(typeof guardian.analyze, 'function');
        console.log('\u2713 Analyze method exists');

        console.log('Node.js SDK basic test completed successfully.');
    }

    main().catch(err => {
        console.error(err);
        process.exit(1);
    });
    """
    
    test_file_path = os.path.join(SDK_DIR, "basic_test.js")
    with open(test_file_path, "w", encoding="utf-8") as f:
        f.write(test_script_content)

    try:
        # Ensure node_modules are installed
        subprocess.run(["npm", "install"], cwd=SDK_DIR, check=True, shell=True, capture_output=True, text=True)
        
        # Run the test script
        result = subprocess.run(
            ["node", "basic_test.js"],
            cwd=SDK_DIR,
            check=True,
            capture_output=True,
            text=True,
        )
        
        # Check for success message in stdout
        assert "Node.js SDK basic test completed successfully" in result.stdout
        print(result.stdout)

    finally:
        # Clean up the test file
        os.remove(test_file_path)