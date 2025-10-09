# Guardian Node.js SDK

[![npm version](https://badge.fury.io/js/%40guardian%2Fsdk.svg)](https://badge.fury.io/js/%40guardian%2Fsdk)

The official Node.js SDK for the Guardian API, providing a modern, promise-based, and production-ready interface for real-time threat detection.

This SDK includes:
- A simple and intuitive async/await API
- Robust error handling and automatic retries with jitter
- High-performance connection pooling with `undici`
- Namespaced debug logging
- Comprehensive configuration options

## Installation

Install the SDK using npm or yarn:

```bash
npm install @soorajnair282005/guardian_sdk
# or
yarn add @guardian/sdk
```

## Quick Start

Here’s a basic example of how to analyze a piece of text using async/await:

```javascript
import { Guardian, GuardianAPIError } from '@guardian/sdk';

// Initialize the client. API key can be passed directly or set via
// the GUARDIAN_API_KEY environment variable.
const client = new Guardian({ apiKey: process.env.GUARDIAN_API_KEY });

const textToAnalyze = "URGENT: Your account is locked. Click http://secure-login-portal.com to fix.";

async function main() {
  try {
    const result = await client.analyze(textToAnalyze);
    console.log(`Risk Score: ${result.risk_score}`);
    for (const threat of result.threats_detected) {
      console.log(`- Detected Threat: ${threat.category} (Confidence: ${threat.confidence_score})`);
    }
  } catch (error) {
    if (error instanceof GuardianAPIError) {
      console.error(`API Error: ${error.message} (Status: ${error.status})`);
    } else {
      console.error(`An unexpected error occurred: ${error.message}`);
    }
  }
}

main();
```

## Configuration

The client is configured by passing an object to the `Guardian` constructor.

```javascript
import { Guardian } from '@guardian/sdk';

// Advanced configuration
const client = new Guardian({
  apiKey: 'YOUR_API_KEY',
  baseUrl: 'https://api.your-guardian-instance.com',
  timeoutMs: 30000,
  maxRetries: 5,
  debug: true, // Enable verbose logging
});
```

| Parameter   | Type    | Default                         | Description                                                              |
| :---------- | :------ | :------------------------------ | :----------------------------------------------------------------------- |
| `apiKey`    | `string`| `process.env.GUARDIAN_API_KEY`  | Your Guardian API key.                                                   |
| `baseUrl`   | `string`| `"http://localhost:8000"`         | The base URL of the Guardian API.                                        |
| `timeoutMs` | `number`| `15000`                         | Timeout in milliseconds for network requests.                            |
| `maxRetries`| `number`| `3`                             | Maximum number of retries for transient errors (e.g., 5xx, timeouts).    |
| `debug`     | `boolean`| `false`                         | If `true`, enables verbose debug logging to the console.                 |

## Error Handling

The SDK throws specific error classes for different types of failures, all inheriting from `GuardianError`.

- `GuardianValidationError`: Invalid input provided to the SDK.
- `GuardianAPIError`: A generic error from the API (e.g., 400, 500).
- `GuardianRateLimitError`: A `429 Too Many Requests` error. The `retryAfter` property contains the recommended wait time in seconds.
- `GuardianTimeoutError`: The request timed out.

**Example:**

```javascript
import { Guardian, GuardianError, GuardianRateLimitError } from '@guardian/sdk';

const client = new Guardian({ apiKey: 'YOUR_API_KEY' });

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function analyzeWithRetry(text) {
  try {
    return await client.analyze(text);
  } catch (error) {
    if (error instanceof GuardianRateLimitError) {
      console.log(`Rate limited. Waiting for ${error.retryAfter} seconds.`);
      await sleep(error.retryAfter * 1000);
      return analyzeWithRetry(text); // Retry the request
    }
    throw error; // Re-throw other errors
  }
}
```

## Best Practices

### Singleton Instance

For most applications (e.g., an Express server), you should create a single `Guardian` client instance and reuse it across all requests. This is critical for connection pooling to work effectively.

```javascript
// In your application's initialization file (e.g., server.js)
import { Guardian } from '@guardian/sdk';

export const guardianClient = new Guardian({ apiKey: process.env.GUARDIAN_API_KEY });

// In your Express route handler:
app.post('/analyze', async (req, res) => {
  const { text } = req.body;
  try {
    const result = await guardianClient.analyze(text);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

## Debugging

The SDK uses the `debug` library for logging. To enable detailed logs, set the `DEBUG` environment variable:

```bash
export DEBUG="guardian:*"
```

This will enable all SDK logs, including client initialization, request details, and retry attempts.

- `guardian:client`: General client lifecycle events.
- `guardian:request`: Details about outgoing requests and incoming responses.
- `guardian:retry`: Information about retry attempts and backoff delays.
