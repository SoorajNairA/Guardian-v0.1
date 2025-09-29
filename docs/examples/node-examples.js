/**
 * This file contains a comprehensive collection of Node.js code examples for the Guardian SDK.
 */

import { Guardian, GuardianError, GuardianRateLimitError, GuardianTimeoutError } from '@guardian/sdk';

const API_KEY = process.env.GUARDIAN_API_KEY || 'your-api-key';

// ===================================
// 1. Basic Usage
// ===================================
async function basicAnalysis() {
  console.log('--- 1. Basic Usage ---');
  const client = new Guardian({ apiKey: API_KEY });
  try {
    const result = await client.analyze('This is a test of the basic analysis.');
    console.log(`Risk Score: ${result.risk_score}`);
    console.log(`Threats:`, result.threats_detected);
  } catch (error) {
    console.error(`An error occurred: ${error.message}`);
  }
}

// ===================================
// 2. Error Handling
// ===================================
async function errorHandlingExample() {
  console.log('\n--- 2. Error Handling ---');
  // Using a non-existent server to force a timeout
  const client = new Guardian({ apiKey: API_KEY, baseUrl: 'http://localhost:9999', maxRetries: 2 });
  try {
    await client.analyze('This will time out.');
  } catch (error) {
    if (error instanceof GuardianTimeoutError) {
      console.log(`Caught expected timeout error: ${error.message}`);
    } else {
      console.error(`Caught unexpected error: ${error.message}`);
    }
  }
}

// ===================================
// 3. Batch Processing
// ===================================
async function batchProcessingExample() {
  console.log('\n--- 3. Batch Processing ---');
  const client = new Guardian({ apiKey: API_KEY });
  const textsToAnalyze = [
    'This is a benign text.',
    'Click here to win a prize: http://prize-scam.com',
    'My SSN is 123-45-6789.',
    'Another normal message.',
  ];

  const results = await Promise.allSettled(
    textsToAnalyze.map(text => client.analyze(text))
  );

  results.forEach((result, index) => {
    const text = textsToAnalyze[index];
    if (result.status === 'fulfilled') {
      console.log(`'${text.substring(0, 20)}...' -> Risk Score: ${result.value.risk_score}`);
    } else {
      console.error(`Error analyzing '${text.substring(0, 20)}...': ${result.reason.message}`);
    }
  });
}

// ===================================
// 4. Integration with Express.js
// ===================================
// This is a conceptual example of how you would integrate with Express.
// To run this, you would need to install Express (`npm install express`).

/*
import express from 'express';
import { Guardian } from '@guardian/sdk';

const app = express();
app.use(express.json());

const guardianClient = new Guardian({ apiKey: API_KEY });

app.post('/analyze', async (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).json({ error: "'text' field is required" });
  }

  try {
    const result = await guardianClient.analyze(text);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// app.listen(3000, () => console.log('Express server running on port 3000'));
*/

// ===================================
// 5. Advanced Configuration
// ===================================
async function advancedConfiguration() {
  console.log('\n--- 5. Advanced Configuration ---');
  // Enable debug logging by setting the DEBUG environment variable:
  // export DEBUG="guardian:*"
  const client = new Guardian({
    apiKey: API_KEY,
    timeoutMs: 20000,
    maxRetries: 4,
    debug: true, // This enables the debug logs
  });
  console.log('Client created with advanced configuration and debug logging enabled.');
  await client.analyze('This analysis will be logged in detail.');
}


async function main() {
  await basicAnalysis();
  await errorHandlingExample();
  await batchProcessingExample();
  await advancedConfiguration();
  console.log('\nExpress example is commented out. See file for implementation details.');
}

main().catch(console.error);
