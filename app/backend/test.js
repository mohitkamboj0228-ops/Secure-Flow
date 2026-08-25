const http = require('http');
const assert = require('assert');

// Simple integration test for backend endpoints
async function runTests() {
  console.log('[TEST] Starting API test suite...');
  
  // We can launch the backend temporarily or expect it to be running.
  // In a local run, we check if the server is accessible.
  const host = 'localhost';
  const port = process.env.PORT || 5000;

  const testEndpoint = (path) => {
    return new Promise((resolve, reject) => {
      http.get(`http://${host}:${port}${path}`, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          resolve({ statusCode: res.statusCode, body: JSON.parse(body) });
        });
      }).on('error', err => reject(err));
    });
  };

  try {
    console.log('[TEST] Verifying /health endpoint...');
    const health = await testEndpoint('/health');
    assert.strictEqual(health.statusCode, 200);
    assert.strictEqual(health.body.status, 'UP');
    console.log('✓ /health test passed.');

    console.log('[TEST] Verifying /ready endpoint...');
    const ready = await testEndpoint('/ready');
    assert.strictEqual(ready.statusCode, 200);
    assert.strictEqual(ready.body.status, 'READY');
    console.log('✓ /ready test passed.');

    console.log('[TEST] Verifying /api/status endpoint...');
    const status = await testEndpoint('/api/status');
    assert.strictEqual(status.statusCode, 200);
    assert.ok(status.body.platform.includes('SecureFlow'));
    console.log('✓ /api/status test passed.');

    console.log('\n[TEST] All backend API tests completed SUCCESS.');
  } catch (err) {
    console.error(`[TEST] Test suite failed: ${err.message}`);
    console.log('NOTE: Ensure backend is running via "npm start" or docker container before executing tests.');
    process.exit(1);
  }
}

// Run the script directly if invoked
if (require.main === module) {
  runTests();
}
