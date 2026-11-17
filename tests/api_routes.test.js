const assert = require('assert');
const express = require('express');
const http = require('http');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

async function main() {
  let receivedContent;
  const mlServer = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      receivedContent = payload.content_base64;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        classification: 'Safe',
        risk_score: 1,
        probabilities: { safe: 1, suspicious: 0, malicious: 0 }
      }));
    });
  });

  const mlPort = await listen(mlServer);
  process.env.ML_INFER_URL = `http://127.0.0.1:${mlPort}`;
  const apiRouter = require('../backend/routes/api');
  const app = express();
  app.use(express.json({ limit: '50mb' }));
  app.use(apiRouter);
  const appServer = http.createServer(app);
  const appPort = await listen(appServer);

  try {
    const largeBase64 = 'A'.repeat(8 * 1024 * 1024 + 2);
    const response = await fetch(`http://127.0.0.1:${appPort}/predict_attachment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: 'large.pdf',
        mime_type: 'application/pdf',
        content_base64: largeBase64
      })
    });

    assert.strictEqual(response.status, 200);
    assert.strictEqual((await response.json()).classification, 'Safe');
    assert.strictEqual(receivedContent, `${largeBase64}==`);

    const dataUrlResponse = await fetch(`http://127.0.0.1:${appPort}/predict_attachment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: 'small.txt',
        content_base64: 'data:text/plain;base64,SGVsbG8'
      })
    });
    assert.strictEqual(dataUrlResponse.status, 200);
    assert.strictEqual(receivedContent, 'SGVsbG8=');

    const invalidResponse = await fetch(`http://127.0.0.1:${appPort}/predict_attachment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: 'invalid.txt', content_base64: 'a===' })
    });
    assert.strictEqual(invalidResponse.status, 400);
  } finally {
    await Promise.all([close(appServer), close(mlServer)]);
  }

  console.log('Node attachment API large/data-URL base64 paths passed');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
