// server.js
// Main entry point - routes requests to /backend and serves static frontend

const express = require('express');
const cors = require('cors');
const path = require('path');

const apiRouter = require('./backend/routes/api');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Mount backend API routes directly and under /api
app.use('/api', apiRouter);
app.use('/', apiRouter);

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'frontend')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[PhishGuard Engine] Server running on http://0.0.0.0:${PORT}`);
});
