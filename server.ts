import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const apiRouter = require('./backend/routes/api.js');
import { runAgenticThreatAnalysis } from './backend/engine/aiAgent.js';

function getPythonExecutable() {
  if (process.env.PYTHON) return process.env.PYTHON;
  const venvPythonWin = path.join(__dirname, '.venv', 'Scripts', 'python.exe');
  if (fs.existsSync(venvPythonWin)) return venvPythonWin;
  const venvPythonPosix = path.join(__dirname, '.venv', 'bin', 'python');
  if (fs.existsSync(venvPythonPosix)) return venvPythonPosix;
  return 'python';
}

function startMlService() {
  const python = getPythonExecutable();
  const script = path.join(__dirname, 'ml', 'infer.py');
  if (!fs.existsSync(script)) return null;

  console.log(`[ML] Spawning inference service using: ${python}`);
  const child = spawn(python, [script], {
    cwd: path.join(__dirname, 'ml'),
    stdio: 'inherit',
    windowsHide: true
  });

  child.on('error', (err) => {
    console.warn('[ML] Could not start inference service:', err.message);
  });

  child.on('exit', (code, signal) => {
    if (code && code !== 0) {
      console.warn(`[ML] Inference service exited (code=${code}, signal=${signal})`);
    }
  });

  const stop = () => {
    if (!child.killed) child.kill();
  };
  process.on('exit', stop);
  process.on('SIGINT', () => {
    stop();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    stop();
    process.exit(0);
  });

  return child;
}

if (process.env.SKIP_ML_SERVER !== '1') {
  startMlService();
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT || 3000);
  const HOST = process.env.HOST || '0.0.0.0';

  app.use(cors());
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // Agentic AI Advanced Threat Analysis Route (Independent of ML pipeline)
  app.post(['/api/ai-threat-analysis', '/ai-threat-analysis'], async (req, res) => {
    try {
      const { type = 'email', content = '', email_text, sender, sender_email, url, attachments } = req.body || {};
      const targetContent = content || email_text || url || '';
      const targetSender = sender || sender_email || '';

      const analysis = await runAgenticThreatAnalysis({
        type: type === 'url' ? 'url' : 'email',
        content: String(targetContent),
        sender: String(targetSender),
        url: type === 'url' ? String(url || targetContent) : undefined,
        attachments: Array.isArray(attachments) ? attachments : undefined
      });

      return res.json(analysis);
    } catch (err: any) {
      console.error('[AI Analysis Error]', err);
      return res.status(500).json({ error: 'AI Agentic Threat Analysis failed: ' + (err.message || 'Internal error') });
    }
  });

  // Mount backend API routes directly and under /api
  app.use('/api', apiRouter);
  app.use('/', apiRouter);

  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (err.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Request exceeds the 50 MB limit.' });
    }
    console.error('[Request Error]', err);
    return res.status(err.status || 500).json({ error: 'Request could not be processed.' });
  });

  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true, host: '0.0.0.0', port: PORT },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, HOST, () => {
    console.log(`[PhishGuard Engine] Full-stack server running on http://${HOST}:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
