import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { apiRouter } from './backend/api/routes';
import { getCorsOptions } from './backend/api/cors';
import { sendSafeError } from './backend/api/errors';

export const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) || 3000 : 3000;

// Hardened CORS policy
app.use(cors(getCorsOptions()));

// Hardened security headers (frame-safe for preview environment)
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Hardened JSON body limit (12MB ceiling to protect memory while supporting 10MB scan payloads)
app.use(express.json({ limit: '12mb' }));

// Safe JSON parsing error handler
app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
  if (err) {
    const statusCode = err.status || err.statusCode || 400;
    const message =
      statusCode === 413
        ? 'Request body exceeds maximum payload size limit.'
        : 'Malformed JSON payload provided.';
    sendSafeError(res, statusCode, message);
    return;
  }
  next();
});

// Mount modular security scanner API routes
app.use('/api', apiRouter);

// Start server with Vite middleware for development and static serve for production
export async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  return app.listen(PORT, '0.0.0.0', () => {
    console.log(`GitHub Security Scanner server running on http://0.0.0.0:${PORT}`);
  });
}

// Only start listener if this module is run directly as main entry point
const isDirectExecution =
  process.argv[1] &&
  (process.argv[1].endsWith('/server.ts') ||
    process.argv[1].endsWith('\\server.ts') ||
    process.argv[1].endsWith('/server.cjs') ||
    process.argv[1].endsWith('\\server.cjs'));

if (isDirectExecution) {
  startServer();
}
