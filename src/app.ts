import express, { type Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { env } from './config/env.js';
import { runMigrations } from './db/index.js';
import { authRouter } from './routes/auth.js';
import { passkeyRouter } from './routes/passkeys.js';
import { syncRouter } from './routes/sync.js';
import { consciousnessRouter } from './routes/consciousness.js';
import { chatRouter } from './routes/chat.js';
import { accountRouter } from './routes/account.js';
import { remoteAccessRouter } from './routes/remoteAccessRoutes.js';
import { remoteRouter } from './routes/remote.js';
import { errorHandler, notFound } from './middleware/errorHandler.js';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Builds the Express app without binding a port, so tests can mount it on an
 * ephemeral one. Bootstrapping (listen, signals, retention job) lives in
 * server.ts.
 */
export async function createApp(): Promise<Express> {
  await runMigrations();

  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1); // rate limiters key on req.ip behind a proxy
  // contentSecurityPolicy: false — the dashboard SPA ships its own precise
  // CSP via a <meta> tag (see web-dashboard/index.html), scoped exactly to
  // what that page needs (including the cross-origin remote-mcp-server call).
  // Browsers enforce the INTERSECTION of every CSP source on a page, so
  // helmet's default header-level policy (no connect-src override) was
  // silently blocking that fetch regardless of what the meta tag allowed.
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(
    cors({
      origin(origin, cb) {
        // Native collectors send no Origin header; browsers must be allowlisted.
        if (!origin || env.corsOrigins.includes(origin)) return cb(null, true);
        cb(new Error(`Origin not allowed: ${origin}`));
      },
      credentials: true,
    }),
  );
  app.use(express.json({ limit: '8mb' })); // a 500-event batch of ciphertext

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'oneconscious-backend', time: new Date().toISOString() });
  });

  app.use('/api/auth', authRouter);
  app.use('/api/auth/passkey', passkeyRouter);
  app.use('/api/sync', syncRouter);
  app.use('/api/consciousness', consciousnessRouter);
  app.use('/api/chat', chatRouter);
  app.use('/api/account', accountRouter);
  app.use('/api/account/remote-access', remoteAccessRouter);
  app.use('/api/remote', remoteRouter);

  // Marketing landing page at / (and static assets like the DMG download
  // under /downloads) — plain static files, no build step. Only mounted if
  // it exists, so local dev/tests are unaffected.
  const landingDir = resolve(here, '../../landing');
  if (existsSync(join(landingDir, 'index.html'))) {
    app.use(express.static(landingDir));
  }

  // The dashboard app, under /app — same-origin with the API, avoids any
  // CORS/hosting setup for it. Only mounted if a build actually exists, so
  // local dev/tests (which never build web-dashboard) are unaffected.
  const dashboardDist = resolve(here, '../../web-dashboard/dist');
  const dashboardIndex = join(dashboardDist, 'index.html');
  if (existsSync(dashboardIndex)) {
    app.use('/app', express.static(dashboardDist));
    app.get(/^\/app(\/.*)?$/, (_req, res) => {
      res.sendFile(dashboardIndex);
    });
  }

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
