import 'dotenv/config';
import { z } from 'zod';

const DEV_SECRET = 'dev-only-insecure-secret-change-me';
const DEV_KEK = 'oneconscious-dev-insecure-remote-kek-change-me';

const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(4000),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  DATABASE_PATH: z.string().default('./data/oneconscious.db'),
  // Postgres connection string. When set, this is used instead of SQLite —
  // see db/index.ts. Unset by default, so `npm run dev` with zero config
  // still gets the SQLite path.
  DATABASE_URL: z.string().optional(),
  JWT_SECRET: z.string().min(16).default(DEV_SECRET),
  ACCESS_TOKEN_TTL: z.string().default('15m'),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(7),
  CORS_ORIGINS: z.string().default('http://localhost:5173,http://localhost:3000'),
  // WebAuthn Relying Party ID — the registrable domain, NOT the origin
  // (no scheme, no port). Passkeys are bound to it, so changing it in
  // production invalidates every existing credential.
  RP_ID: z.string().default(''),
  DEFAULT_RETENTION_DAYS: z.coerce.number().int().positive().default(90),
  // Wraps (AES-256-GCM) the data key of any user who opts into remote AI
  // access, so the backend can decrypt on their behalf for unattended remote
  // MCP clients (ChatGPT). This is the server-side half of a deliberate,
  // disclosed weakening of the E2E guarantee for opted-in accounts only —
  // local MCP tools never touch it. Treat it with the same care as JWT_SECRET.
  REMOTE_ACCESS_KEK: z.string().min(32).default(DEV_KEK),
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment configuration:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = {
  ...parsed.data,
  corsOrigins: parsed.data.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
  isProduction: parsed.data.NODE_ENV === 'production',
};

// Refuse to start in production with the shipped dev secret.
if (env.isProduction && env.JWT_SECRET === DEV_SECRET) {
  console.error(
    'FATAL: JWT_SECRET is still the development default. ' +
      'Generate one with: openssl rand -base64 48',
  );
  process.exit(1);
}

// Refuse to start in production with the shipped dev KEK. This key protects
// every opted-in user's wrapped data-decryption key — treat a leak of it as
// equivalent to leaking those users' activity history.
if (env.isProduction && env.REMOTE_ACCESS_KEK === DEV_KEK) {
  console.error(
    'FATAL: REMOTE_ACCESS_KEK is still the development default. ' +
      'Generate one with: openssl rand -base64 48',
  );
  process.exit(1);
}
