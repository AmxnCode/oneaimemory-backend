import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

const common = {
  standardHeaders: true as const,
  legacyHeaders: false as const,
  // Integration tests drive hundreds of requests from one address; limiting
  // them would make the suite order-dependent and flaky.
  skip: () => env.NODE_ENV === 'test',
};

/** Strict limit on credential endpoints to slow online password guessing. */
export const authLimiter = rateLimit({
  ...common,
  windowMs: 15 * 60_000,
  max: 10,
  skipSuccessfulRequests: true,
  message: { error: 'too_many_auth_attempts' },
});

/**
 * Sync is deliberately generous: a device coming back from a long offline
 * stretch legitimately uploads many batches in a burst.
 */
export const syncLimiter = rateLimit({
  ...common,
  windowMs: 60_000,
  max: 120,
  keyGenerator: (req) => String(req.userId ?? req.ip),
  message: { error: 'sync_rate_limit' },
});

export const readLimiter = rateLimit({
  ...common,
  windowMs: 15 * 60_000,
  max: 300,
  keyGenerator: (req) => String(req.userId ?? req.ip),
  message: { error: 'rate_limit' },
});
