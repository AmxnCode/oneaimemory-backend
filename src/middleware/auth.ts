import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import * as integrations from '../repositories/integrations.js';
import type { Scope } from '../repositories/integrations.js';
import { asyncRoute } from './errorHandler.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      userId?: number;
      deviceId?: string;
      integration?: { id: number; label: string; scopes: Scope[] };
    }
  }
}

export interface AccessTokenClaims {
  sub: string;
  deviceId?: string;
}

export function signAccessToken(userId: number, deviceId?: string): string {
  return jwt.sign({ sub: String(userId), deviceId }, env.JWT_SECRET, {
    expiresIn: env.ACCESS_TOKEN_TTL,
    issuer: 'oneconscious',
  } as jwt.SignOptions);
}

function bearer(req: Request): string | null {
  const header = req.get('authorization');
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice(7).trim() || null;
}

/** User/device session auth. Used by the collector apps and dashboard. */
export function requireUser(req: Request, res: Response, next: NextFunction): void {
  const token = bearer(req);
  if (!token) {
    res.status(401).json({ error: 'missing_token' });
    return;
  }
  try {
    const claims = jwt.verify(token, env.JWT_SECRET, { issuer: 'oneconscious' }) as AccessTokenClaims;
    req.userId = Number(claims.sub);
    req.deviceId = claims.deviceId;
    next();
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
}

/**
 * Integration auth for the MCP server.
 *
 * Authenticates the CREDENTIAL. The caller may send X-AI-Model as a hint, but
 * it is recorded as unverified — nothing stops any client from claiming any
 * model name.
 */
export function requireIntegration(...required: Scope[]) {
  // asyncRoute, not a bare async function: Express 4 does not catch a
  // rejected promise from middleware any more than it does from a route
  // handler, so a DB error here would otherwise hang the request.
  return asyncRoute(async (req: Request, res: Response, next: NextFunction) => {
    const token = bearer(req);
    if (!token) {
      res.status(401).json({ error: 'missing_token' });
      return;
    }

    const found = await integrations.findByToken(token);
    if (!found) {
      res.status(401).json({ error: 'invalid_or_revoked_token' });
      return;
    }

    const missing = required.filter((s) => !found.parsedScopes.includes(s));
    if (missing.length > 0) {
      res.status(403).json({ error: 'insufficient_scope', required, missing });
      return;
    }

    req.userId = found.user_id;
    req.integration = { id: found.id, label: found.label, scopes: found.parsedScopes };
    await integrations.touchLastUsed(found.id);
    next();
  });
}
