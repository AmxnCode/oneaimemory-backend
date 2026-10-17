import { Router } from 'express';
import { z } from 'zod';
import { keyFingerprint, type DataKey } from '@oneconscious/shared';
import * as remoteAccess from '../repositories/remoteAccess.js';
import * as users from '../repositories/users.js';
import * as audit from '../repositories/audit.js';
import { wrapDataKey } from '../services/remoteKek.js';
import { requireUser } from '../middleware/auth.js';
import { HttpError, asyncRoute } from '../middleware/errorHandler.js';

/**
 * Opt-in for REMOTE (server-side decrypting) AI access — see
 * db/schema.sql's remote_access_grants comment for the security tradeoff.
 * Behind requireUser (the logged-in dashboard/desktop session), not an
 * integration token: this is an account-level decision, not something an AI
 * tool can flip on its own behalf.
 */
export const remoteAccessRouter = Router();
remoteAccessRouter.use(requireUser);

remoteAccessRouter.get('/status', asyncRoute(async (req, res) => {
  const grant = await remoteAccess.getGrant(req.userId!);
  res.json({ enabled: Boolean(grant?.enabled), enabledAt: grant?.enabled_at ?? null });
}));

const enableSchema = z.object({
  // Raw 32-byte data key, base64, sent exactly once over TLS on this explicit
  // opt-in action. Never persisted as-is — wrapped immediately below.
  dataKey: z.string().min(1),
});

remoteAccessRouter.post('/enable', asyncRoute(async (req, res) => {
  const body = enableSchema.parse(req.body);
  const raw = Buffer.from(body.dataKey, 'base64');
  if (raw.length !== 32) throw new HttpError(400, 'invalid_data_key', 'Expected a 32-byte key, base64-encoded.');

  const user = await users.findUserById(req.userId!);
  if (!user) throw new HttpError(404, 'user_not_found');

  const fingerprint = keyFingerprint(raw as DataKey);
  if (user.key_fingerprint && user.key_fingerprint !== fingerprint) {
    throw new HttpError(400, 'key_mismatch', 'This key does not match the one used on your other devices.');
  }

  const wrapped = wrapDataKey(req.userId!, raw as DataKey);
  await remoteAccess.enable(req.userId!, wrapped, 1);

  // Never log the raw key — only that the action happened.
  await audit.record({ userId: req.userId!, action: 'remote_access_enabled', ipAddress: req.ip });

  const grant = await remoteAccess.getGrant(req.userId!);
  res.json({ enabled: true, enabledAt: grant?.enabled_at ?? null });
}));

remoteAccessRouter.post('/disable', asyncRoute(async (req, res) => {
  await remoteAccess.disable(req.userId!);
  await audit.record({ userId: req.userId!, action: 'remote_access_disabled', ipAddress: req.ip });
  res.json({ enabled: false });
}));
