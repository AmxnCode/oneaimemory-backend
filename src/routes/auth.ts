import { Router } from 'express';
import { z } from 'zod';
import { generateSalt } from '@oneconscious/shared';
import * as users from '../repositories/users.js';
import * as refresh from '../repositories/refreshTokens.js';
import * as audit from '../repositories/audit.js';
import { hashPassword, verifyPassword } from '../services/passwords.js';
import { signAccessToken, requireUser } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimiter.js';
import { HttpError, asyncRoute } from '../middleware/errorHandler.js';

export const authRouter = Router();

const credentials = z.object({
  email: z.string().email().max(255),
  password: z.string().min(10).max(200),
  deviceId: z.string().max(255).optional(),
});

authRouter.post('/register', authLimiter, asyncRoute(async (req, res) => {
  const { email, password, deviceId } = credentials.parse(req.body);

  if (await users.findUserByEmail(email)) {
    throw new HttpError(409, 'email_taken');
  }

  const { hash, salt } = hashPassword(password);
  const user = await users.createUser({
    email,
    passwordHash: hash,
    passwordSalt: salt,
    // Salt for the CLIENT-side data key. Not secret; the passphrase that
    // combines with it never reaches this server.
    dataKeySalt: generateSalt(),
  });

  await audit.record({ userId: user.id, action: 'register', ipAddress: req.ip });

  res.status(201).json({
    userId: user.id,
    email: user.email,
    dataKeySalt: user.data_key_salt,
    accessToken: signAccessToken(user.id, deviceId),
    refreshToken: await refresh.issueRefreshToken(user.id, deviceId),
  });
}));

authRouter.post('/login', authLimiter, asyncRoute(async (req, res) => {
  const { email, password, deviceId } = credentials.parse(req.body);
  const user = await users.findUserByEmail(email);

  // Uniform failure for unknown-email and wrong-password so the response does
  // not reveal which accounts exist.
  if (!user || !verifyPassword(password, user.password_hash, user.password_salt)) {
    throw new HttpError(401, 'invalid_credentials');
  }
  if (!user.is_active) throw new HttpError(403, 'account_disabled');

  await audit.record({ userId: user.id, action: 'login', ipAddress: req.ip });

  res.json({
    userId: user.id,
    email: user.email,
    dataKeySalt: user.data_key_salt,
    keyFingerprint: user.key_fingerprint,
    accessToken: signAccessToken(user.id, deviceId),
    refreshToken: await refresh.issueRefreshToken(user.id, deviceId),
  });
}));

authRouter.post('/refresh', asyncRoute(async (req, res) => {
  const { refreshToken } = z.object({ refreshToken: z.string().min(10) }).parse(req.body);
  const row = await refresh.consumeRefreshToken(refreshToken);
  if (!row) throw new HttpError(401, 'invalid_refresh_token');

  res.json({
    accessToken: signAccessToken(row.user_id, row.device_id ?? undefined),
    refreshToken: await refresh.issueRefreshToken(row.user_id, row.device_id ?? undefined),
  });
}));

authRouter.post('/logout', requireUser, asyncRoute(async (req, res) => {
  await refresh.revokeAllForUser(req.userId!);
  await audit.record({ userId: req.userId!, action: 'logout', ipAddress: req.ip });
  res.json({ ok: true });
}));

/**
 * Record the client's data-key fingerprint. Lets other devices verify the user
 * typed the same passphrase before they download events they cannot decrypt.
 */
authRouter.post('/key-fingerprint', requireUser, asyncRoute(async (req, res) => {
  const { fingerprint } = z.object({ fingerprint: z.string().min(8).max(64) }).parse(req.body);
  const user = (await users.findUserById(req.userId!))!;

  if (user.key_fingerprint && user.key_fingerprint !== fingerprint) {
    throw new HttpError(409, 'key_fingerprint_mismatch',
      'This passphrase differs from the one used on your other devices. ' +
      'Events encrypted with the other key would not be readable here.');
  }
  if (!user.key_fingerprint) await users.setKeyFingerprint(req.userId!, fingerprint);
  res.json({ ok: true, fingerprint });
}));

authRouter.get('/me', requireUser, asyncRoute(async (req, res) => {
  const user = await users.findUserById(req.userId!);
  if (!user) throw new HttpError(404, 'user_not_found');
  res.json({
    userId: user.id,
    email: user.email,
    dataKeySalt: user.data_key_salt,
    keyFingerprint: user.key_fingerprint,
  });
}));
