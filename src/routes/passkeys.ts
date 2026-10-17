import { Router } from 'express';
import { z } from 'zod';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { env } from '../config/env.js';
import * as passkeys from '../repositories/passkeys.js';
import * as users from '../repositories/users.js';
import * as refresh from '../repositories/refreshTokens.js';
import * as audit from '../repositories/audit.js';
import { signAccessToken, requireUser } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimiter.js';
import { HttpError, asyncRoute } from '../middleware/errorHandler.js';

/**
 * Passkey (WebAuthn) authentication.
 *
 * Two independent capabilities:
 *
 *  1. SIGN-IN — replaces the password. The server verifies a signature over a
 *     challenge it issued; there is no shared secret to phish or leak, and the
 *     browser binds the credential to this origin.
 *
 *  2. KEY UNWRAP — optional. If the authenticator supports the PRF extension,
 *     the client derives a KEK on-device, wraps the data key with it, and
 *     stores only the ciphertext here. The server never sees the PRF output or
 *     the data key, so end-to-end encryption is preserved while the user stops
 *     retyping the passphrase.
 *
 * The server treats the wrapped key as an opaque blob. It cannot open it, and
 * nothing in this file tries.
 */
export const passkeyRouter = Router();

/** Relying Party ID must be the site's registrable domain — never the origin. */
function rpConfig() {
  const origins = env.corsOrigins.length > 0 ? env.corsOrigins : ['http://localhost:5173'];
  const rpID = env.RP_ID || new URL(origins[0]!).hostname;
  return { rpID, rpName: 'OneConscious', expectedOrigins: origins };
}

const b64 = {
  toBuffer: (s: string) => Buffer.from(s, 'base64'),
  fromBuffer: (b: Buffer) => b.toString('base64'),
};

// --- registration (requires an existing session) ---------------------------

passkeyRouter.post('/register/options', requireUser, asyncRoute(async (req, res) => {
  const { rpID, rpName } = rpConfig();
  const user = (await users.findUserById(req.userId!))!;
  const existing = await passkeys.listForUser(req.userId!);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.email,
    userDisplayName: user.email,
    attestationType: 'none',
    // Prevents registering the same authenticator twice.
    excludeCredentials: existing.map((c) => ({
      id: c.credential_id,
      transports: c.transports ? (JSON.parse(c.transports) as never) : undefined,
    })),
    authenticatorSelection: {
      residentKey: 'required',      // discoverable, so sign-in needs no email
      userVerification: 'required', // biometric or PIN, not mere presence
    },
  });

  // Persist our own challenge rather than trusting the client to return it.
  const challenge = await passkeys.createChallenge('registration', req.userId!);
  res.json({ ...options, challenge });
}));

const registerVerifySchema = z.object({
  response: z.record(z.unknown()),
  challenge: z.string().min(16),
  deviceLabel: z.string().min(1).max(120).default('This device'),
  // Optional PRF-wrapped data key, produced client-side.
  prfSalt: z.string().max(200).optional(),
  wrappedKey: z.string().max(4000).optional(),
  wrappedKeyIv: z.string().max(200).optional(),
});

passkeyRouter.post('/register/verify', requireUser, asyncRoute(async (req, res) => {
  const body = registerVerifySchema.parse(req.body);
  const { rpID, expectedOrigins } = rpConfig();

  const consumed = await passkeys.consumeChallenge(body.challenge, 'registration');
  if (!consumed || consumed.userId !== req.userId!) {
    throw new HttpError(400, 'invalid_challenge', 'Challenge is unknown, expired, or already used.');
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response as never,
      expectedChallenge: body.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (err) {
    throw new HttpError(400, 'verification_failed', err instanceof Error ? err.message : undefined);
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new HttpError(400, 'verification_failed');
  }

  const { credential, credentialBackedUp } = verification.registrationInfo;

  if (await passkeys.findByCredentialId(credential.id)) {
    throw new HttpError(409, 'credential_already_registered');
  }

  const saved = await passkeys.saveCredential({
    userId: req.userId!,
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports as string[] | undefined,
    deviceLabel: body.deviceLabel,
    backedUp: credentialBackedUp,
    prfSalt: body.prfSalt ?? null,
    wrappedKey: body.wrappedKey ? b64.toBuffer(body.wrappedKey) : null,
    wrappedKeyIv: body.wrappedKeyIv ? b64.toBuffer(body.wrappedKeyIv) : null,
  });

  await audit.record({
    userId: req.userId!,
    action: 'passkey_registered',
    ipAddress: req.ip,
    details: { label: body.deviceLabel, keyWrapped: Boolean(body.wrappedKey) },
  });

  res.status(201).json({
    id: saved.id,
    deviceLabel: saved.device_label,
    canUnlock: Boolean(saved.wrapped_key),
  });
}));

// --- authentication (no session required) ----------------------------------

passkeyRouter.post('/login/options', authLimiter, asyncRoute(async (_req, res) => {
  const { rpID } = rpConfig();

  // Discoverable credentials: no allowList, so the request reveals nothing
  // about which accounts exist.
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
  });

  const challenge = await passkeys.createChallenge('authentication');
  res.json({ ...options, challenge });
}));

const loginVerifySchema = z.object({
  response: z.record(z.unknown()),
  challenge: z.string().min(16),
  deviceId: z.string().max(255).optional(),
});

passkeyRouter.post('/login/verify', authLimiter, asyncRoute(async (req, res) => {
  const body = loginVerifySchema.parse(req.body);
  const { rpID, expectedOrigins } = rpConfig();

  const consumed = await passkeys.consumeChallenge(body.challenge, 'authentication');
  if (!consumed) throw new HttpError(400, 'invalid_challenge');

  const credentialId = (body.response as { id?: string }).id;
  if (!credentialId) throw new HttpError(400, 'missing_credential_id');

  const stored = await passkeys.findByCredentialId(credentialId);
  if (!stored) throw new HttpError(401, 'unknown_credential');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body.response as never,
      expectedChallenge: body.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID,
      requireUserVerification: true,
      credential: {
        id: stored.credential_id,
        publicKey: new Uint8Array(stored.public_key),
        counter: stored.counter,
        transports: stored.transports ? (JSON.parse(stored.transports) as never) : undefined,
      },
    });
  } catch (err) {
    throw new HttpError(401, 'verification_failed', err instanceof Error ? err.message : undefined);
  }

  if (!verification.verified) throw new HttpError(401, 'verification_failed');

  // A counter that fails to advance suggests a cloned authenticator. Platform
  // authenticators often report 0 permanently, which is legitimate; only a
  // non-zero counter that stalls or regresses is a signal.
  const newCounter = verification.authenticationInfo.newCounter;
  if (stored.counter > 0 && newCounter <= stored.counter) {
    await audit.record({
      userId: stored.user_id,
      action: 'passkey_counter_regression',
      ipAddress: req.ip,
      details: { stored: stored.counter, presented: newCounter },
    });
    throw new HttpError(401, 'possible_cloned_credential');
  }
  await passkeys.updateCounter(stored.id, newCounter);

  const user = await users.findUserById(stored.user_id);
  if (!user || !user.is_active) throw new HttpError(403, 'account_disabled');

  await audit.record({ userId: user.id, action: 'login_passkey', ipAddress: req.ip });

  res.json({
    userId: user.id,
    email: user.email,
    dataKeySalt: user.data_key_salt,
    keyFingerprint: user.key_fingerprint,
    accessToken: signAccessToken(user.id, body.deviceId),
    refreshToken: await refresh.issueRefreshToken(user.id, body.deviceId),
    // Opaque to the server; only a client holding the PRF secret can open it.
    prfSalt: stored.prf_salt,
    wrappedKey: stored.wrapped_key ? b64.fromBuffer(stored.wrapped_key) : null,
    wrappedKeyIv: stored.wrapped_key_iv ? b64.fromBuffer(stored.wrapped_key_iv) : null,
  });
}));

// --- management -------------------------------------------------------------

passkeyRouter.get('/', requireUser, asyncRoute(async (req, res) => {
  const list = await passkeys.listForUser(req.userId!);
  res.json({
    passkeys: list.map((c) => ({
      id: c.id,
      deviceLabel: c.device_label,
      createdAt: c.created_at,
      lastUsedAt: c.last_used_at,
      backedUp: c.backed_up === 1,
      canUnlock: Boolean(c.wrapped_key),
    })),
  });
}));

/** Attach a wrapped key to an existing credential (e.g. PRF enabled later). */
passkeyRouter.post('/:id/wrapped-key', requireUser, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const body = z
    .object({
      prfSalt: z.string().min(8).max(200),
      wrappedKey: z.string().min(8).max(4000),
      wrappedKeyIv: z.string().min(8).max(200),
    })
    .parse(req.body);

  const ok = await passkeys.setWrappedKey(
    req.userId!,
    id,
    body.prfSalt,
    b64.toBuffer(body.wrappedKey),
    b64.toBuffer(body.wrappedKeyIv),
  );
  if (!ok) throw new HttpError(404, 'passkey_not_found');

  await audit.record({ userId: req.userId!, action: 'passkey_key_wrapped', ipAddress: req.ip, details: { id } });
  res.json({ ok: true });
}));

passkeyRouter.delete('/:id', requireUser, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) throw new HttpError(400, 'invalid_id');
  if (!(await passkeys.deleteCredential(req.userId!, id))) throw new HttpError(404, 'passkey_not_found');

  await audit.record({ userId: req.userId!, action: 'passkey_removed', ipAddress: req.ip, details: { id } });
  res.json({ ok: true });
}));
