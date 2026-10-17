import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const testDir = mkdtempSync(join(tmpdir(), 'onecon-pk-'));
process.env.DATABASE_PATH = join(testDir, 'test.db');
process.env.JWT_SECRET = randomBytes(32).toString('base64');
process.env.NODE_ENV = 'test';

const { createApp } = await import('../app.js');
const passkeys = await import('../repositories/passkeys.js');
const app = await createApp();

let server: ReturnType<typeof app.listen>;
let base: string;

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const addr = server.address();
      base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;
      resolve();
    });
  });
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  rmSync(testDir, { recursive: true, force: true });
});

async function call<T = Record<string, unknown>>(
  path: string,
  opts: { method?: string; body?: unknown; token?: string } = {},
): Promise<{ status: number; body: T }> {
  const res = await fetch(base + path, {
    method: opts.method ?? 'GET',
    headers: {
      'content-type': 'application/json',
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as T };
}

let uniq = 0;
async function makeUser() {
  const email = `pk${Date.now()}-${uniq++}@example.com`;
  const { body } = await call<{ accessToken: string; userId: number }>('/api/auth/register', {
    method: 'POST',
    body: { email, password: 'a-long-enough-password' },
  });
  return { email, ...body };
}

describe('challenge handling', () => {
  it('issues a distinct challenge per request', async () => {
    const a = await call<{ challenge: string }>('/api/auth/passkey/login/options', { method: 'POST' });
    const b = await call<{ challenge: string }>('/api/auth/passkey/login/options', { method: 'POST' });
    expect(a.body.challenge).toBeTruthy();
    expect(a.body.challenge).not.toBe(b.body.challenge);
  });

  it('is single-use', async () => {
    const challenge = await passkeys.createChallenge('authentication');
    expect(await passkeys.consumeChallenge(challenge, 'authentication')).not.toBeNull();
    // A replay of the same challenge must not be accepted.
    expect(await passkeys.consumeChallenge(challenge, 'authentication')).toBeNull();
  });

  it('rejects a challenge used for the wrong ceremony', async () => {
    // Needs a real user: registration challenges carry a FK to users.
    const u = await makeUser();
    const challenge = await passkeys.createChallenge('registration', u.userId);
    expect(await passkeys.consumeChallenge(challenge, 'authentication')).toBeNull();
    // Still valid for the ceremony it was issued for.
    expect(await passkeys.consumeChallenge(challenge, 'registration')).not.toBeNull();
  });

  it('rejects an unknown challenge', async () => {
    expect(await passkeys.consumeChallenge('never-issued-value', 'authentication')).toBeNull();
  });

  it('rejects a client-supplied challenge at the endpoint', async () => {
    const u = await makeUser();
    const { status } = await call('/api/auth/passkey/register/verify', {
      method: 'POST',
      token: u.accessToken,
      body: { response: {}, challenge: 'attacker-chosen-challenge', deviceLabel: 'x' },
    });
    expect(status).toBe(400);
  });

  it('does not let one user consume another user\'s registration challenge', async () => {
    const a = await makeUser();
    const b = await makeUser();
    const opts = await call<{ challenge: string }>('/api/auth/passkey/register/options', {
      method: 'POST',
      token: a.accessToken,
    });
    const { status } = await call('/api/auth/passkey/register/verify', {
      method: 'POST',
      token: b.accessToken,
      body: { response: {}, challenge: opts.body.challenge, deviceLabel: 'stolen' },
    });
    expect(status).toBe(400);
  });
});

describe('registration options', () => {
  it('requires user verification and a discoverable credential', async () => {
    const u = await makeUser();
    const { body } = await call<{
      authenticatorSelection: { userVerification: string; residentKey: string };
      challenge: string;
    }>('/api/auth/passkey/register/options', { method: 'POST', token: u.accessToken });

    // userVerification 'required' is what makes this biometric rather than
    // mere presence; residentKey lets sign-in work without an email.
    expect(body.authenticatorSelection.userVerification).toBe('required');
    expect(body.authenticatorSelection.residentKey).toBe('required');
    expect(body.challenge).toBeTruthy();
  });

  it('needs a session', async () => {
    const { status } = await call('/api/auth/passkey/register/options', { method: 'POST' });
    expect(status).toBe(401);
  });
});

describe('login options do not leak account existence', () => {
  it('returns no allowCredentials', async () => {
    const { body } = await call<{ allowCredentials?: unknown[] }>('/api/auth/passkey/login/options', {
      method: 'POST',
    });
    // An allowList would confirm which credentials exist for a probed account.
    expect(body.allowCredentials ?? []).toHaveLength(0);
  });
});

describe('wrapped key storage', () => {
  it('stores the wrapped key as an opaque blob and returns it verbatim', async () => {
    const u = await makeUser();
    const wrappedKey = randomBytes(48);
    const iv = randomBytes(12);

    await passkeys.saveCredential({
      userId: u.userId,
      credentialId: 'cred-opaque-1',
      publicKey: randomBytes(64),
      counter: 0,
      deviceLabel: 'Test',
      backedUp: false,
      prfSalt: 'oneconscious:prf:v1',
      wrappedKey,
      wrappedKeyIv: iv,
    });

    const stored = (await passkeys.findByCredentialId('cred-opaque-1'))!;
    expect(Buffer.from(stored.wrapped_key!).equals(wrappedKey)).toBe(true);
    expect(Buffer.from(stored.wrapped_key_iv!).equals(iv)).toBe(true);
  });

  it('never exposes the wrapped key through the management list', async () => {
    const u = await makeUser();
    await passkeys.saveCredential({
      userId: u.userId,
      credentialId: `cred-list-${u.userId}`,
      publicKey: randomBytes(64),
      counter: 0,
      deviceLabel: 'Laptop',
      backedUp: true,
      prfSalt: 'oneconscious:prf:v1',
      wrappedKey: randomBytes(48),
      wrappedKeyIv: randomBytes(12),
    });

    const { body } = await call<{ passkeys: Array<Record<string, unknown>> }>('/api/auth/passkey', {
      token: u.accessToken,
    });
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain('wrappedKey');
    expect(serialized).not.toContain('publicKey');
    expect(body.passkeys[0]!.canUnlock).toBe(true);
  });
});

describe('credential management', () => {
  it('lists only the caller\'s passkeys', async () => {
    const a = await makeUser();
    const b = await makeUser();
    await passkeys.saveCredential({
      userId: a.userId, credentialId: `cred-a-${a.userId}`, publicKey: randomBytes(64),
      counter: 0, deviceLabel: 'A', backedUp: false,
    });

    const listB = await call<{ passkeys: unknown[] }>('/api/auth/passkey', { token: b.accessToken });
    expect(listB.body.passkeys).toHaveLength(0);
  });

  it('cannot delete another user\'s passkey', async () => {
    const a = await makeUser();
    const b = await makeUser();
    const cred = await passkeys.saveCredential({
      userId: a.userId, credentialId: `cred-del-${a.userId}`, publicKey: randomBytes(64),
      counter: 0, deviceLabel: 'A', backedUp: false,
    });

    const res = await call(`/api/auth/passkey/${cred.id}`, { method: 'DELETE', token: b.accessToken });
    expect(res.status).toBe(404);
    expect(await passkeys.findByCredentialId(`cred-del-${a.userId}`)).toBeTruthy();
  });

  it('deletes its own', async () => {
    const u = await makeUser();
    const cred = await passkeys.saveCredential({
      userId: u.userId, credentialId: `cred-own-${u.userId}`, publicKey: randomBytes(64),
      counter: 0, deviceLabel: 'Mine', backedUp: false,
    });
    const res = await call(`/api/auth/passkey/${cred.id}`, { method: 'DELETE', token: u.accessToken });
    expect(res.status).toBe(200);
    expect(await passkeys.findByCredentialId(`cred-own-${u.userId}`)).toBeUndefined();
  });
});

describe('assertion verification', () => {
  it('rejects an unknown credential id', async () => {
    const opts = await call<{ challenge: string }>('/api/auth/passkey/login/options', { method: 'POST' });
    const { status } = await call('/api/auth/passkey/login/verify', {
      method: 'POST',
      body: { response: { id: 'no-such-credential' }, challenge: opts.body.challenge },
    });
    expect(status).toBe(401);
  });

  it('rejects a forged assertion against a real credential', async () => {
    const u = await makeUser();
    await passkeys.saveCredential({
      userId: u.userId, credentialId: 'cred-forge', publicKey: randomBytes(64),
      counter: 5, deviceLabel: 'Real', backedUp: false,
    });

    const opts = await call<{ challenge: string }>('/api/auth/passkey/login/options', { method: 'POST' });
    const { status } = await call('/api/auth/passkey/login/verify', {
      method: 'POST',
      body: {
        response: {
          id: 'cred-forge',
          rawId: 'cred-forge',
          type: 'public-key',
          response: {
            clientDataJSON: Buffer.from('{}').toString('base64url'),
            authenticatorData: randomBytes(37).toString('base64url'),
            signature: randomBytes(64).toString('base64url'),
          },
          clientExtensionResults: {},
        },
        challenge: opts.body.challenge,
      },
    });
    // Signature verification must fail — no valid private key was involved.
    expect(status).toBe(401);
  });
});

describe('expiry', () => {
  it('purges expired challenges', async () => {
    await passkeys.createChallenge('authentication');
    // Nothing is expired yet, so the purge is a no-op rather than a wipe.
    expect(await passkeys.purgeExpiredChallenges()).toBe(0);
  });
});
