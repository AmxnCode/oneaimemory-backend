import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID, randomBytes } from 'node:crypto';
import { rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deriveKey, keyFingerprint, encryptEvent, type ConsciousnessEvent, type DataKey } from '@oneconscious/shared';

const testDir = mkdtempSync(join(tmpdir(), 'onecon-remote-test-'));
process.env.DATABASE_PATH = join(testDir, 'test.db');
process.env.JWT_SECRET = randomBytes(32).toString('base64');
process.env.REMOTE_ACCESS_KEK = randomBytes(32).toString('base64');
process.env.NODE_ENV = 'test';

const { wrapDataKey, unwrapDataKey } = await import('../services/remoteKek.js');
const { createApp } = await import('../app.js');
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

interface Res<T = Record<string, unknown>> {
  status: number;
  body: T;
}

async function call<T = Record<string, unknown>>(
  path: string,
  opts: { method?: string; body?: unknown; token?: string; headers?: Record<string, string> } = {},
): Promise<Res<T>> {
  const res = await fetch(base + path, {
    method: opts.method ?? 'GET',
    headers: {
      'content-type': 'application/json',
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...opts.headers,
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as T };
}

const password = 'a-long-enough-password';
const passphrase = 'a-totally-different-passphrase';
let uniq = 0;
const newEmail = () => `remote${Date.now()}-${uniq++}@example.com`;

async function makeUser() {
  const email = newEmail();
  const deviceId = `dev-${randomUUID()}`;
  const { body } = await call<{ accessToken: string; refreshToken: string; dataKeySalt: string; userId: number }>(
    '/api/auth/register',
    { method: 'POST', body: { email, password, deviceId } },
  );
  await call('/api/sync/devices/register', {
    method: 'POST',
    token: body.accessToken,
    body: { deviceId, deviceName: 'Test Mac', deviceType: 'mac' },
  });
  const key = deriveKey(passphrase, body.dataKeySalt);
  return { email, deviceId, key, ...body };
}

async function makeIntegration(accessToken: string, scopes: string[]) {
  const { body } = await call<{ id: number; token: string }>('/api/account/integrations', {
    method: 'POST',
    token: accessToken,
    body: { label: 'test-remote', scopes },
  });
  return body;
}

async function syncSearchEvent(accessToken: string, deviceId: string, key: DataKey, query: string) {
  const event: ConsciousnessEvent = {
    eventUuid: randomUUID(),
    deviceId,
    type: 'search',
    timestamp: new Date().toISOString(),
    payload: { query, engine: 'google' },
  };
  const envelope = encryptEvent(event, key);
  await call('/api/sync/events', { method: 'POST', token: accessToken, body: { events: [envelope] } });
}

describe('remoteKek wrap/unwrap', () => {
  it('round-trips a data key', () => {
    const key = deriveKey('some passphrase', Buffer.from(randomBytes(16)).toString('base64'));
    const wrapped = wrapDataKey(42, key);
    const unwrapped = unwrapDataKey(42, {
      wrapped_data_key: wrapped.ciphertext,
      wrapped_data_key_iv: wrapped.iv,
      wrapped_data_key_auth_tag: wrapped.authTag,
    });
    expect(Buffer.compare(unwrapped, key)).toBe(0);
  });

  it('fails to unwrap under a different userId (AAD binding)', () => {
    const key = deriveKey('some passphrase', Buffer.from(randomBytes(16)).toString('base64'));
    const wrapped = wrapDataKey(42, key);
    expect(() =>
      unwrapDataKey(43, {
        wrapped_data_key: wrapped.ciphertext,
        wrapped_data_key_iv: wrapped.iv,
        wrapped_data_key_auth_tag: wrapped.authTag,
      }),
    ).toThrow();
  });
});

describe('remote access opt-in', () => {
  it('is disabled by default', async () => {
    const u = await makeUser();
    const status = await call<{ enabled: boolean }>('/api/account/remote-access/status', { token: u.accessToken });
    expect(status.body.enabled).toBe(false);
  });

  it('enables, then disables', async () => {
    const u = await makeUser();
    const enable = await call<{ enabled: boolean }>('/api/account/remote-access/enable', {
      method: 'POST',
      token: u.accessToken,
      body: { dataKey: u.key.toString('base64') },
    });
    expect(enable.status).toBe(200);
    expect(enable.body.enabled).toBe(true);

    const status = await call<{ enabled: boolean }>('/api/account/remote-access/status', { token: u.accessToken });
    expect(status.body.enabled).toBe(true);

    const disable = await call<{ enabled: boolean }>('/api/account/remote-access/disable', {
      method: 'POST',
      token: u.accessToken,
    });
    expect(disable.body.enabled).toBe(false);
  });

  it('rejects a key that does not match the fingerprint already on file', async () => {
    const u = await makeUser();
    await call('/api/auth/key-fingerprint', {
      method: 'POST',
      token: u.accessToken,
      body: { fingerprint: keyFingerprint(u.key) },
    });

    const wrongKey = deriveKey('a-completely-different-passphrase', randomBytes(16).toString('base64'));
    const enable = await call('/api/account/remote-access/enable', {
      method: 'POST',
      token: u.accessToken,
      body: { dataKey: wrongKey.toString('base64') },
    });
    expect(enable.status).toBe(400);
  });

  it('requires a logged-in session, not an integration token', async () => {
    const u = await makeUser();
    const it = await makeIntegration(u.accessToken, ['remote:mcp', 'devices:read']);
    const status = await call('/api/account/remote-access/status', { token: it.token });
    expect(status.status).toBe(401);
  });
});

describe('/api/remote/* gate', () => {
  it('403s when remote access is not enabled, even with a valid remote:mcp token', async () => {
    const u = await makeUser();
    const it = await makeIntegration(u.accessToken, ['remote:mcp', 'consciousness:summary']);
    const res = await call('/api/remote/consciousness', { token: it.token });
    expect(res.status).toBe(403);
  });

  it('403s for a local-only token even when remote access is enabled', async () => {
    const u = await makeUser();
    await call('/api/account/remote-access/enable', {
      method: 'POST',
      token: u.accessToken,
      body: { dataKey: u.key.toString('base64') },
    });
    // No 'remote:mcp' scope — this is what a locally-issued desktop token looks like.
    const it = await makeIntegration(u.accessToken, ['consciousness:summary']);
    const res = await call<{ missing: string[] }>('/api/remote/consciousness', { token: it.token });
    expect(res.status).toBe(403);
    expect(res.body.missing).toContain('remote:mcp');
  });

  it('decrypts real activity once enabled, and stops immediately once disabled', async () => {
    const u = await makeUser();
    await syncSearchEvent(u.accessToken, u.deviceId, u.key, 'golden retriever recall training');

    await call('/api/account/remote-access/enable', {
      method: 'POST',
      token: u.accessToken,
      body: { dataKey: u.key.toString('base64') },
    });
    const it = await makeIntegration(u.accessToken, ['remote:mcp', 'consciousness:summary', 'activity:search']);

    const summary = await call<{ recentSearches: string[]; eventCount: number }>('/api/remote/consciousness', {
      token: it.token,
    });
    expect(summary.status).toBe(200);
    expect(summary.body.eventCount).toBe(1);
    expect(summary.body.recentSearches[0]).toContain('golden retriever');

    const search = await call<{ events: Array<{ payload: { query: string } }> }>(
      '/api/remote/search?query=retriever',
      { token: it.token },
    );
    expect(search.status).toBe(200);
    expect(search.body.events).toHaveLength(1);
    expect(search.body.events[0]!.payload.query).toContain('golden retriever');

    await call('/api/account/remote-access/disable', { method: 'POST', token: u.accessToken });

    const after = await call('/api/remote/consciousness', { token: it.token });
    expect(after.status).toBe(403);
  });

  it('/whoami works with any valid integration token, no remote-access gate', async () => {
    const u = await makeUser();
    const it = await makeIntegration(u.accessToken, ['consciousness:summary']);
    const res = await call<{ userId: number }>('/api/remote/whoami', { token: it.token });
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe(u.userId);
  });
});
