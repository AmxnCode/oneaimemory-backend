import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID, randomBytes } from 'node:crypto';
import { rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Point the server at a throwaway database before any module reads env.
const testDir = mkdtempSync(join(tmpdir(), 'onecon-test-'));
process.env.DATABASE_PATH = join(testDir, 'test.db');
process.env.JWT_SECRET = randomBytes(32).toString('base64');
process.env.NODE_ENV = 'test';
// PORT is deliberately not set: createApp() does not bind, and the suite
// listens on an ephemeral port below. dotenv does not override vars already
// present, so DATABASE_PATH above wins over backend/.env.

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
let uniq = 0;
const newEmail = () => `user${Date.now()}-${uniq++}@example.com`;

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
  return { email, deviceId, ...body };
}

function envelope(deviceId: string, over: Record<string, unknown> = {}) {
  return {
    eventUuid: randomUUID(),
    deviceId,
    type: 'browsing',
    timestamp: new Date().toISOString(),
    ciphertext: randomBytes(48).toString('base64'),
    iv: randomBytes(12).toString('base64'),
    authTag: randomBytes(16).toString('base64'),
    ...over,
  };
}

describe('health', () => {
  it('reports ok', async () => {
    const { status, body } = await call<{ status: string }>('/health');
    expect(status).toBe(200);
    expect(body.status).toBe('ok');
  });
});

describe('auth', () => {
  it('registers and returns a data key salt the server cannot use', async () => {
    const u = await makeUser();
    expect(u.dataKeySalt).toBeTruthy();
    expect(u.accessToken).toBeTruthy();
  });

  it('rejects a duplicate email', async () => {
    const u = await makeUser();
    const { status } = await call('/api/auth/register', {
      method: 'POST', body: { email: u.email, password },
    });
    expect(status).toBe(409);
  });

  it('rejects a short password', async () => {
    const { status } = await call('/api/auth/register', {
      method: 'POST', body: { email: newEmail(), password: 'short' },
    });
    expect(status).toBe(400);
  });

  it('gives an identical error for unknown email and wrong password', async () => {
    const u = await makeUser();
    const wrongPass = await call('/api/auth/login', {
      method: 'POST', body: { email: u.email, password: 'wrong-password-here' },
    });
    const unknown = await call('/api/auth/login', {
      method: 'POST', body: { email: newEmail(), password },
    });
    expect(wrongPass.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrongPass.body).toEqual(unknown.body);
  });

  it('rotates refresh tokens and refuses reuse', async () => {
    const u = await makeUser();
    const first = await call<{ refreshToken: string }>('/api/auth/refresh', {
      method: 'POST', body: { refreshToken: u.refreshToken },
    });
    expect(first.status).toBe(200);

    const replay = await call('/api/auth/refresh', {
      method: 'POST', body: { refreshToken: u.refreshToken },
    });
    expect(replay.status).toBe(401);
  });

  it('rejects requests with no or invalid token', async () => {
    expect((await call('/api/auth/me')).status).toBe(401);
    expect((await call('/api/auth/me', { token: 'garbage' })).status).toBe(401);
  });

  it('refuses a mismatched key fingerprint', async () => {
    const u = await makeUser();
    const ok = await call('/api/auth/key-fingerprint', {
      method: 'POST', token: u.accessToken, body: { fingerprint: 'fingerprint-aaa' },
    });
    expect(ok.status).toBe(200);

    const mismatch = await call('/api/auth/key-fingerprint', {
      method: 'POST', token: u.accessToken, body: { fingerprint: 'fingerprint-bbb' },
    });
    expect(mismatch.status).toBe(409);
  });
});

describe('sync', () => {
  it('accepts a batch and is idempotent on replay', async () => {
    const u = await makeUser();
    const batch = [envelope(u.deviceId), envelope(u.deviceId)];

    const first = await call<{ inserted: number; duplicates: number }>('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events: batch },
    });
    expect(first.body.inserted).toBe(2);

    const replay = await call<{ inserted: number; duplicates: number }>('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events: batch },
    });
    expect(replay.body.inserted).toBe(0);
    expect(replay.body.duplicates).toBe(2);
  });

  it('rejects events from an unregistered device', async () => {
    const u = await makeUser();
    const { status } = await call('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events: [envelope('never-registered')] },
    });
    expect(status).toBe(400);
  });

  it('rejects an oversized batch', async () => {
    const u = await makeUser();
    const big = Array.from({ length: 501 }, () => envelope(u.deviceId));
    const { status } = await call('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events: big },
    });
    expect(status).toBe(400);
  });

  it('refuses to re-home another user\'s device id', async () => {
    const a = await makeUser();
    const b = await makeUser();
    const { status } = await call('/api/sync/devices/register', {
      method: 'POST', token: b.accessToken,
      body: { deviceId: a.deviceId, deviceName: 'Stolen', deviceType: 'mac' },
    });
    expect(status).toBe(409);
  });

  it('accepts and discards while collection is paused', async () => {
    const u = await makeUser();
    await call('/api/account/preferences', {
      method: 'PATCH', token: u.accessToken, body: { collection_enabled: false },
    });
    const { body } = await call<{ paused: boolean; inserted: number }>('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events: [envelope(u.deviceId)] },
    });
    expect(body.paused).toBe(true);
    expect(body.inserted).toBe(0);
  });
});

describe('isolation between users', () => {
  it('never returns another user\'s events', async () => {
    const a = await makeUser();
    const b = await makeUser();

    await call('/api/sync/events', {
      method: 'POST', token: a.accessToken, body: { events: [envelope(a.deviceId)] },
    });

    const bView = await call<{ events: unknown[] }>('/api/sync/events?limit=100', {
      token: b.accessToken,
    });
    expect(bView.body.events).toHaveLength(0);
  });

  it('cannot delete another user\'s events', async () => {
    const a = await makeUser();
    const b = await makeUser();
    const ev = envelope(a.deviceId);

    await call('/api/sync/events', {
      method: 'POST', token: a.accessToken, body: { events: [ev] },
    });

    const del = await call<{ deleted: number }>('/api/account/events', {
      method: 'DELETE', token: b.accessToken, body: { eventUuids: [ev.eventUuid] },
    });
    expect(del.body.deleted).toBe(0);

    const stillThere = await call<{ events: unknown[] }>('/api/sync/events?limit=10', {
      token: a.accessToken,
    });
    expect(stillThere.body.events).toHaveLength(1);
  });
});

describe('integration tokens and scopes', () => {
  it('enforces scopes per credential', async () => {
    const u = await makeUser();
    const limited = await call<{ token: string }>('/api/account/integrations', {
      method: 'POST', token: u.accessToken,
      body: { label: 'summary only', scopes: ['consciousness:summary'] },
    });

    const summary = await call('/api/consciousness/summary', { token: limited.body.token });
    expect(summary.status).toBe(200);

    const events = await call<{ missing: string[] }>('/api/consciousness/events', {
      token: limited.body.token,
    });
    expect(events.status).toBe(403);
    expect(events.body.missing).toContain('activity:read');
  });

  it('stops working once revoked', async () => {
    const u = await makeUser();
    const created = await call<{ id: number; token: string }>('/api/account/integrations', {
      method: 'POST', token: u.accessToken,
      body: { label: 'temp', scopes: ['consciousness:summary'] },
    });
    expect((await call('/api/consciousness/summary', { token: created.body.token })).status).toBe(200);

    await call(`/api/account/integrations/${created.body.id}`, {
      method: 'DELETE', token: u.accessToken,
    });
    expect((await call('/api/consciousness/summary', { token: created.body.token })).status).toBe(401);
  });

  it('returns the token exactly once', async () => {
    const u = await makeUser();
    await call('/api/account/integrations', {
      method: 'POST', token: u.accessToken,
      body: { label: 'x', scopes: ['activity:read'] },
    });
    const list = await call<{ integrations: Array<Record<string, unknown>> }>(
      '/api/account/integrations', { token: u.accessToken },
    );
    expect(JSON.stringify(list.body)).not.toContain('onecon_');
  });

  it('does not accept a user session token as an integration credential', async () => {
    const u = await makeUser();
    const { status } = await call('/api/consciousness/summary', { token: u.accessToken });
    expect(status).toBe(401);
  });
});

describe('audit log', () => {
  it('records AI access and marks the model claim unverified', async () => {
    const u = await makeUser();
    const it = await call<{ token: string }>('/api/account/integrations', {
      method: 'POST', token: u.accessToken,
      body: { label: 'Claude', scopes: ['consciousness:summary'] },
    });

    await call('/api/consciousness/summary', {
      token: it.body.token,
      headers: { 'x-ai-model': 'definitely-not-really-verified' },
    });

    const audit = await call<{ entries: Array<Record<string, unknown>> }>('/api/account/audit', {
      token: u.accessToken,
    });
    const entry = audit.body.entries.find((e) => e.action === 'ai_read_summary');
    expect(entry).toBeTruthy();
    expect(entry!.claimedAiModel).toBe('definitely-not-really-verified');
    expect(entry!.claimedAiModelVerified).toBe(false);
  });
});

describe('server blindness', () => {
  it('stores and returns only ciphertext', async () => {
    const u = await makeUser();
    const ev = envelope(u.deviceId);
    await call('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events: [ev] },
    });

    const page = await call<{ events: Array<Record<string, string>> }>('/api/sync/events?limit=10', {
      token: u.accessToken,
    });
    const returned = page.body.events[0]!;
    expect(returned.ciphertext).toBe(ev.ciphertext);
    // No decrypted field ever appears.
    expect(returned).not.toHaveProperty('payload');
  });

  it('exports encrypted events plus the salt, never plaintext', async () => {
    const u = await makeUser();
    await call('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events: [envelope(u.deviceId)] },
    });
    const exported = await call<{ events: unknown[]; dataKeySalt: string; encryption: string }>(
      '/api/account/export', { token: u.accessToken },
    );
    expect(exported.body.events).toHaveLength(1);
    expect(exported.body.dataKeySalt).toBeTruthy();
    expect(exported.body.encryption).toContain('AES-256-GCM');
  });
});

describe('pagination', () => {
  it('pages with a stable keyset cursor and no overlap', async () => {
    const u = await makeUser();
    const now = Date.now();
    const events = Array.from({ length: 25 }, (_, i) =>
      envelope(u.deviceId, { timestamp: new Date(now - i * 60_000).toISOString() }),
    );
    await call('/api/sync/events', {
      method: 'POST', token: u.accessToken, body: { events },
    });

    const seen = new Set<string>();
    let cursor: string | null = null;
    let pages = 0;
    do {
      const q: string = `/api/sync/events?limit=10${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
      const page = await call<{ events: Array<{ eventUuid: string }>; nextCursor: string | null }>(q, {
        token: u.accessToken,
      });
      page.body.events.forEach((e) => seen.add(e.eventUuid));
      cursor = page.body.nextCursor;
      pages++;
    } while (cursor && pages < 10);

    expect(seen.size).toBe(25);
  });
});

describe('validation', () => {
  it('rejects an unknown event type', async () => {
    const u = await makeUser();
    const { status } = await call('/api/sync/events', {
      method: 'POST', token: u.accessToken,
      body: { events: [envelope(u.deviceId, { type: 'keylog' })] },
    });
    expect(status).toBe(400);
  });

  it('rejects a non-uuid event id', async () => {
    const u = await makeUser();
    const { status } = await call('/api/sync/events', {
      method: 'POST', token: u.accessToken,
      body: { events: [envelope(u.deviceId, { eventUuid: 'nope' })] },
    });
    expect(status).toBe(400);
  });

  it('404s an unknown route', async () => {
    expect((await call('/api/nope')).status).toBe(404);
  });
});

describe('chat', () => {
  it('creates a session, appends messages, and returns them in order', async () => {
    const u = await makeUser();

    const created = await call<{ id: number; title: string; kind: string }>('/api/chat/sessions', {
      method: 'POST', token: u.accessToken, body: { title: 'Trip planning', kind: 'text' },
    });
    expect(created.status).toBe(201);
    expect(created.body.title).toBe('Trip planning');
    expect(created.body.kind).toBe('text');

    const sessionId = created.body.id;
    await call(`/api/chat/sessions/${sessionId}/messages`, {
      method: 'POST', token: u.accessToken, body: { role: 'user', content: 'Where should I go?' },
    });
    await call(`/api/chat/sessions/${sessionId}/messages`, {
      method: 'POST', token: u.accessToken, body: { role: 'assistant', content: 'How about Kyoto?' },
    });

    const fetched = await call<{ messages: { role: string; content: string }[] }>(
      `/api/chat/sessions/${sessionId}`,
      { token: u.accessToken },
    );
    expect(fetched.status).toBe(200);
    expect(fetched.body.messages.map((m) => m.role)).toEqual(['user', 'assistant']);
    expect(fetched.body.messages[1]!.content).toBe('How about Kyoto?');
  });

  it('defaults an untitled session to "New chat"', async () => {
    const u = await makeUser();
    const created = await call<{ title: string }>('/api/chat/sessions', {
      method: 'POST', token: u.accessToken, body: {},
    });
    expect(created.body.title).toBe('New chat');
  });

  it('lists sessions most-recently-active first', async () => {
    const u = await makeUser();
    const first = await call<{ id: number }>('/api/chat/sessions', {
      method: 'POST', token: u.accessToken, body: { title: 'First' },
    });
    const second = await call<{ id: number }>('/api/chat/sessions', {
      method: 'POST', token: u.accessToken, body: { title: 'Second' },
    });
    // Touch the older session so it should now sort first.
    await call(`/api/chat/sessions/${first.body.id}/messages`, {
      method: 'POST', token: u.accessToken, body: { role: 'user', content: 'hi' },
    });

    const list = await call<{ sessions: { id: number; title: string }[] }>('/api/chat/sessions', {
      token: u.accessToken,
    });
    expect(list.body.sessions.map((s) => s.title)).toEqual(['First', 'Second']);
    void second;
  });

  it('renames and deletes a session', async () => {
    const u = await makeUser();
    const created = await call<{ id: number }>('/api/chat/sessions', {
      method: 'POST', token: u.accessToken, body: {},
    });
    const sessionId = created.body.id;

    const renamed = await call(`/api/chat/sessions/${sessionId}`, {
      method: 'PATCH', token: u.accessToken, body: { title: 'Renamed' },
    });
    expect(renamed.status).toBe(200);

    const deleted = await call(`/api/chat/sessions/${sessionId}`, {
      method: 'DELETE', token: u.accessToken,
    });
    expect(deleted.status).toBe(200);

    const gone = await call(`/api/chat/sessions/${sessionId}`, { token: u.accessToken });
    expect(gone.status).toBe(404);
  });

  it('never lets one user read, message, or delete another user\'s session', async () => {
    const a = await makeUser();
    const b = await makeUser();
    const created = await call<{ id: number }>('/api/chat/sessions', {
      method: 'POST', token: a.accessToken, body: { title: 'Private' },
    });
    const sessionId = created.body.id;

    expect((await call(`/api/chat/sessions/${sessionId}`, { token: b.accessToken })).status).toBe(404);
    expect(
      (
        await call(`/api/chat/sessions/${sessionId}/messages`, {
          method: 'POST', token: b.accessToken, body: { role: 'user', content: 'nope' },
        })
      ).status,
    ).toBe(404);
    expect((await call(`/api/chat/sessions/${sessionId}`, { method: 'DELETE', token: b.accessToken })).status).toBe(
      404,
    );

    const stillThere = await call(`/api/chat/sessions/${sessionId}`, { token: a.accessToken });
    expect(stillThere.status).toBe(200);
  });

  it('rejects an invalid role', async () => {
    const u = await makeUser();
    const created = await call<{ id: number }>('/api/chat/sessions', {
      method: 'POST', token: u.accessToken, body: {},
    });
    const { status } = await call(`/api/chat/sessions/${created.body.id}/messages`, {
      method: 'POST', token: u.accessToken, body: { role: 'system', content: 'x' },
    });
    expect(status).toBe(400);
  });

  it('requires auth', async () => {
    expect((await call('/api/chat/sessions')).status).toBe(401);
  });
});
