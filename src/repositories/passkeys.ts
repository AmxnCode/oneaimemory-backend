import { randomBytes } from 'node:crypto';
import { db, nowIso, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';

export interface CredentialRow {
  id: number;
  user_id: number;
  credential_id: string;
  public_key: Buffer;
  counter: number;
  transports: string | null;
  device_label: string;
  backed_up: number;
  prf_salt: string | null;
  wrapped_key: Buffer | null;
  wrapped_key_iv: Buffer | null;
  created_at: string;
  last_used_at: string | null;
}

/** Postgres has a real boolean and a native TEXT[] for transports; SQLite has
 * 0/1 and a JSON string. Normalize both back to the SQLite shape so callers
 * (routes/passkeys.ts) work unchanged. */
function normalize(row: Record<string, unknown>): CredentialRow {
  return {
    ...row,
    backed_up: row.backed_up ? 1 : 0,
    transports: Array.isArray(row.transports) ? JSON.stringify(row.transports) : row.transports,
  } as CredentialRow;
}

const CHALLENGE_TTL_MS = 5 * 60_000;

/**
 * Issue a server-side challenge. Held in the database rather than round-tripped
 * to the client so a caller cannot choose or replay its own value.
 */
export async function createChallenge(
  kind: 'registration' | 'authentication',
  userId?: number,
): Promise<string> {
  const challenge = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();

  if (usePg) {
    await pgQuery(
      `INSERT INTO webauthn_challenges (challenge, user_id, kind, expires_at) VALUES ($1, $2, $3, $4)`,
      [challenge, userId ?? null, kind, expiresAt],
    );
    return challenge;
  }

  db.prepare(
    `INSERT INTO webauthn_challenges (challenge, user_id, kind, expires_at) VALUES (?, ?, ?, ?)`,
  ).run(challenge, userId ?? null, kind, expiresAt);
  return challenge;
}

/**
 * Single-use consumption. Returns the row only if it is unconsumed, unexpired,
 * and of the expected kind — then immediately marks it spent.
 */
export async function consumeChallenge(
  challenge: string,
  kind: 'registration' | 'authentication',
): Promise<{ userId: number | null } | null> {
  if (usePg) {
    const { rows } = await pgQuery<{
      id: number; user_id: number | null; expires_at: string; consumed: boolean;
    }>(`SELECT * FROM webauthn_challenges WHERE challenge = $1 AND kind = $2`, [challenge, kind]);
    const row = rows[0];
    if (!row || row.consumed || new Date(row.expires_at) < new Date()) return null;
    await pgQuery(`UPDATE webauthn_challenges SET consumed = true WHERE id = $1`, [row.id]);
    return { userId: row.user_id };
  }

  const row = db
    .prepare(`SELECT * FROM webauthn_challenges WHERE challenge = ? AND kind = ?`)
    .get(challenge, kind) as { id: number; user_id: number | null; expires_at: string; consumed: number } | undefined;
  if (!row || row.consumed === 1 || row.expires_at < nowIso()) return null;
  db.prepare(`UPDATE webauthn_challenges SET consumed = 1 WHERE id = ?`).run(row.id);
  return { userId: row.user_id };
}

export async function purgeExpiredChallenges(): Promise<number> {
  if (usePg) {
    const { rowCount } = await pgQuery(`DELETE FROM webauthn_challenges WHERE expires_at < now()`);
    return rowCount;
  }
  return db.prepare(`DELETE FROM webauthn_challenges WHERE expires_at < ?`).run(nowIso()).changes;
}

export async function saveCredential(params: {
  userId: number;
  credentialId: string;
  publicKey: Buffer;
  counter: number;
  transports?: string[];
  deviceLabel: string;
  backedUp: boolean;
  prfSalt?: string | null;
  wrappedKey?: Buffer | null;
  wrappedKeyIv?: Buffer | null;
}): Promise<CredentialRow> {
  if (usePg) {
    await pgQuery(
      `INSERT INTO webauthn_credentials
         (user_id, credential_id, public_key, counter, transports, device_label, backed_up,
          prf_salt, wrapped_key, wrapped_key_iv)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        params.userId, params.credentialId, params.publicKey, params.counter,
        params.transports ?? null, params.deviceLabel, params.backedUp,
        params.prfSalt ?? null, params.wrappedKey ?? null, params.wrappedKeyIv ?? null,
      ],
    );
    return (await findByCredentialId(params.credentialId))!;
  }

  db.prepare(
    `INSERT INTO webauthn_credentials
       (user_id, credential_id, public_key, counter, transports, device_label, backed_up,
        prf_salt, wrapped_key, wrapped_key_iv)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    params.userId, params.credentialId, params.publicKey, params.counter,
    params.transports ? JSON.stringify(params.transports) : null,
    params.deviceLabel, params.backedUp ? 1 : 0,
    params.prfSalt ?? null, params.wrappedKey ?? null, params.wrappedKeyIv ?? null,
  );
  return (await findByCredentialId(params.credentialId))!;
}

export async function findByCredentialId(credentialId: string): Promise<CredentialRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery(
      `SELECT * FROM webauthn_credentials WHERE credential_id = $1`,
      [credentialId],
    );
    return rows[0] ? normalize(rows[0]) : undefined;
  }
  return db
    .prepare(`SELECT * FROM webauthn_credentials WHERE credential_id = ?`)
    .get(credentialId) as CredentialRow | undefined;
}

export async function listForUser(userId: number): Promise<CredentialRow[]> {
  if (usePg) {
    const { rows } = await pgQuery(
      `SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return rows.map(normalize);
  }
  return db
    .prepare(`SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC`)
    .all(userId) as CredentialRow[];
}

export async function countForUser(userId: number): Promise<number> {
  if (usePg) {
    const { rows } = await pgQuery<{ n: string }>(
      `SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = $1`,
      [userId],
    );
    return Number(rows[0]?.n ?? 0);
  }
  const r = db
    .prepare(`SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?`)
    .get(userId) as { n: number };
  return r.n;
}

/**
 * Record a successful assertion. The signature counter must strictly increase
 * for authenticators that implement it — a repeat or regression indicates a
 * cloned credential, so the caller rejects it.
 */
export async function updateCounter(id: number, counter: number): Promise<void> {
  if (usePg) {
    await pgQuery(`UPDATE webauthn_credentials SET counter = $1, last_used_at = now() WHERE id = $2`, [
      counter, id,
    ]);
    return;
  }
  db.prepare(`UPDATE webauthn_credentials SET counter = ?, last_used_at = ? WHERE id = ?`).run(
    counter, nowIso(), id,
  );
}

export async function deleteCredential(userId: number, id: number): Promise<boolean> {
  if (usePg) {
    const { rowCount } = await pgQuery(
      `DELETE FROM webauthn_credentials WHERE user_id = $1 AND id = $2`,
      [userId, id],
    );
    return rowCount > 0;
  }
  return (
    db.prepare(`DELETE FROM webauthn_credentials WHERE user_id = ? AND id = ?`).run(userId, id)
      .changes > 0
  );
}

/** Attach a PRF-wrapped data key to a credential that was registered without one. */
export async function setWrappedKey(
  userId: number,
  id: number,
  prfSalt: string,
  wrappedKey: Buffer,
  iv: Buffer,
): Promise<boolean> {
  if (usePg) {
    const { rowCount } = await pgQuery(
      `UPDATE webauthn_credentials SET prf_salt = $1, wrapped_key = $2, wrapped_key_iv = $3
        WHERE user_id = $4 AND id = $5`,
      [prfSalt, wrappedKey, iv, userId, id],
    );
    return rowCount > 0;
  }
  return (
    db
      .prepare(
        `UPDATE webauthn_credentials SET prf_salt = ?, wrapped_key = ?, wrapped_key_iv = ?
          WHERE user_id = ? AND id = ?`,
      )
      .run(prfSalt, wrappedKey, iv, userId, id).changes > 0
  );
}
