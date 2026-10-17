import { db, nowIso, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';
import { hashToken, generateToken } from '../services/passwords.js';
import { env } from '../config/env.js';

export async function issueRefreshToken(userId: number, deviceId?: string): Promise<string> {
  const token = generateToken(48);
  const expiresAt = new Date(Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 86400_000).toISOString();

  if (usePg) {
    await pgQuery(
      `INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at) VALUES ($1, $2, $3, $4)`,
      [userId, hashToken(token), deviceId ?? null, expiresAt],
    );
    return token;
  }

  db.prepare(
    `INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at) VALUES (?, ?, ?, ?)`,
  ).run(userId, hashToken(token), deviceId ?? null, expiresAt);
  return token;
}

export interface RefreshRow {
  id: number;
  user_id: number;
  device_id: string | null;
  expires_at: string;
  revoked: number;
}

export async function consumeRefreshToken(token: string): Promise<RefreshRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery<Omit<RefreshRow, 'revoked'> & { revoked: boolean }>(
      `SELECT * FROM refresh_tokens WHERE token_hash = $1`,
      [hashToken(token)],
    );
    const row = rows[0];
    if (!row || row.revoked || new Date(row.expires_at) < new Date()) return undefined;

    // Single-use: rotate on every refresh so a stolen token is usable at most once.
    await pgQuery(`UPDATE refresh_tokens SET revoked = true WHERE id = $1`, [row.id]);
    return { ...row, revoked: 1 };
  }

  const row = db.prepare(`SELECT * FROM refresh_tokens WHERE token_hash = ?`).get(hashToken(token)) as
    | RefreshRow
    | undefined;
  if (!row || row.revoked === 1 || row.expires_at < nowIso()) return undefined;
  db.prepare(`UPDATE refresh_tokens SET revoked = 1 WHERE id = ?`).run(row.id);
  return row;
}

export async function revokeAllForUser(userId: number): Promise<void> {
  if (usePg) {
    await pgQuery(`UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`, [
      userId,
    ]);
    return;
  }
  db.prepare(`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0`).run(userId);
}

export async function purgeExpired(): Promise<number> {
  if (usePg) {
    const { rowCount } = await pgQuery(`DELETE FROM refresh_tokens WHERE expires_at < now()`);
    return rowCount;
  }
  return db.prepare(`DELETE FROM refresh_tokens WHERE expires_at < ?`).run(nowIso()).changes;
}
