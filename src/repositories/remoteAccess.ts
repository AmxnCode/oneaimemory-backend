import { db, nowIso, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';
import type { WrappedKey } from '../services/remoteKek.js';

export interface RemoteAccessRow {
  user_id: number;
  enabled: number; // normalized to 0/1, see normalize()
  wrapped_data_key: Buffer | null;
  wrapped_data_key_iv: Buffer | null;
  wrapped_data_key_auth_tag: Buffer | null;
  kek_version: number;
  enabled_at: string | null;
}

function normalize(row: Record<string, unknown>): RemoteAccessRow {
  return { ...row, enabled: row.enabled ? 1 : 0 } as unknown as RemoteAccessRow;
}

export async function getGrant(userId: number): Promise<RemoteAccessRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery(`SELECT * FROM remote_access_grants WHERE user_id = $1`, [userId]);
    return rows[0] ? normalize(rows[0]) : undefined;
  }
  const row = db.prepare(`SELECT * FROM remote_access_grants WHERE user_id = ?`).get(userId) as
    | Record<string, unknown>
    | undefined;
  return row ? normalize(row) : undefined;
}

/** Upserts the wrapped key and marks the grant enabled. */
export async function enable(userId: number, wrapped: WrappedKey, kekVersion: number): Promise<void> {
  if (usePg) {
    await pgQuery(
      `INSERT INTO remote_access_grants
         (user_id, enabled, wrapped_data_key, wrapped_data_key_iv, wrapped_data_key_auth_tag, kek_version, enabled_at, disabled_at)
       VALUES ($1, true, $2, $3, $4, $5, now(), NULL)
       ON CONFLICT (user_id) DO UPDATE SET
         enabled = true,
         wrapped_data_key = $2,
         wrapped_data_key_iv = $3,
         wrapped_data_key_auth_tag = $4,
         kek_version = $5,
         enabled_at = now(),
         disabled_at = NULL,
         updated_at = now()`,
      [userId, wrapped.ciphertext, wrapped.iv, wrapped.authTag, kekVersion],
    );
    return;
  }
  const now = nowIso();
  db.prepare(
    `INSERT INTO remote_access_grants
       (user_id, enabled, wrapped_data_key, wrapped_data_key_iv, wrapped_data_key_auth_tag, kek_version, enabled_at, disabled_at, updated_at)
     VALUES (?, 1, ?, ?, ?, ?, ?, NULL, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       enabled = 1,
       wrapped_data_key = excluded.wrapped_data_key,
       wrapped_data_key_iv = excluded.wrapped_data_key_iv,
       wrapped_data_key_auth_tag = excluded.wrapped_data_key_auth_tag,
       kek_version = excluded.kek_version,
       enabled_at = excluded.enabled_at,
       disabled_at = NULL,
       updated_at = excluded.updated_at`,
  ).run(userId, wrapped.ciphertext, wrapped.iv, wrapped.authTag, kekVersion, now, now);
}

/** Disables the grant AND destroys the wrapped key — re-enabling requires the client to send it again. */
export async function disable(userId: number): Promise<void> {
  if (usePg) {
    await pgQuery(
      `UPDATE remote_access_grants
          SET enabled = false, wrapped_data_key = NULL, wrapped_data_key_iv = NULL,
              wrapped_data_key_auth_tag = NULL, disabled_at = now(), updated_at = now()
        WHERE user_id = $1`,
      [userId],
    );
    return;
  }
  const now = nowIso();
  db.prepare(
    `UPDATE remote_access_grants
        SET enabled = 0, wrapped_data_key = NULL, wrapped_data_key_iv = NULL,
            wrapped_data_key_auth_tag = NULL, disabled_at = ?, updated_at = ?
      WHERE user_id = ?`,
  ).run(now, now, userId);
}
