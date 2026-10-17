import { db, nowIso, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';

export interface UserRow {
  id: number;
  email: string;
  password_hash: string;
  password_salt: string;
  data_key_salt: string;
  key_fingerprint: string | null;
  is_active: number;
}

/** Postgres has a real boolean column; normalize back to the SQLite 0/1
 * convention so every caller (routes, tests) works unchanged either way. */
function normalizeUser(row: Record<string, unknown>): UserRow {
  return { ...row, is_active: row.is_active ? 1 : 0 } as UserRow;
}

export async function createUser(params: {
  email: string;
  passwordHash: string;
  passwordSalt: string;
  dataKeySalt: string;
}): Promise<UserRow> {
  const email = params.email.toLowerCase();

  if (usePg) {
    const { rows } = await pgQuery<{ id: number }>(
      `INSERT INTO users (email, password_hash, password_salt, data_key_salt)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [email, params.passwordHash, params.passwordSalt, params.dataKeySalt],
    );
    const id = rows[0]!.id;
    await pgQuery(`INSERT INTO user_preferences (user_id) VALUES ($1)`, [id]);
    return (await findUserById(id))!;
  }

  const info = db
    .prepare(
      `INSERT INTO users (email, password_hash, password_salt, data_key_salt)
       VALUES (?, ?, ?, ?)`,
    )
    .run(email, params.passwordHash, params.passwordSalt, params.dataKeySalt);
  db.prepare(`INSERT INTO user_preferences (user_id) VALUES (?)`).run(info.lastInsertRowid);
  return (await findUserById(Number(info.lastInsertRowid)))!;
}

export async function findUserByEmail(email: string): Promise<UserRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery(`SELECT * FROM users WHERE email = $1`, [email.toLowerCase()]);
    return rows[0] ? normalizeUser(rows[0]) : undefined;
  }
  const row = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email.toLowerCase()) as
    | UserRow
    | undefined;
  return row;
}

export async function findUserById(id: number): Promise<UserRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery(`SELECT * FROM users WHERE id = $1`, [id]);
    return rows[0] ? normalizeUser(rows[0]) : undefined;
  }
  return db.prepare(`SELECT * FROM users WHERE id = ?`).get(id) as UserRow | undefined;
}

export async function setKeyFingerprint(userId: number, fingerprint: string): Promise<void> {
  if (usePg) {
    await pgQuery(`UPDATE users SET key_fingerprint = $1, updated_at = now() WHERE id = $2`, [
      fingerprint,
      userId,
    ]);
    return;
  }
  db.prepare(`UPDATE users SET key_fingerprint = ?, updated_at = ? WHERE id = ?`).run(
    fingerprint,
    nowIso(),
    userId,
  );
}

export interface PreferencesRow {
  collection_enabled: number;
  collect_browsing: number;
  collect_searches: number;
  collect_youtube: number;
  collect_files: number;
  collect_code_activity: number;
  collect_apps: number;
  data_retention_days: number;
  timezone: string;
  language: string;
  theme: string;
}

const PREF_BOOL_COLS = [
  'collection_enabled', 'collect_browsing', 'collect_searches', 'collect_youtube',
  'collect_files', 'collect_code_activity', 'collect_apps', 'auto_delete_enabled',
] as const;

function normalizePrefs(row: Record<string, unknown>): PreferencesRow {
  const out = { ...row };
  for (const col of PREF_BOOL_COLS) if (col in out) out[col] = out[col] ? 1 : 0;
  return out as unknown as PreferencesRow;
}

export async function getPreferences(userId: number): Promise<PreferencesRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery(`SELECT * FROM user_preferences WHERE user_id = $1`, [userId]);
    return rows[0] ? normalizePrefs(rows[0]) : undefined;
  }
  return db.prepare(`SELECT * FROM user_preferences WHERE user_id = ?`).get(userId) as
    | PreferencesRow
    | undefined;
}

const UPDATABLE_PREFS = new Set([
  'collection_enabled', 'collect_browsing', 'collect_searches', 'collect_youtube',
  'collect_files', 'collect_code_activity', 'collect_apps', 'data_retention_days',
  'auto_delete_enabled', 'timezone', 'language', 'theme',
]);

export async function updatePreferences(userId: number, patch: Record<string, unknown>): Promise<void> {
  const entries = Object.entries(patch).filter(([k]) => UPDATABLE_PREFS.has(k));
  if (entries.length === 0) return;
  // Column names come from the allowlist above, never from user input.

  if (usePg) {
    const setSql = entries.map(([k], i) => `${k} = $${i + 1}`).join(', ');
    await pgQuery(
      `UPDATE user_preferences SET ${setSql}, updated_at = now() WHERE user_id = $${entries.length + 1}`,
      [...entries.map(([, v]) => v), userId],
    );
    return;
  }

  const setSql = entries.map(([k]) => `${k} = ?`).join(', ');
  db.prepare(`UPDATE user_preferences SET ${setSql}, updated_at = ? WHERE user_id = ?`).run(
    ...entries.map(([, v]) => (typeof v === 'boolean' ? (v ? 1 : 0) : (v as string | number))),
    nowIso(),
    userId,
  );
}

export async function getBlockedPatterns(userId: number) {
  if (usePg) {
    const { rows } = await pgQuery<{ pattern_type: string; pattern: string }>(
      `SELECT pattern_type, pattern FROM blocked_patterns WHERE user_id = $1`,
      [userId],
    );
    return rows;
  }
  return db
    .prepare(`SELECT pattern_type, pattern FROM blocked_patterns WHERE user_id = ?`)
    .all(userId) as Array<{ pattern_type: string; pattern: string }>;
}

export async function addBlockedPattern(userId: number, type: string, pattern: string): Promise<void> {
  if (usePg) {
    await pgQuery(
      `INSERT INTO blocked_patterns (user_id, pattern_type, pattern) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, pattern_type, pattern) DO NOTHING`,
      [userId, type, pattern],
    );
    return;
  }
  db.prepare(
    `INSERT OR IGNORE INTO blocked_patterns (user_id, pattern_type, pattern) VALUES (?, ?, ?)`,
  ).run(userId, type, pattern);
}

export async function removeBlockedPattern(userId: number, type: string, pattern: string): Promise<void> {
  if (usePg) {
    await pgQuery(
      `DELETE FROM blocked_patterns WHERE user_id = $1 AND pattern_type = $2 AND pattern = $3`,
      [userId, type, pattern],
    );
    return;
  }
  db.prepare(
    `DELETE FROM blocked_patterns WHERE user_id = ? AND pattern_type = ? AND pattern = ?`,
  ).run(userId, type, pattern);
}
