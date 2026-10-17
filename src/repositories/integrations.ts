import { db, nowIso, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';
import { hashToken, generateToken } from '../services/passwords.js';

/**
 * Scopes an integration token can hold. Access is bound to the credential, not
 * to a claimed model identity — see docs/PRD-REVIEW.md #2.
 */
export const SCOPES = [
  'consciousness:summary', // bounded summary only
  'activity:read',         // raw event history
  'activity:search',       // full-text search
  'devices:read',          // device status
  // Marks a token as OAuth/remote-issued (minted by remote-mcp-server on the
  // user's behalf, not locally by the desktop app). Every /api/remote/* route
  // requires this IN ADDITION TO a specific scope above, so a leaked local
  // desktop token can never reach the server-side-decrypting endpoints.
  'remote:mcp',
] as const;

export type Scope = (typeof SCOPES)[number];

export interface IntegrationRow {
  id: number;
  user_id: number;
  label: string;
  token_hash: string;
  scopes: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface CreatedIntegration {
  id: number;
  label: string;
  scopes: Scope[];
  /** Returned exactly once, at creation. Only the hash is stored. */
  token: string;
}

/** SQLite stores scopes as a JSON string; Postgres uses a native TEXT[]. */
function parseScopes(raw: unknown): Scope[] {
  return Array.isArray(raw) ? (raw as Scope[]) : (JSON.parse(raw as string) as Scope[]);
}

export async function createIntegration(
  userId: number,
  label: string,
  scopes: Scope[],
): Promise<CreatedIntegration> {
  const token = `onecon_${generateToken(32)}`;

  if (usePg) {
    const { rows } = await pgQuery<{ id: number }>(
      `INSERT INTO integrations (user_id, label, token_hash, scopes) VALUES ($1, $2, $3, $4) RETURNING id`,
      [userId, label, hashToken(token), scopes],
    );
    return { id: rows[0]!.id, label, scopes, token };
  }

  const info = db
    .prepare(`INSERT INTO integrations (user_id, label, token_hash, scopes) VALUES (?, ?, ?, ?)`)
    .run(userId, label, hashToken(token), JSON.stringify(scopes));
  return { id: Number(info.lastInsertRowid), label, scopes, token };
}

export async function findByToken(
  token: string,
): Promise<(IntegrationRow & { parsedScopes: Scope[] }) | undefined> {
  if (usePg) {
    const { rows } = await pgQuery<IntegrationRow>(
      `SELECT * FROM integrations WHERE token_hash = $1 AND revoked_at IS NULL`,
      [hashToken(token)],
    );
    return rows[0] ? { ...rows[0], parsedScopes: parseScopes(rows[0].scopes) } : undefined;
  }
  const row = db
    .prepare(`SELECT * FROM integrations WHERE token_hash = ? AND revoked_at IS NULL`)
    .get(hashToken(token)) as IntegrationRow | undefined;
  if (!row) return undefined;
  return { ...row, parsedScopes: parseScopes(row.scopes) };
}

export async function touchLastUsed(id: number): Promise<void> {
  if (usePg) {
    await pgQuery(`UPDATE integrations SET last_used_at = now() WHERE id = $1`, [id]);
    return;
  }
  db.prepare(`UPDATE integrations SET last_used_at = ? WHERE id = ?`).run(nowIso(), id);
}

export async function listIntegrations(userId: number) {
  if (usePg) {
    const { rows } = await pgQuery(
      `SELECT id, label, scopes, created_at, last_used_at, revoked_at
         FROM integrations WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return rows.map((r) => ({ ...r, scopes: parseScopes(r.scopes) }));
  }
  const rows = db
    .prepare(
      `SELECT id, label, scopes, created_at, last_used_at, revoked_at
         FROM integrations WHERE user_id = ? ORDER BY created_at DESC`,
    )
    .all(userId) as Array<Omit<IntegrationRow, 'token_hash' | 'user_id'>>;
  return rows.map((r) => ({ ...r, scopes: parseScopes(r.scopes) }));
}

export async function revokeIntegration(userId: number, id: number): Promise<boolean> {
  if (usePg) {
    const { rowCount } = await pgQuery(
      `UPDATE integrations SET revoked_at = now() WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL`,
      [userId, id],
    );
    return rowCount > 0;
  }
  return (
    db
      .prepare(`UPDATE integrations SET revoked_at = ? WHERE user_id = ? AND id = ? AND revoked_at IS NULL`)
      .run(nowIso(), userId, id).changes > 0
  );
}
