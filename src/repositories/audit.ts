import { db, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';

export interface AuditEntry {
  userId: number;
  action: string;
  integrationId?: number | null;
  /**
   * Self-reported by the caller and NOT verifiable — MCP servers authenticate a
   * credential, not a model. Stored as a hint for the user's own benefit; the
   * dashboard must label it as unverified. The trustworthy identity is
   * integrationId.
   */
  claimedAiModel?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  details?: unknown;
}

export async function record(entry: AuditEntry): Promise<void> {
  if (usePg) {
    await pgQuery(
      `INSERT INTO audit_logs (user_id, action, integration_id, claimed_ai_model, ip_address, user_agent, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        entry.userId,
        entry.action,
        entry.integrationId ?? null,
        entry.claimedAiModel ?? null,
        entry.ipAddress ?? null,
        entry.userAgent ?? null,
        entry.details === undefined ? null : JSON.stringify(entry.details),
      ],
    );
    return;
  }

  db.prepare(
    `INSERT INTO audit_logs (user_id, action, integration_id, claimed_ai_model, ip_address, user_agent, details)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    entry.userId,
    entry.action,
    entry.integrationId ?? null,
    entry.claimedAiModel ?? null,
    entry.ipAddress ?? null,
    entry.userAgent ?? null,
    entry.details === undefined ? null : JSON.stringify(entry.details),
  );
}

/** Postgres auto-parses JSONB columns into objects; SQLite stores raw TEXT. */
function parseDetails(raw: unknown): unknown {
  if (raw === null || raw === undefined) return null;
  return typeof raw === 'string' ? JSON.parse(raw) : raw;
}

export async function list(userId: number, limit = 100) {
  if (usePg) {
    const { rows } = await pgQuery<Record<string, unknown>>(
      `SELECT a.id, a.action, a.integration_id, a.claimed_ai_model, a.timestamp,
              a.ip_address, a.user_agent, a.details, i.label AS integration_label
         FROM audit_logs a
    LEFT JOIN integrations i ON i.id = a.integration_id
        WHERE a.user_id = $1
        ORDER BY a.timestamp DESC, a.id DESC
        LIMIT $2`,
      [userId, limit],
    );
    return rows.map((r) => ({
      id: r.id,
      action: r.action,
      integrationId: r.integration_id,
      integrationLabel: r.integration_label,
      claimedAiModel: r.claimed_ai_model,
      claimedAiModelVerified: false,
      timestamp: r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp,
      ipAddress: r.ip_address,
      userAgent: r.user_agent,
      details: parseDetails(r.details),
    }));
  }

  const rows = db
    .prepare(
      `SELECT a.id, a.action, a.integration_id, a.claimed_ai_model, a.timestamp,
              a.ip_address, a.user_agent, a.details, i.label AS integration_label
         FROM audit_logs a
    LEFT JOIN integrations i ON i.id = a.integration_id
        WHERE a.user_id = ?
        ORDER BY a.timestamp DESC, a.id DESC
        LIMIT ?`,
    )
    .all(userId, limit) as Array<Record<string, unknown>>;

  return rows.map((r) => ({
    id: r.id,
    action: r.action,
    integrationId: r.integration_id,
    integrationLabel: r.integration_label,
    claimedAiModel: r.claimed_ai_model,
    claimedAiModelVerified: false,
    timestamp: r.timestamp,
    ipAddress: r.ip_address,
    userAgent: r.user_agent,
    details: r.details ? JSON.parse(r.details as string) : null,
  }));
}
