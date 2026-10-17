import type { EncryptedEnvelope } from '@oneconscious/shared';
import { db, nowIso, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';

export interface EventRow {
  id: number;
  event_uuid: string;
  device_id: string;
  event_type: string;
  ciphertext: Buffer;
  iv: Buffer;
  auth_tag: Buffer;
  // SQLite returns TEXT; Postgres returns TIMESTAMPTZ as a JS Date.
  timestamp: string | Date;
}

interface InsertResult {
  inserted: number;
  duplicates: number;
}

// Prepared lazily for the SQLite path: ESM hoists imports, so this module is
// evaluated before runMigrations() has created the tables. Cached after first use.
let sqliteInsertTx: ((userId: number, events: EncryptedEnvelope[]) => InsertResult) | null = null;

function getSqliteInsertTx() {
  if (sqliteInsertTx) return sqliteInsertTx;

  const stmt = db.prepare(
    `INSERT INTO consciousness_events
       (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp, synced_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (user_id, event_uuid) DO NOTHING`,
  );

  sqliteInsertTx = db.transaction((userId: number, events: EncryptedEnvelope[]): InsertResult => {
    const syncedAt = nowIso();
    let inserted = 0;
    for (const e of events) {
      const info = stmt.run(
        userId, e.eventUuid, e.deviceId, e.type,
        Buffer.from(e.ciphertext, 'base64'), Buffer.from(e.iv, 'base64'), Buffer.from(e.authTag, 'base64'),
        e.timestamp, syncedAt,
      );
      if (info.changes > 0) inserted++;
    }
    return { inserted, duplicates: events.length - inserted };
  });

  return sqliteInsertTx;
}

/**
 * Idempotent batch insert. Devices retry on network failure, so the same batch
 * can arrive more than once; ON CONFLICT DO NOTHING makes replays free instead
 * of duplicating rows.
 *
 * The Postgres conflict target is (user_id, event_uuid, timestamp) — three
 * columns, not two — because the table is partitioned by timestamp and the
 * partition key must be part of any uniqueness constraint. This is not a
 * behavioral gap in practice: eventUuid is client-generated and immutable, so
 * a legitimate retry always resends the identical timestamp alongside it.
 */
export async function insertEvents(userId: number, events: EncryptedEnvelope[]): Promise<InsertResult> {
  if (!usePg) return getSqliteInsertTx()(userId, events);
  if (events.length === 0) return { inserted: 0, duplicates: 0 };

  // Bulk multi-row INSERT: turns 200 sequential round-trips to the remote
  // Supabase pooler (~60s, which tripped the Next.js proxy's ~30s timeout
  // and surfaced as plain-text 500 "Internal Server Error" on the desktop)
  // into 1 round-trip (~0.3-0.8s). Chunked to stay under Postgres's 65535
  // parameter limit (500 events * 8 params = 4000).
  const CHUNK = 200;
  let inserted = 0;
  for (let i = 0; i < events.length; i += CHUNK) {
    const chunk = events.slice(i, i + CHUNK);
    const values: string[] = [];
    const params: unknown[] = [];
    let p = 1;
    for (const e of chunk) {
      values.push(`($${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, now())`);
      params.push(
        userId,
        e.eventUuid,
        e.deviceId,
        e.type,
        Buffer.from(e.ciphertext, 'base64'),
        Buffer.from(e.iv, 'base64'),
        Buffer.from(e.authTag, 'base64'),
        e.timestamp,
      );
    }
    const sql = `INSERT INTO consciousness_events
           (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp, synced_at)
         VALUES ${values.join(', ')}
         ON CONFLICT (user_id, event_uuid, timestamp) DO NOTHING`;
    const { rowCount } = await pgQuery(sql, params);
    inserted += rowCount;
  }
  return { inserted, duplicates: events.length - inserted };
}

export interface QueryOptions {
  userId: number;
  since?: string;
  until?: string;
  types?: string[];
  deviceId?: string;
  limit: number;
  /** Opaque cursor: "<timestamp>|<id>" from a previous page. */
  cursor?: string;
}

export interface QueryResult {
  events: EncryptedEnvelope[];
  nextCursor: string | null;
}

function toEnvelope(r: EventRow): EncryptedEnvelope {
  return {
    eventUuid: r.event_uuid,
    deviceId: r.device_id,
    type: r.event_type as EncryptedEnvelope['type'],
    // Postgres returns TIMESTAMPTZ as a JS Date; SQLite returns the TEXT
    // column verbatim. Normalize both to the same ISO string shape.
    timestamp: r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp,
    ciphertext: r.ciphertext.toString('base64'),
    iv: r.iv.toString('base64'),
    authTag: r.auth_tag.toString('base64'),
  };
}

/**
 * Newest-first page of encrypted events. Keyset pagination on (timestamp, id)
 * rather than OFFSET, so deep pages stay O(limit) instead of degrading as the
 * table grows.
 */
export async function queryEvents(opts: QueryOptions): Promise<QueryResult> {
  if (usePg) {
    const where: string[] = ['user_id = $1'];
    const params: unknown[] = [opts.userId];
    const next = () => params.length + 1;

    if (opts.since) { where.push(`timestamp >= $${next()}`); params.push(opts.since); }
    if (opts.until) { where.push(`timestamp <= $${next()}`); params.push(opts.until); }
    if (opts.deviceId) { where.push(`device_id = $${next()}`); params.push(opts.deviceId); }
    if (opts.types && opts.types.length > 0) {
      // = ANY($n::text[]) with one array param, not N individual $-placeholders
      // in an IN-list: against this partitioned table, Postgres's planner
      // fails to infer a type for later placeholders in that shape ("could
      // not determine data type of parameter $4") — a real bug caught live
      // once a query actually filtered by more than a couple of types. The
      // explicit ::text[] cast sidesteps inference entirely.
      where.push(`event_type = ANY($${next()}::text[])`);
      params.push(opts.types);
    }
    if (opts.cursor) {
      const sep = opts.cursor.lastIndexOf('|');
      const ts = opts.cursor.slice(0, sep);
      const id = Number(opts.cursor.slice(sep + 1));
      if (ts && Number.isFinite(id)) {
        const tsIdx = next();
        const idIdx = tsIdx + 1;
        where.push(`(timestamp < $${tsIdx} OR (timestamp = $${tsIdx} AND id < $${idIdx}))`);
        params.push(ts, id);
      }
    }
    params.push(opts.limit + 1);

    const { rows } = await pgQuery<EventRow>(
      `SELECT id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp
         FROM consciousness_events
        WHERE ${where.join(' AND ')}
        ORDER BY timestamp DESC, id DESC
        LIMIT $${params.length}`,
      params,
    );

    const hasMore = rows.length > opts.limit;
    const page = hasMore ? rows.slice(0, opts.limit) : rows;
    const last = page[page.length - 1];
    const lastTs = last ? (last.timestamp instanceof Date ? last.timestamp.toISOString() : last.timestamp) : null;

    return {
      events: page.map(toEnvelope),
      nextCursor: hasMore && last ? `${lastTs}|${last.id}` : null,
    };
  }

  const where: string[] = ['user_id = ?'];
  const params: Array<string | number> = [opts.userId];

  if (opts.since) { where.push('timestamp >= ?'); params.push(opts.since); }
  if (opts.until) { where.push('timestamp <= ?'); params.push(opts.until); }
  if (opts.deviceId) { where.push('device_id = ?'); params.push(opts.deviceId); }
  if (opts.types && opts.types.length > 0) {
    where.push(`event_type IN (${opts.types.map(() => '?').join(',')})`);
    params.push(...opts.types);
  }
  if (opts.cursor) {
    const sep = opts.cursor.lastIndexOf('|');
    const ts = opts.cursor.slice(0, sep);
    const id = Number(opts.cursor.slice(sep + 1));
    if (ts && Number.isFinite(id)) {
      where.push('(timestamp < ? OR (timestamp = ? AND id < ?))');
      params.push(ts, ts, id);
    }
  }

  const rows = db
    .prepare(
      `SELECT id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp
         FROM consciousness_events
        WHERE ${where.join(' AND ')}
        ORDER BY timestamp DESC, id DESC
        LIMIT ?`,
    )
    .all(...params, opts.limit + 1) as EventRow[];

  const hasMore = rows.length > opts.limit;
  const page = hasMore ? rows.slice(0, opts.limit) : rows;
  const last = page[page.length - 1];

  return {
    events: page.map(toEnvelope),
    nextCursor: hasMore && last ? `${last.timestamp}|${last.id}` : null,
  };
}

export async function countEvents(userId: number): Promise<number> {
  if (usePg) {
    const { rows } = await pgQuery<{ n: string }>(
      `SELECT COUNT(*) AS n FROM consciousness_events WHERE user_id = $1`,
      [userId],
    );
    // Postgres COUNT(*) returns bigint, which node-postgres gives back as a
    // string to avoid silent precision loss above 2^53 — safe to Number()
    // here since a single user's event count will never approach that.
    return Number(rows[0]?.n ?? 0);
  }
  const row = db
    .prepare(`SELECT COUNT(*) AS n FROM consciousness_events WHERE user_id = ?`)
    .get(userId) as { n: number };
  return row.n;
}

export async function eventTypeBreakdown(userId: number, since?: string): Promise<Record<string, number>> {
  if (usePg) {
    const { rows } = await pgQuery<{ event_type: string; n: string }>(
      since
        ? `SELECT event_type, COUNT(*) AS n FROM consciousness_events WHERE user_id = $1 AND timestamp >= $2 GROUP BY event_type`
        : `SELECT event_type, COUNT(*) AS n FROM consciousness_events WHERE user_id = $1 GROUP BY event_type`,
      since ? [userId, since] : [userId],
    );
    return Object.fromEntries(rows.map((r) => [r.event_type, Number(r.n)]));
  }
  const rows = db
    .prepare(
      `SELECT event_type, COUNT(*) AS n
         FROM consciousness_events
        WHERE user_id = ? ${since ? 'AND timestamp >= ?' : ''}
        GROUP BY event_type`,
    )
    .all(...(since ? [userId, since] : [userId])) as Array<{ event_type: string; n: number }>;
  return Object.fromEntries(rows.map((r) => [r.event_type, r.n]));
}

export async function deleteEvents(userId: number, uuids: string[]): Promise<number> {
  if (uuids.length === 0) return 0;
  if (usePg) {
    const placeholders = uuids.map((_, i) => `$${i + 2}`).join(',');
    const { rowCount } = await pgQuery(
      `DELETE FROM consciousness_events WHERE user_id = $1 AND event_uuid IN (${placeholders})`,
      [userId, ...uuids],
    );
    return rowCount;
  }
  const info = db
    .prepare(
      `DELETE FROM consciousness_events
        WHERE user_id = ? AND event_uuid IN (${uuids.map(() => '?').join(',')})`,
    )
    .run(userId, ...uuids);
  return info.changes;
}

export async function deleteAllEvents(userId: number): Promise<number> {
  if (usePg) {
    const { rowCount } = await pgQuery(`DELETE FROM consciousness_events WHERE user_id = $1`, [userId]);
    return rowCount;
  }
  return db.prepare(`DELETE FROM consciousness_events WHERE user_id = ?`).run(userId).changes;
}

/**
 * Retention purge. On Postgres, production is meant to prefer DROP PARTITION
 * (drop_old_event_partitions() in the schema) for the bulk of old data; this
 * per-user DELETE remains necessary for a retention window shorter than the
 * global partition-drop horizon (see docs/PRD-REVIEW.md #6).
 */
export async function purgeExpiredEvents(): Promise<number> {
  if (usePg) {
    const { rows } = await pgQuery<{ user_id: number; data_retention_days: number }>(
      `SELECT user_id, data_retention_days FROM user_preferences WHERE auto_delete_enabled = true`,
    );
    let total = 0;
    for (const { user_id, data_retention_days } of rows) {
      const cutoff = new Date(Date.now() - data_retention_days * 86400_000).toISOString();
      const { rowCount } = await pgQuery(
        `DELETE FROM consciousness_events WHERE user_id = $1 AND timestamp < $2`,
        [user_id, cutoff],
      );
      total += rowCount;
    }
    return total;
  }

  const rows = db
    .prepare(`SELECT user_id, data_retention_days FROM user_preferences WHERE auto_delete_enabled = 1`)
    .all() as Array<{ user_id: number; data_retention_days: number }>;

  let total = 0;
  for (const { user_id, data_retention_days } of rows) {
    const cutoff = new Date(Date.now() - data_retention_days * 86400_000).toISOString();
    total += db
      .prepare(`DELETE FROM consciousness_events WHERE user_id = ? AND timestamp < ?`)
      .run(user_id, cutoff).changes;
  }
  return total;
}
