import pg from 'pg';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { env } from '../config/env.js';

const { Pool } = pg;
const here = dirname(fileURLToPath(import.meta.url));

/**
 * node-postgres returns BIGINT (OID 20) columns as strings by default, to
 * avoid silent precision loss past Number.MAX_SAFE_INTEGER. Every BIGINT in
 * this schema (id, user_id, integration_id, ...) is a row count that will
 * never get remotely close to that ceiling, so the safety net just becomes a
 * footgun: code that does `row.user_id !== req.userId` (a real number, from
 * `Number(jwt.sub)`) silently fails ("9" !== 9) even when they're the same
 * user. Coercing to number globally, once, here, matches what every
 * repository's TypeScript types already claim (`user_id: number`) and avoids
 * relying on every call site remembering to coerce.
 */
pg.types.setTypeParser(20, (val: string) => parseInt(val, 10));

/**
 * Postgres pool for production (Supabase or any managed Postgres).
 *
 * Uses the pooler (Supavisor/PgBouncer) in SESSION mode, not transaction
 * mode: this backend is a long-lived Express process, not serverless, and
 * session mode is what Supabase's own docs recommend for that shape — it
 * also avoids transaction mode's "no prepared statements" caveat, which
 * node-postgres relies on for parameterized queries.
 *
 * `rejectUnauthorized: false` because Supabase's pooler presents a
 * certificate chain that Node's default trust store does not always
 * validate cleanly; the connection itself is still encrypted (TLS), this
 * only skips CA verification. Fine for a managed provider's own endpoint;
 * would not be fine for an arbitrary user-supplied host.
 */
export const pgPool = env.DATABASE_URL
  ? (() => {
      const pool = new Pool({
        connectionString: env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        max: 10,
        // Managed providers (Supabase's pooler) drop idle or half-dead pooled
        // connections. These bounds keep us from handing out a stale client and
        // from queueing indefinitely behind one.
        connectionTimeoutMillis: 10_000,
        idleTimeoutMillis: 30_000,
        maxUses: 500,
      });

      // node-postgres `Pool` extends EventEmitter. When the provider terminates a
      // pooled client, the pool emits an `error` event; with no listener this
      // becomes an unhandled rejection that surfaces as `[unhandled] ... Connection
      // terminated unexpectedly` and makes in-flight requests fail without a JSON
      // body (the desktop sees `502 request_failed` and marks itself Offline).
      // Listening—and logging—lets the pool discard the dead client and continue.
      pool.on('error', (err) => {
        console.error('[postgres] pooled client error (dropped by provider):', err?.message ?? err);
      });

      return pool;
    })()
  : null;

export async function pgQuery<T = Record<string, unknown>>(
  text: string,
  params: unknown[] = [],
): Promise<{ rows: T[]; rowCount: number }> {
  if (!pgPool) throw new Error('pgQuery called without DATABASE_URL configured');
  try {
    const result = await pgPool.query(text, params);
    return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
  } catch (err) {
    // Transient provider drops (Supabase session pooler terminating an idle
    // client mid-query) appear as ECONNRESET / "Connection terminated". One
    // immediate retry on a fresh connection usually succeeds; anything else we
    // rethrow for the request handler to map to a proper error response.
    if (isConnectionDrop(err)) {
      const msg = (err as { message?: string })?.message ?? String(err);
      console.warn(`[postgres] connection dropped during query, retrying once (${msg})`);
      const result = await pgPool.query(text, params);
      return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
    }
    throw err;
  }
}

function isConnectionDrop(err: unknown): boolean {
  const code = (err as { code?: string })?.code;
  const msg = (err as { message?: string })?.message ?? String(err);
  return (
    code === '57P01' || // admin_shutdown
    code === '57P02' || // crash_shutdown
    code === '57P03' || // cannot_connect_now
    code === '08006' || // connection_failure
    code === '08003' || // connection_does_not_exist
    /ECONNRESET|terminated unexpectedly|Connection terminated/i.test(msg)
  );
}

/** Run a sequence of queries on one connection inside a transaction. */
export async function pgTransaction<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  if (!pgPool) throw new Error('pgTransaction called without DATABASE_URL configured');
  const client = await pgPool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export async function runPostgresMigrations(): Promise<void> {
  let schemaPath = process.env.ONECON_PG_SCHEMA_PATH ?? resolve(here, 'postgres-schema.sql');
  try {
    readFileSync(schemaPath);
  } catch {
    schemaPath = resolve(process.cwd(), 'src/db/postgres-schema.sql');
  }
  const sql = readFileSync(schemaPath, 'utf8');
  // Multiple semicolon-separated statements in one string use the simple
  // query protocol, same as better-sqlite3's db.exec() for the SQLite path.
  await pgPool!.query(sql);
}

/**
 * Keeps consciousness_events partitioned by month without manual attention:
 * mints the next few months' tables ahead of time (idempotent — CREATE TABLE
 * IF NOT EXISTS under the hood) and drops partitions old enough that no
 * per-user retention setting (max 730 days, see postgres-schema.sql) could
 * still need them. Without this, events for a month with no partition yet
 * silently fall into consciousness_events_default, which the retention purge
 * cannot see — see docs/PRD-REVIEW.md #6.
 *
 * Idempotent and cheap; safe to call on every retention sweep rather than on
 * its own schedule.
 */
export async function runPartitionMaintenance(): Promise<void> {
  if (!pgPool) return;
  await pgQuery(`SELECT ensure_events_partitions($1, $2)`, [1, 3]);
  await pgQuery(`SELECT drop_old_event_partitions($1)`, [25]);
}

export async function closePostgres(): Promise<void> {
  await pgPool?.end();
}
