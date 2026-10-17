import Database from 'better-sqlite3';
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { env } from '../config/env.js';
import { runPostgresMigrations } from './postgres.js';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * SQLite is the default — zero setup, no external service, matches the
 * README's "clone and run" promise. Postgres (via DATABASE_URL) is what a
 * real deployment uses instead: see docs/ARCHITECTURE.md for why (mainly
 * scale — SQLite has no answer to partitioned retention at the row counts
 * the PRD targets).
 *
 * Every repository file branches on `usePg` internally rather than this
 * module picking one implementation to export, because the two engines
 * genuinely need different SQL (placeholder syntax, boolean/array/JSON
 * column types, partition-aware uniqueness) — there is no single query
 * string that is correct against both.
 */
export const usePg = Boolean(env.DATABASE_URL);

// Only opened when actually needed, so a Postgres-configured deployment
// never touches the filesystem for a SQLite file it will never use.
export const db = usePg
  ? (null as unknown as Database.Database)
  : (() => {
      const dbPath = resolve(process.cwd(), env.DATABASE_PATH);
      mkdirSync(dirname(dbPath), { recursive: true });
      const d = new Database(dbPath);
      d.pragma('journal_mode = WAL');
      d.pragma('foreign_keys = ON');
      return d;
    })();

export async function runMigrations(): Promise<void> {
  if (usePg) {
    await runPostgresMigrations();
    return;
  }
  let schemaPath = process.env.ONECON_SCHEMA_PATH ?? resolve(here, 'schema.sql');
  try {
    readFileSync(schemaPath);
  } catch {
    schemaPath = resolve(process.cwd(), 'src/db/schema.sql');
  }
  db.exec(readFileSync(schemaPath, 'utf8'));
}

export function nowIso(): string {
  return new Date().toISOString();
}
