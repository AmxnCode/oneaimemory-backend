import { env } from './config/env.js';
import { db, usePg } from './db/index.js';
import { closePostgres, runPartitionMaintenance } from './db/postgres.js';
import { createApp } from './app.js';
import { purgeExpiredEvents } from './repositories/events.js';
import { purgeExpired as purgeExpiredTokens } from './repositories/refreshTokens.js';

const app = await createApp();

const server = app.listen(env.PORT, () => {
  console.log(`OneConscious backend  →  http://localhost:${env.PORT}`);
  console.log(`  env=${env.NODE_ENV}  db=${usePg ? 'postgres' : env.DATABASE_PATH}`);
  if (!env.isProduction) {
    console.log('  NOTE: dev mode. Payloads are E2E encrypted; this server cannot read them.');
  }
});

// Retention sweep. Hourly here; in production this belongs in a separate job
// so a restart cannot skip it and so it can DROP PARTITION instead of DELETE.
//
// Also keeps the events table's monthly partitions ahead of schedule: without
// this, a month with no partition yet silently routes new events into the
// default partition, where the purge above cannot find them. Runs once at
// boot too, so a restart that missed the last sweep catches up immediately
// instead of waiting up to an hour.
async function runRetentionSweep() {
  try {
    if (usePg) await runPartitionMaintenance();
    const events = await purgeExpiredEvents();
    const tokens = await purgeExpiredTokens();
    if (events || tokens) console.log(`[retention] purged ${events} events, ${tokens} tokens`);
  } catch (err) {
    console.error('[retention] failed', err);
  }
}

void runRetentionSweep();
const retentionTimer = setInterval(() => void runRetentionSweep(), 3600_000);
retentionTimer.unref();

function shutdown(signal: string) {
  console.log(`\n${signal} received, shutting down`);
  server.close(() => {
    void (async () => {
      if (usePg) await closePostgres();
      else db.close();
      process.exit(0);
    })();
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
