-- OneConscious — production PostgreSQL schema.
--
-- STATUS: live. The backend driver is selected at runtime by `DATABASE_URL`
-- (see src/db/index.ts's `usePg` flag) — set in production, unset in local
-- dev/tests, where SQLite (schema.sql) is used instead. Every repository in
-- src/repositories/* branches `usePg ? ... : ...` per query to serve both
-- drivers from one codepath. See docs/ARCHITECTURE.md.
--
-- Differences from the dev SQLite schema, all driven by scale:
--   * consciousness_events is RANGE PARTITIONED BY MONTH. At ~1000 events/day
--     per user and 10K users that is ~3.65B rows/year; retention has to be
--     DROP PARTITION, because a mass DELETE against that table is not viable.
--   * BIGINT identity columns — int4 exhausts at 2.1B, reachable in year one.
--   * TIMESTAMPTZ everywhere.
--   * BYTEA for ciphertext/iv/auth_tag rather than text encodings.

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- only useful if E2E is relaxed

-- ---------------------------------------------------------------- users ----

CREATE TABLE IF NOT EXISTS users (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email           TEXT        NOT NULL UNIQUE,
  password_hash   TEXT        NOT NULL,
  password_salt   TEXT        NOT NULL,
  -- Salt for the CLIENT-side data key. Not secret; the passphrase that
  -- combines with it never reaches this server.
  data_key_salt   TEXT        NOT NULL,
  key_fingerprint TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  is_active       BOOLEAN     NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS device_registry (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id     BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Randomly generated at install. NOT a hardware identifier: those are
  -- themselves sensitive and restricted on mobile platforms.
  device_id   TEXT        NOT NULL UNIQUE,
  device_name TEXT        NOT NULL,
  device_type TEXT        NOT NULL CHECK (device_type IN ('mac','windows','linux','android','ios')),
  os_version  TEXT,
  app_version TEXT,
  last_sync   TIMESTAMPTZ,
  is_active   BOOLEAN     NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_user ON device_registry(user_id);

-- ------------------------------------------------- consciousness_events ----

-- Partition key must be part of the primary key, so the PK is composite.
-- (user_id, event_uuid) uniqueness is enforced per-partition, which is
-- sufficient: sync retries always carry the same timestamp, so a replayed
-- event lands in the same partition.
CREATE TABLE IF NOT EXISTS consciousness_events (
  id          BIGINT GENERATED ALWAYS AS IDENTITY,
  user_id     BIGINT      NOT NULL,
  event_uuid  UUID        NOT NULL,
  device_id   TEXT        NOT NULL,
  event_type  TEXT        NOT NULL CHECK (event_type IN ('browsing','search','youtube','file','app','code','ai_session')),
  ciphertext  BYTEA       NOT NULL,
  iv          BYTEA       NOT NULL,
  auth_tag    BYTEA       NOT NULL,
  timestamp   TIMESTAMPTZ NOT NULL,
  synced_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (id, timestamp),
  CONSTRAINT consciousness_events_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) PARTITION BY RANGE (timestamp);

CREATE UNIQUE INDEX IF NOT EXISTS idx_events_idem
  ON consciousness_events (user_id, event_uuid, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_user_time
  ON consciousness_events (user_id, timestamp DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_events_user_type
  ON consciousness_events (user_id, event_type, timestamp DESC);

-- One-time upgrade path for a database created before 'ai_session' existed:
-- CREATE TABLE IF NOT EXISTS above is a no-op against an already-live table,
-- so the old CHECK constraint (no 'ai_session') would otherwise stick around
-- forever. Guarded so it costs nothing on a fresh install (constraint is
-- already correct from creation) or on any later boot (constraint already
-- updated) — the DROP+ADD only actually runs once, the first time this file
-- executes against a pre-existing database.
DO $$
DECLARE
  con RECORD;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'consciousness_events'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%ai_session%'
  ) THEN
    -- Match on the column name only, not the syntax used to write the check:
    -- Postgres normalizes `event_type IN (...)` to `event_type = ANY (ARRAY[...])`
    -- internally, so a `LIKE '%IN%'` filter here would never match anything.
    FOR con IN
      SELECT conname FROM pg_constraint
      WHERE conrelid = 'consciousness_events'::regclass
        AND contype = 'c'
        AND pg_get_constraintdef(oid) LIKE '%event_type%'
    LOOP
      EXECUTE format('ALTER TABLE consciousness_events DROP CONSTRAINT %I', con.conname);
    END LOOP;

    ALTER TABLE consciousness_events
      ADD CONSTRAINT consciousness_events_event_type_check
      CHECK (event_type IN ('browsing','search','youtube','file','app','code','ai_session'));
  END IF;
END $$;

-- Default partition is a SAFETY NET, not a destination. It stops an insert
-- failing because a month was not provisioned, but rows landing here have two
-- real costs:
--   1. they are invisible to drop_old_event_partitions(), so retention silently
--      stops working for them;
--   2. the planner must scan it for every bounded-range query, since it could
--      hold any timestamp — which defeats pruning.
--
-- Alert if this table is ever non-empty:
--   SELECT count(*) FROM consciousness_events_default;
CREATE TABLE IF NOT EXISTS consciousness_events_default
  PARTITION OF consciousness_events DEFAULT;

/**
 * Create the partition for a given month if absent. Run monthly, ahead of time
 * (e.g. pg_cron), so writes never fall into the default partition.
 */
CREATE OR REPLACE FUNCTION ensure_events_partition(target DATE)
RETURNS void AS $$
DECLARE
  start_date DATE := date_trunc('month', target)::DATE;
  end_date   DATE := (date_trunc('month', target) + INTERVAL '1 month')::DATE;
  part_name  TEXT := format('consciousness_events_%s', to_char(start_date, 'YYYY_MM'));
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
    EXECUTE format(
      'CREATE TABLE %I PARTITION OF consciousness_events FOR VALUES FROM (%L) TO (%L)',
      part_name, start_date, end_date);
  END IF;
END;
$$ LANGUAGE plpgsql;

/**
 * Retention. Drops whole partitions older than the cutoff — O(1) per month,
 * versus a DELETE that would rewrite billions of rows.
 *
 * NOTE: this is coarser than the per-user data_retention_days setting. A user
 * asking for 30-day retention still needs a targeted DELETE; partition drop
 * enforces only the global maximum. Both are required.
 */
CREATE OR REPLACE FUNCTION drop_old_event_partitions(keep_months INT)
RETURNS INT AS $$
DECLARE
  cutoff DATE := (date_trunc('month', now()) - (keep_months || ' months')::INTERVAL)::DATE;
  part   RECORD;
  dropped INT := 0;
BEGIN
  FOR part IN
    SELECT c.relname
      FROM pg_class c
      JOIN pg_inherits i ON i.inhrelid = c.oid
      JOIN pg_class p ON p.oid = i.inhparent
     WHERE p.relname = 'consciousness_events'
       AND c.relname ~ '^consciousness_events_\d{4}_\d{2}$'
       AND to_date(right(c.relname, 7), 'YYYY_MM') < cutoff
  LOOP
    EXECUTE format('DROP TABLE %I', part.relname);
    dropped := dropped + 1;
  END LOOP;
  RETURN dropped;
END;
$$ LANGUAGE plpgsql;

/**
 * Provision an inclusive range of months.
 *
 * Backward coverage matters as much as forward: a device returning from a long
 * offline stretch, or an import from another instance, carries older
 * timestamps. Without partitions for those months every such row lands in the
 * default partition and escapes retention.
 */
CREATE OR REPLACE FUNCTION ensure_events_partitions(months_back INT, months_forward INT)
RETURNS INT AS $$
DECLARE
  m INT;
  created INT := 0;
BEGIN
  FOR m IN -months_back..months_forward LOOP
    PERFORM ensure_events_partition((date_trunc('month', now()) + (m || ' months')::INTERVAL)::DATE);
    created := created + 1;
  END LOOP;
  RETURN created;
END;
$$ LANGUAGE plpgsql;

/**
 * Move anything that fell into the default partition into a real one.
 * Run after provisioning new ranges. Requires an ACCESS EXCLUSIVE lock on the
 * default partition, so schedule it off-peak.
 */
CREATE OR REPLACE FUNCTION rescue_default_partition()
RETURNS INT AS $$
DECLARE
  moved INT := 0;
  r RECORD;
BEGIN
  -- Order matters. CREATE TABLE ... PARTITION OF revalidates the default
  -- partition and fails if it holds any row belonging to the new range, so
  -- the rows must be evacuated BEFORE the partitions are created.
  CREATE TEMP TABLE _rescued ON COMMIT DROP AS
    SELECT * FROM consciousness_events_default;

  DELETE FROM consciousness_events_default;

  FOR r IN SELECT DISTINCT date_trunc('month', timestamp)::DATE AS m FROM _rescued LOOP
    PERFORM ensure_events_partition(r.m);
  END LOOP;

  INSERT INTO consciousness_events
    (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp, synced_at)
  SELECT user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp, synced_at
    FROM _rescued;

  GET DIAGNOSTICS moved = ROW_COUNT;
  RETURN moved;
END;
$$ LANGUAGE plpgsql;

-- Cover the default 90-day retention window backwards plus three months ahead,
-- so neither a late-syncing device nor a lapsed cron lands rows in default.
SELECT ensure_events_partitions(4, 3);

-- ------------------------------------------------------- integrations -----

-- Replaces the PRD's allow_claude/allow_chatgpt booleans, which could not be
-- enforced: MCP servers authenticate a credential, not a model identity.
CREATE TABLE IF NOT EXISTS integrations (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label        TEXT        NOT NULL,
  token_hash   TEXT        NOT NULL UNIQUE,
  scopes       TEXT[]      NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_integrations_user ON integrations(user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT        NOT NULL UNIQUE,
  device_id  TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked    BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expiry ON refresh_tokens(expires_at) WHERE NOT revoked;

-- ---------------------------------------------------------- audit_logs -----

-- `claimed_ai_model` is UNVERIFIED — a self-reported string from the caller.
-- It must never be presented as an audit fact. integration_id is the
-- verifiable identity.
CREATE TABLE IF NOT EXISTS audit_logs (
  id               BIGINT GENERATED ALWAYS AS IDENTITY,
  user_id          BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action           TEXT        NOT NULL,
  integration_id   BIGINT      REFERENCES integrations(id) ON DELETE SET NULL,
  claimed_ai_model TEXT,
  timestamp        TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip_address       INET,
  user_agent       TEXT,
  details          JSONB,
  PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE IF NOT EXISTS audit_logs_default PARTITION OF audit_logs DEFAULT;

CREATE INDEX IF NOT EXISTS idx_audit_user_action
  ON audit_logs (user_id, action, timestamp DESC);

-- --------------------------------------------------------- passkeys -------

-- Two independent jobs, deliberately kept separate:
--   1. AUTHENTICATION — the server verifies a signature against public_key;
--      no shared secret exists to steal or phish.
--   2. KEY UNWRAP — wrapped_key is the data key sealed with a KEK the
--      authenticator derives via the WebAuthn PRF extension. The PRF output
--      never leaves the client, so the server stores ciphertext it cannot open.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id        BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id  TEXT        NOT NULL UNIQUE,
  public_key     BYTEA       NOT NULL,
  counter        BIGINT      NOT NULL DEFAULT 0,
  transports     TEXT[],
  device_label   TEXT        NOT NULL,
  backed_up      BOOLEAN     NOT NULL DEFAULT false,
  prf_salt       TEXT,
  wrapped_key    BYTEA,
  wrapped_key_iv BYTEA,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

-- Server-issued, single-use, short-lived. Held server-side so a replayed or
-- client-chosen challenge cannot be accepted.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  challenge  TEXT        NOT NULL UNIQUE,
  user_id    BIGINT      REFERENCES users(id) ON DELETE CASCADE,  -- NULL for discoverable login
  kind       TEXT        NOT NULL CHECK (kind IN ('registration','authentication')),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed   BOOLEAN     NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenge_expiry ON webauthn_challenges(expires_at);

-- ------------------------------------------------- remote_access_grants ----
-- Per-user opt-in for REMOTE (server-side decrypting) AI access, e.g. ChatGPT
-- over the hosted MCP server. Enabling this is a deliberate, disclosed
-- weakening of E2E: the server stores a copy of the data key wrapped with a
-- server-held KEK (REMOTE_ACCESS_KEK, see config/env.ts) so it can decrypt on
-- the user's behalf for unattended remote clients. Local MCP tools (Claude
-- Desktop/Cursor/Kiro) never touch this table and stay fully E2E regardless.

CREATE TABLE IF NOT EXISTS remote_access_grants (
  id                        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id                   BIGINT      NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  enabled                   BOOLEAN     NOT NULL DEFAULT false,
  wrapped_data_key          BYTEA,
  wrapped_data_key_iv       BYTEA,
  wrapped_data_key_auth_tag BYTEA,
  -- Lets a future KEK rotation (e.g. move to KMS) be introduced without a
  -- breaking migration: unwrap logic branches on this.
  kek_version               SMALLINT    NOT NULL DEFAULT 1,
  enabled_at                TIMESTAMPTZ,
  disabled_at               TIMESTAMPTZ,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------- settings ------

CREATE TABLE IF NOT EXISTS user_preferences (
  id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id               BIGINT      NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  collection_enabled    BOOLEAN     NOT NULL DEFAULT true,
  collect_browsing      BOOLEAN     NOT NULL DEFAULT true,
  collect_searches      BOOLEAN     NOT NULL DEFAULT true,
  collect_youtube       BOOLEAN     NOT NULL DEFAULT true,
  collect_files         BOOLEAN     NOT NULL DEFAULT false,
  collect_code_activity BOOLEAN     NOT NULL DEFAULT true,
  collect_apps          BOOLEAN     NOT NULL DEFAULT true,
  data_retention_days   INT         NOT NULL DEFAULT 90 CHECK (data_retention_days BETWEEN 1 AND 730),
  auto_delete_enabled   BOOLEAN     NOT NULL DEFAULT true,
  timezone              TEXT        NOT NULL DEFAULT 'UTC',
  language              TEXT        NOT NULL DEFAULT 'en',
  theme                 TEXT        NOT NULL DEFAULT 'auto' CHECK (theme IN ('light','dark','auto')),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Synced across devices for convenience. NOT the enforcement point: filtering
-- happens on-device at collection time. Patterns are matched as literal
-- substrings, never as regex — user-supplied regex evaluated server-side
-- would be a ReDoS vector.
CREATE TABLE IF NOT EXISTS blocked_patterns (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pattern_type TEXT        NOT NULL CHECK (pattern_type IN ('domain','query_term','path_prefix')),
  pattern      TEXT        NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, pattern_type, pattern)
);

-- --------------------------------------------------------------- chat -----

-- Plain (not E2E-encrypted, unlike consciousness_events): chat content is
-- already visible to the LLM provider mid-conversation, so server-side
-- plaintext storage adds no new exposure and keeps sync/search simple.
CREATE TABLE IF NOT EXISTS chat_sessions (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT        NOT NULL DEFAULT 'New chat',
  kind       TEXT        NOT NULL DEFAULT 'text' CHECK (kind IN ('text','voice')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_user ON chat_sessions(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  session_id BIGINT      NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
  -- Denormalized from the session so an ownership check is one indexed
  -- lookup instead of a join, on every message read/write.
  user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT        NOT NULL CHECK (role IN ('user','assistant')),
  content    TEXT        NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_blocked_user ON blocked_patterns(user_id);
