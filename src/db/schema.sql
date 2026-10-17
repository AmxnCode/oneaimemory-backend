-- OneConscious schema (SQLite dev dialect).
--
-- Applies the fixes from docs/PRD-REVIEW.md issue #4:
--   * 64-bit ids (SQLite INTEGER PRIMARY KEY is already 64-bit; Postgres uses
--     BIGINT GENERATED ALWAYS AS IDENTITY)
--   * event_uuid uniqueness for idempotent sync retries
--   * iv/auth_tag as BLOB, not VARCHAR
--   * UNIQUE(user_id) on preferences
--   * ISO-8601 UTC timestamps throughout (TIMESTAMPTZ in Postgres)
--   * integrations table replacing the unenforceable allow_<model> booleans
--
-- The Postgres migration additionally range-partitions consciousness_events on
-- timestamp (monthly) so retention becomes DROP PARTITION rather than a mass
-- DELETE. See docs/ARCHITECTURE.md.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  email          TEXT    NOT NULL UNIQUE,
  password_hash  TEXT    NOT NULL,
  password_salt  TEXT    NOT NULL,
  -- Salt for the client-side data key. NOT secret: the key is derived from it
  -- plus the user's passphrase, which the server never sees.
  data_key_salt  TEXT    NOT NULL,
  -- Non-reversible fingerprint of the client data key. Lets a client detect a
  -- wrong passphrase without downloading events it cannot decrypt.
  key_fingerprint TEXT,
  created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  is_active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS device_registry (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Randomly generated at install. NOT a hardware identifier: persistent
  -- hardware ids are restricted by Play policy and are themselves sensitive.
  device_id          TEXT    NOT NULL UNIQUE,
  device_name        TEXT    NOT NULL,
  device_type        TEXT    NOT NULL CHECK (device_type IN ('mac','windows','linux','android','ios')),
  os_version         TEXT,
  app_version        TEXT,
  last_sync          TEXT,
  is_active          INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_device_user ON device_registry(user_id);

-- Encrypted activity. The server can range-scan by timestamp and filter by
-- type, but cannot read payloads: `ciphertext` is AES-256-GCM sealed with a key
-- derived on-device. Cleartext metadata is bound as AAD, so tampering with
-- `type` or `timestamp` here makes the row fail to decrypt rather than
-- silently returning a mislabeled event.
CREATE TABLE IF NOT EXISTS consciousness_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_uuid  TEXT    NOT NULL,
  device_id   TEXT    NOT NULL,
  event_type  TEXT    NOT NULL CHECK (event_type IN ('browsing','search','youtube','file','app','code','ai_session')),
  ciphertext  BLOB    NOT NULL,
  iv          BLOB    NOT NULL,
  auth_tag    BLOB    NOT NULL,
  timestamp   TEXT    NOT NULL,
  synced_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (user_id, event_uuid)
);

CREATE INDEX IF NOT EXISTS idx_events_user_time ON consciousness_events(user_id, timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_events_user_type ON consciousness_events(user_id, event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_device    ON consciousness_events(device_id);

-- Scoped credentials for AI integrations.
--
-- Replaces the PRD's allow_claude/allow_chatgpt booleans, which could not be
-- enforced: MCP servers authenticate a credential, not a model identity, and
-- "I am Claude" is an unverifiable self-reported string. Access binds to a
-- token the user issues and can revoke.
CREATE TABLE IF NOT EXISTS integrations (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label         TEXT    NOT NULL,
  token_hash    TEXT    NOT NULL UNIQUE,
  scopes        TEXT    NOT NULL,          -- JSON array
  created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_used_at  TEXT,
  revoked_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_integrations_user ON integrations(user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  device_id   TEXT,
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);

-- Access log. `claimed_ai_model` is UNVERIFIED — it is a self-reported string
-- from the caller and must never be presented as an audit fact. The verifiable
-- identity is integration_id.
CREATE TABLE IF NOT EXISTS audit_logs (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action            TEXT    NOT NULL,
  integration_id    INTEGER REFERENCES integrations(id) ON DELETE SET NULL,
  claimed_ai_model  TEXT,
  timestamp         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ip_address        TEXT,
  user_agent        TEXT,
  details           TEXT                    -- JSON
);

CREATE INDEX IF NOT EXISTS idx_audit_user_action ON audit_logs(user_id, action, timestamp DESC);

CREATE TABLE IF NOT EXISTS user_preferences (
  id                     INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id                INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  collection_enabled     INTEGER NOT NULL DEFAULT 1,
  collect_browsing       INTEGER NOT NULL DEFAULT 1,
  collect_searches       INTEGER NOT NULL DEFAULT 1,
  collect_youtube        INTEGER NOT NULL DEFAULT 1,
  collect_files          INTEGER NOT NULL DEFAULT 0,
  collect_code_activity  INTEGER NOT NULL DEFAULT 1,
  collect_apps           INTEGER NOT NULL DEFAULT 1,
  data_retention_days    INTEGER NOT NULL DEFAULT 90,
  auto_delete_enabled    INTEGER NOT NULL DEFAULT 1,
  timezone               TEXT    NOT NULL DEFAULT 'UTC',
  language               TEXT    NOT NULL DEFAULT 'en',
  theme                  TEXT    NOT NULL DEFAULT 'auto',
  created_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Passkeys (WebAuthn).
--
-- Two independent jobs, deliberately kept separate:
--   1. AUTHENTICATION — replaces the password. The server verifies a signature
--      against `public_key`; no shared secret exists to steal or phish.
--   2. KEY UNWRAP — `wrapped_key` is the user's data key sealed with a KEK the
--      authenticator derives via the WebAuthn PRF extension. The PRF output
--      never leaves the client, so the server stores ciphertext it cannot open.
--      This is what lets a user unlock without retyping the passphrase while
--      keeping the end-to-end property intact.
--
-- `wrapped_key` is nullable: a credential can do (1) without (2) when the
-- authenticator or browser lacks PRF support.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id  TEXT    NOT NULL UNIQUE,   -- base64url
  public_key     BLOB    NOT NULL,
  counter        INTEGER NOT NULL DEFAULT 0,
  transports     TEXT,                      -- JSON array
  device_label   TEXT    NOT NULL,
  backed_up      INTEGER NOT NULL DEFAULT 0,
  -- Per-credential PRF salt. Not secret; the secret is the authenticator's
  -- HMAC over it, which never leaves the device.
  prf_salt       TEXT,
  wrapped_key    BLOB,
  wrapped_key_iv BLOB,
  created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_used_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

-- Server-issued, single-use, short-lived. Held server-side so a replayed or
-- client-chosen challenge cannot be accepted.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge  TEXT    NOT NULL UNIQUE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,  -- NULL for discoverable login
  kind       TEXT    NOT NULL CHECK (kind IN ('registration','authentication')),
  expires_at TEXT    NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenge_expiry ON webauthn_challenges(expires_at);

-- Per-user opt-in for REMOTE (server-side decrypting) AI access, e.g. ChatGPT
-- over the hosted MCP server. Enabling this is a deliberate, disclosed
-- weakening of E2E: the server stores a copy of the data key wrapped with a
-- server-held KEK (REMOTE_ACCESS_KEK, see config/env.ts) so it can decrypt on
-- the user's behalf for unattended remote clients. Local MCP tools (Claude
-- Desktop/Cursor/Kiro) never touch this table and stay fully E2E regardless.
CREATE TABLE IF NOT EXISTS remote_access_grants (
  id                        INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id                   INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  enabled                   INTEGER NOT NULL DEFAULT 0,
  wrapped_data_key          BLOB,     -- NULL unless enabled
  wrapped_data_key_iv       BLOB,
  wrapped_data_key_auth_tag BLOB,
  -- Lets a future KEK rotation (e.g. move to KMS) be introduced without a
  -- breaking migration: unwrap logic branches on this.
  kek_version               INTEGER NOT NULL DEFAULT 1,
  enabled_at                TEXT,
  disabled_at               TEXT,
  created_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Synced across devices for convenience. NOT the enforcement point: filtering
-- happens on-device at collection time (see packages/shared/src/redaction.ts).
-- Patterns are matched as literal substrings, never as regex — a user-supplied
-- regex evaluated server-side would be a ReDoS vector.
CREATE TABLE IF NOT EXISTS blocked_patterns (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pattern_type  TEXT    NOT NULL CHECK (pattern_type IN ('domain','query_term','path_prefix')),
  pattern       TEXT    NOT NULL,
  created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (user_id, pattern_type, pattern)
);

CREATE INDEX IF NOT EXISTS idx_blocked_user ON blocked_patterns(user_id);

-- Plain (not E2E-encrypted, unlike consciousness_events): chat content is
-- already visible to the LLM provider mid-conversation, so server-side
-- plaintext storage adds no new exposure and keeps sync/search simple.
CREATE TABLE IF NOT EXISTS chat_sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT    NOT NULL DEFAULT 'New chat',
  kind       TEXT    NOT NULL DEFAULT 'text' CHECK (kind IN ('text','voice')),
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_user ON chat_sessions(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
  -- Denormalized from the session so an ownership check is one indexed
  -- lookup instead of a join, on every message read/write.
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT    NOT NULL CHECK (role IN ('user','assistant')),
  content    TEXT    NOT NULL,
  created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_id, created_at ASC);
