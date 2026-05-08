-- 0001_init.sql — initial schema baseline
--
-- Captures the post-Phase-3 state of every table the Archer server
-- needs, including columns that previous Archer versions added via
-- inline ALTER statements (the dataset→sensor column rename in
-- findings, the detail column in suppressions, and the status column
-- in users). Those ALTERs are no longer separate migrations because
-- they were already applied on every existing install before the
-- migration framework landed; the framework's bootstrap-stamp logic
-- marks this version as applied on existing installs without re-running
-- it, so operator data is preserved untouched.
--
-- IF NOT EXISTS is used throughout because this migration runs in the
-- same code path as the bootstrap detection — defensive against any
-- partial-state install. Future migrations should use stricter forms
-- (no IF NOT EXISTS) so any inconsistency surfaces as a startup error
-- instead of being silently papered over.

-- Operator config: allowlist and IOC list. Slice-backed in memory;
-- SQLite rowid order is the source of truth for save/reload ordering.
CREATE TABLE IF NOT EXISTS allowlist (entry TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS ioc_list  (entry TEXT PRIMARY KEY);

-- Findings — analyst-visible event rows. Includes the post-rename
-- "sensor" column (formerly "dataset" in pre-Quiver schemas). intervals
-- and ts_data carry per-finding chart data; notes is a JSON array of
-- operator/escalation entries.
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY,
    type         TEXT,
    severity     TEXT,
    score        INTEGER,
    src_ip       TEXT,
    dst_ip       TEXT,
    dst_port     TEXT,
    detail       TEXT,
    timestamp    TEXT,
    source_file  TEXT,
    status       TEXT,
    analyst      TEXT,
    analyst_note TEXT,
    status_ts    TEXT,
    ioc_match    INTEGER DEFAULT 0,
    is_new       INTEGER DEFAULT 0,
    sensor       TEXT,
    intervals    TEXT,
    ts_data      TEXT,
    notes        TEXT
);

-- Single-row settings blob. config column is a JSON-encoded
-- internal/config.Config. Multiple rows would be a bug — id is always 1.
CREATE TABLE IF NOT EXISTS settings (
    id     INTEGER PRIMARY KEY,
    config TEXT NOT NULL
);

-- Suppressions — analyst-quieting for noisy targets. Includes the
-- post-ALTER detail column.
CREATE TABLE IF NOT EXISTS suppressions (
    target TEXT PRIMARY KEY,
    expiry INTEGER NOT NULL,
    detail TEXT DEFAULT ''
);

-- Sensors — Quiver-enrolled (or formerly enrolled) endpoints. The
-- partial unique index allows a name to be re-used after disenrollment;
-- only one currently-active sensor per name is enforced at a time.
CREATE TABLE IF NOT EXISTS sensors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    host            TEXT,
    source_ip       TEXT,
    enrolled_at     INTEGER NOT NULL,
    enrolled_by     TEXT,
    status          TEXT NOT NULL DEFAULT 'enrolled',
    pubkey_fp       TEXT,
    authkey_line    TEXT,
    schedule_hour   INTEGER NOT NULL DEFAULT 2,
    schedule_minute INTEGER NOT NULL DEFAULT 0,
    last_seen_at    INTEGER DEFAULT 0,
    last_files      INTEGER DEFAULT 0,
    last_bytes      INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sensors_active_name
    ON sensors(name) WHERE status IN ('enrolled','disenrolling');

-- Enrollment tokens — single-use, time-bounded sensor enrollment auth.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token         TEXT NOT NULL UNIQUE,
    override_name TEXT,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    used_at       INTEGER DEFAULT 0,
    created_by    TEXT,
    consumed_by   TEXT
);

-- Unauthorized attempts — checkin from a name we don't recognize.
-- Composite-unique on (name, source_ip) so we upsert on the next
-- attempt from the same source instead of growing the row count.
CREATE TABLE IF NOT EXISTS unauthorized_attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    source_ip     TEXT NOT NULL,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    pinned        INTEGER NOT NULL DEFAULT 0,
    UNIQUE(name, source_ip)
);

-- Users — analyst accounts. Includes the post-ALTER status column
-- (active / pending). Sessions live in memory only and are not part
-- of the persisted schema.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    first_name    TEXT    NOT NULL DEFAULT '',
    last_name     TEXT    NOT NULL DEFAULT '',
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'analyst',
    status        TEXT    NOT NULL DEFAULT 'active',
    created_at    TEXT    NOT NULL
);
