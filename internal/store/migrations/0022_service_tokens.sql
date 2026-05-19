-- v0.30.0: service-account tokens for /api/sensors/health.
-- Allows Prometheus/Nagios to scrape the health endpoint without
-- a browser session. Tokens are generated as 32-byte random values
-- (prefix "archer_") and stored only as their SHA-256 hash so the
-- raw credential is never at rest in the database.

CREATE TABLE service_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT    NOT NULL,
    token_hash  TEXT    NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    created_by  TEXT    NOT NULL DEFAULT ''
);
