-- Phase 7 slice 1 — feed-aggregator schema.
--
-- Two tables. `feeds` is the configured-feed list (one row per MISP /
-- OpenCTI / future-source-type instance the operator has wired up).
-- `feed_indicators` is the per-feed indicator stream — IPs, CIDRs,
-- domains, file hashes — that the fetcher worker pulls on the
-- per-feed cadence and dedupes against existing rows.
--
-- Slice 1 only creates the tables and indexes. The fetcher worker,
-- source-type adapters (slices 2 and 3), matcher integration (also
-- slice 1 but in Go code), and provenance plumbing (slice 4) land in
-- subsequent commits.

CREATE TABLE feeds (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type              TEXT NOT NULL CHECK(source_type IN ('misp','opencti')),
    name                     TEXT NOT NULL UNIQUE,
    url                      TEXT NOT NULL,
    api_key                  TEXT NOT NULL DEFAULT '',
    refresh_cadence_minutes  INTEGER NOT NULL DEFAULT 60,
    indicator_aging_days     INTEGER NOT NULL DEFAULT 30,
    last_refresh_at          INTEGER NOT NULL DEFAULT 0,
    last_indicator_count     INTEGER NOT NULL DEFAULT 0,
    last_error               TEXT NOT NULL DEFAULT '',
    status                   TEXT NOT NULL DEFAULT 'idle',
    enabled                  INTEGER NOT NULL DEFAULT 1,
    created_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL
);

CREATE TABLE feed_indicators (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id         INTEGER NOT NULL,
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL CHECK(indicator_type IN ('ip','domain','cidr','hash')),
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    source_id       TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (feed_id) REFERENCES feeds(id) ON DELETE CASCADE
);

CREATE INDEX idx_feed_indicators_feed_id   ON feed_indicators(feed_id);
CREATE INDEX idx_feed_indicators_indicator ON feed_indicators(indicator);
CREATE INDEX idx_feed_indicators_last_seen ON feed_indicators(last_seen);
