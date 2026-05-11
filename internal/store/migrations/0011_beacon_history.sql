-- 0011_beacon_history.sql
-- v0.16.0 — beacon evolution history.
--
-- One row per beacon per UTC day, captured at SetFindings time when a
-- Beaconing or HTTP Beaconing finding lands. The (fingerprint, day_utc)
-- PRIMARY KEY enforces "first pass of the UTC day wins" via INSERT
-- … ON CONFLICT DO NOTHING — analysts see the morning's score for that
-- day, not the noon re-run that might be temporarily lower because
-- only half the day's logs are present yet.
--
-- fingerprint is the canonical-string BeaconHistoryKey() over
-- (Type, SrcIP, DstIP, DstPort, Hostname, URI) joined with ASCII Unit
-- Separator (\x1f) — deliberately not sha256 hashed so the table is
-- self-describing under SQLite-CLI inspection without a join back to
-- findings (which may have been deleted by the time history is being
-- inspected — history rows survive their source finding by the
-- retention window).
--
-- Distinct from model.Finding.Fingerprint() (which is just {Type,
-- SrcIP, DstIP, DstPort}) because HTTP Beaconing rows to different
-- (host, uri) on the same (src, dst, port) would otherwise overwrite
-- each other's daily snapshot.
--
-- Retention is enforced by store.purgeBeaconHistory hooked into the
-- watch's first-tick-of-UTC-day branch; const 30 days for v1 (promote
-- to config when an operator asks for longer trend lookback — the
-- chart range is also 30 days so longer retention is invisible until
-- the chart range grows too).

CREATE TABLE IF NOT EXISTS beacon_history (
    fingerprint  TEXT    NOT NULL,
    day_utc      TEXT    NOT NULL,
    finding_type TEXT    NOT NULL,
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT    NOT NULL,
    dst_port     TEXT    NOT NULL DEFAULT '',
    host         TEXT    NOT NULL DEFAULT '',
    uri          TEXT    NOT NULL DEFAULT '',
    score        INTEGER NOT NULL,
    severity     TEXT    NOT NULL,
    ts_score     REAL    NOT NULL DEFAULT 0,
    ds_score     REAL    NOT NULL DEFAULT 0,
    hist_score   REAL    NOT NULL DEFAULT 0,
    dur_score    REAL    NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (fingerprint, day_utc)
);

CREATE INDEX IF NOT EXISTS idx_beacon_history_fp_day
    ON beacon_history(fingerprint, day_utc);
