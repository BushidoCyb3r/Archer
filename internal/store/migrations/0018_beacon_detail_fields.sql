-- 0018_beacon_detail_fields.sql
-- Sprint 1 (Beacon triage depth). Closes NEW-89.
--
-- The four per-axis beacon sub-scores (ts/ds/hist/dur) and the
-- timing-summary fields (mean/median interval, jitter = interval CV,
-- sample size) were computed at emit time but lived only on the
-- in-memory Finding — tagged json:"-", no columns. NEW-89 (twentieth
-- audit round) documented the restart-survival gap rather than fixing
-- it because nothing outside saveBeaconHistory consumed them.
--
-- The structured triage header (Sprint 1) is that consumer: it breaks
-- a beacon's score down by axis and shows "every 47s ± 3s, n=312" in
-- the detail pane. For a beacon that didn't re-fire in the current
-- run (preserved by SetFindings's carry-forward, or loaded fresh after
-- a restart) those fields must come back from disk, not as zeros.
-- Hence real columns.
--
-- All DEFAULT 0: pre-0018 rows and non-beacon findings read back as
-- zero, which loadFindings/the UI treat as "no structured beacon data"
-- — the triage header is gated on the finding type plus a non-zero
-- sample_size, so a zeroed legacy beacon row simply falls back to the
-- raw Detail string (no regression, just no enriched header until the
-- next full analysis re-emits it).
--
-- NEW-90 (spectral_rescued / spectral_period on beacon_history) is
-- deliberately NOT bundled here: it has no consumer in this slice.
-- Per the project rule, those columns land in their own migration the
-- first time a feature reads them.

ALTER TABLE findings ADD COLUMN ts_score        REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN ds_score        REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN hist_score      REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN dur_score       REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN mean_interval   REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN median_interval REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN jitter          REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN sample_size     INTEGER NOT NULL DEFAULT 0;
