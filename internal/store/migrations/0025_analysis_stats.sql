-- 0025_analysis_stats.sql
-- Per-run analysis metadata for longitudinal visibility into detector
-- behaviour. Currently tracks fully-blocked spectral rescues (pairs where
-- the plausibility gate rejected the only strong periodogram peak) so the
-- corpus spot-check script can flag cumulative under-detection risk rather
-- than relying on log lines that scroll past.
--
-- One row per completed Analyze() call. run_at is Unix seconds (UTC).
-- spectral_blocked is the total count across all three beacon analyzers
-- (conn + http + dns).

CREATE TABLE IF NOT EXISTS analysis_stats (
    run_at           INTEGER NOT NULL,
    spectral_blocked INTEGER NOT NULL DEFAULT 0
);
