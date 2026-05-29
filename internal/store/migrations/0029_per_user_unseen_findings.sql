-- 0029_per_user_unseen_findings.sql
-- Per-user "new findings since you last looked" tracking.
--
-- The login/analysis-complete modal previously counted findings.is_new,
-- which the SetFindings merge overwrites every analysis run (fresh
-- fingerprints true, carried-forward false). With hourly watch and a
-- once-a-day login an analyst only ever saw the last run's new findings,
-- not the accumulation since they last checked, and the flag was global
-- rather than per-viewer.
--
-- Fix: a stable per-finding detection time that survives re-analysis,
-- plus a per-user marker. Unseen-for-a-user = COUNT(detected_at > marker).
--
--   findings.detected_at    epoch seconds the fingerprint first entered the
--                           store; carried forward unchanged on every merge
--                           (like the stable id). Set by Go on insert.
--   users.findings_seen_at  epoch seconds this analyst last acknowledged the
--                           new-findings view (advanced on modal dismiss).
--
-- Backfill both to now so existing installs start caught-up: the first
-- post-upgrade login shows zero unseen, and genuinely-new findings accrue
-- per-user from there rather than flooding every analyst with the whole
-- existing finding set.

ALTER TABLE findings ADD COLUMN detected_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users    ADD COLUMN findings_seen_at INTEGER NOT NULL DEFAULT 0;

UPDATE findings SET detected_at      = strftime('%s','now') WHERE detected_at = 0;
UPDATE users    SET findings_seen_at = strftime('%s','now') WHERE findings_seen_at = 0;

CREATE INDEX IF NOT EXISTS idx_findings_detected_at ON findings(detected_at);
