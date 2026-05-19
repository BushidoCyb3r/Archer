-- 0023_beacon_history_spectral.sql
-- NEW-90 follow-through. Closes the deferred schema item from migration
-- 0018: spectral_rescued and spectral_period on beacon_history.
--
-- spectral_rescued is 1 when the Lomb-Scargle periodogram rescued a
-- beacon whose ts score fell below SpectralRescueThreshold; 0 otherwise.
-- spectral_period is the dominant period (seconds) the periodogram found.
--
-- Both are per-peak: they update alongside the other peak-characterisation
-- columns (severity, ts/ds/hist/dur scores) when a new analysis pass beats
-- the day's existing max_score. A zero spectral_period on a rescued row
-- means the period wasn't resolved — treat as "rescued but period unknown."
--
-- DEFAULT 0 for both: pre-0023 rows and non-spectral beacons read back as
-- 0, which the evolution chart interprets as "not a spectral rescue day."

ALTER TABLE beacon_history ADD COLUMN spectral_rescued INTEGER NOT NULL DEFAULT 0;
ALTER TABLE beacon_history ADD COLUMN spectral_period  REAL    NOT NULL DEFAULT 0;
