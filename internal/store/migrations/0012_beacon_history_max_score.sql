-- 0012_beacon_history_max_score.sql
-- v0.16.1 NEW-76.
--
-- v0.16.0 shipped beacon_history with INSERT … ON CONFLICT DO NOTHING.
-- The justifying comment claimed the morning's snapshot was "the more
-- representative score" because it sees "the day's earlier logs" —
-- that's factually wrong about how the beacon detector works. The
-- analyzer scores against the accumulated reservoir window, not
-- "today's logs"; the morning pass and the afternoon pass see roughly
-- the same data with slightly more recent additions. "First write
-- wins" silently dropped legitimate trajectory shifts whenever the
-- watch ran more than once per UTC day (sub-daily cadence, admin
-- re-analyze, etc.) — including the adversarial case where a C2
-- operator tunes dwell mid-day and the spike disappears from history
-- forever.
--
-- The fix is two columns of metadata so a single daily row can carry
-- both the spike value (max_score, max_score_at) and the most recent
-- reading (last_score, last_score_at). The chart renders max_score
-- because the spike is what triage care about; last_score is exposed
-- on the API for forensic / per-pass detail.
--
-- Sub-axis scores (ts/ds/hist/dur) track the max-score write, not
-- the last-score write, so an analyst clicking "show me what tripped
-- the high day" sees the components that drove the high day rather
-- than the components of whatever the noon re-run happened to see.

ALTER TABLE beacon_history RENAME COLUMN score TO max_score;
ALTER TABLE beacon_history ADD COLUMN max_score_at  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE beacon_history ADD COLUMN last_score    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE beacon_history ADD COLUMN last_score_at INTEGER NOT NULL DEFAULT 0;

-- Backfill existing rows: max_score_at and last_score_at inherit from
-- created_at (no other timestamp available); last_score inherits from
-- max_score because pre-v0.16.1 rows recorded a single score that was
-- both the first and only write of that day.
UPDATE beacon_history
SET max_score_at  = created_at,
    last_score    = max_score,
    last_score_at = created_at
WHERE max_score_at = 0;
