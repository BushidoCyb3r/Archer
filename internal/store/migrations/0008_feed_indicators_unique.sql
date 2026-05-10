-- v0.12.0 LOW-cluster: collapse the per-indicator SELECT-then-INSERT-or-
-- UPDATE pattern in upsertFeedIndicatorBatch into a single ON CONFLICT
-- UPSERT. SQLite requires a UNIQUE constraint on the conflict target
-- columns; the original 0002_feeds.sql migration didn't include one
-- because the pre-fix code did the existence check in application
-- code. The pre-fix discipline (always check before write) means in
-- practice there shouldn't be any duplicates today, but a defensive
-- DELETE-by-MAX(id) sweep covers the case where some path hit a race
-- and produced two rows; we keep the most recent (highest id) per
-- (feed_id, indicator).

DELETE FROM feed_indicators
WHERE id NOT IN (
    SELECT MAX(id) FROM feed_indicators GROUP BY feed_id, indicator
);

CREATE UNIQUE INDEX idx_feed_indicators_feedid_indicator_unique
    ON feed_indicators(feed_id, indicator);
