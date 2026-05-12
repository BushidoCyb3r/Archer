-- 0013_feeds_consecutive_failures.sql
-- Adds a failure streak counter to feeds for the feed-reliability alarm.
-- Reset to 0 on each successful refresh; incremented on each failed
-- refresh. The alarm loop reads this column plus last_refresh_at to
-- decide whether a feed has gone unreliable: >= 3 consecutive failures
-- OR > 24h since the last successful refresh raises a Kind=feed
-- notification. The admin edit path (UpdateFeed) does not touch this
-- column; only the refresh worker (UpdateFeedRefreshState) does.

ALTER TABLE feeds ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
