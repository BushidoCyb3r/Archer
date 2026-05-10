-- Track when each feed was last *fully* re-pulled, separately from
-- last_refresh_at (which now records the most recent fetch of any
-- kind, full or incremental). Incremental fetches use MISP's
-- restSearch `timestamp` filter to ask only for attributes modified
-- since the previous fetch, which is dramatically faster than
-- offset-paginating the full snapshot every time. But indicators that
-- haven't changed in MISP don't get their last_seen bumped on
-- incremental fetches, so without periodic full refreshes the aging
-- sweep would erroneously delete unchanged-but-still-current
-- indicators. The full-refresh cadence (derived from the per-feed
-- aging window) keeps last_seen fresh for everything that's still in
-- MISP; incremental fetches handle adds/changes between full passes.
--
-- Default 0 (never had a full refresh) forces the next refresh on
-- existing rows to be a full one — the right state-recovery behavior
-- after upgrade.

ALTER TABLE feeds ADD COLUMN last_full_refresh_at INTEGER NOT NULL DEFAULT 0;
