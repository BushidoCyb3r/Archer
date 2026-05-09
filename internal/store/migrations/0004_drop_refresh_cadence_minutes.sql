-- v0.7.0 cleanup — drop the dead per-feed refresh cadence.
--
-- Pre-v0.6.0 the per-feed background worker ticked on each feed's own
-- cadence. v0.6.0 ties feed refresh to the watch full-pass instead and
-- the per-feed Refresh button covers ad-hoc refreshes; the column has
-- been unused since. Drop it so the schema reflects the actual contract
-- and operators stop seeing a configurable that does nothing.
--
-- SQLite supports DROP COLUMN as of 3.35 (modernc.org/sqlite is well
-- past that). Forward-only — restoring requires a new migration that
-- adds the column back with the prior default.

ALTER TABLE feeds DROP COLUMN refresh_cadence_minutes;
