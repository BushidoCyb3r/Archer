-- 0027_pair_allowlist_sensor.sql
-- Scope pair allowlist rules to individual sensors so that a rule
-- applied against sensorA does not silently suppress beacon findings
-- from sensorB on the same (src, dst, port) tuple.
--
-- sensor='' preserves the pre-sensor wildcard semantics: a rule with
-- an empty sensor matches every sensor, so existing rules continue to
-- hide the right findings after this migration. Operators who run
-- only a single sensor and never set a sensor field see no change.
--
-- The unique index is rebuilt to include sensor. Existing rules are
-- all sensor='', so the old unique constraint
-- (src, dst, port, finding_type) is preserved for the empty-sensor
-- population; distinct-sensor rules can now coexist on the same tuple.

ALTER TABLE pair_allowlist ADD COLUMN sensor TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS idx_pair_allowlist_tuple;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pair_allowlist_tuple
    ON pair_allowlist (src, dst, port, finding_type, sensor);
