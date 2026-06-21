-- 0038_findings_count_indexes.sql
-- Additive indexes for the two findings COUNT queries that ran as full table
-- scans. Both back the new-findings / unseen counters the analyze-complete
-- modal and the notification bell read on every pass, so they fire often
-- against a table that grows across a hunt.
--
-- idx_findings_is_new backs CountNewFindings:
--   SELECT COUNT(*) FROM findings WHERE is_new = 1
-- A handful of rows carry is_new=1 against a mostly-zero column, so the index
-- turns a scan of the whole table into a seek over just the new rows.
--
-- idx_findings_detected_at_type backs CountUnseen:
--   SELECT COUNT(*) FROM findings WHERE detected_at > ? AND type NOT IN (?, ?)
-- The leading detected_at column serves the range, and carrying type in the
-- index lets the roll-up-type exclusion evaluate from the index without a row
-- fetch. This composite is a leftmost-prefix superset of the existing
-- idx_findings_detected_at (0029); that single-column index is left in place
-- (removing one is not additive) and can be dropped in a later tidy-up.
--
-- Index-only, no schema or data change: safe on any existing database.

CREATE INDEX IF NOT EXISTS idx_findings_is_new ON findings(is_new);
CREATE INDEX IF NOT EXISTS idx_findings_detected_at_type ON findings(detected_at, type);
