-- 0010_findings_correlations.sql
-- v0.15.1 NEW-72.
--
-- Persist Finding.Correlations across restarts. Without this column the
-- "+N corr" chip on the Findings table disappears on every server
-- restart and reappears only after the next analysis run repopulates
-- it. Stored as a JSON-encoded []int — same shape as the existing
-- intervals/ts_data/notes columns. Default '' (empty string) decodes
-- to a nil slice via store.loadFindings's `if correlations != ""`
-- guard, so historical rows without the column read back as
-- non-correlated which matches their pre-feature semantics.

ALTER TABLE findings ADD COLUMN correlations TEXT NOT NULL DEFAULT '';
