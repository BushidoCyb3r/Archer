-- v0.7.0 — track whether the most recent fetch hit the adapter's
-- page-walk safety cap so operators can see when they're not getting
-- the whole upstream feed. MISP's adapter newly walks pages of 10000
-- up to 100 pages (1M attributes); OpenCTI walks 1000 × 100. Either
-- adapter sets this when it bottoms out at the cap with the upstream
-- still indicating more data.
--
-- Default 0 (not truncated) is safe for existing rows — the next
-- fetch refreshes the value either way.

ALTER TABLE feeds ADD COLUMN last_fetch_truncated INTEGER NOT NULL DEFAULT 0;
