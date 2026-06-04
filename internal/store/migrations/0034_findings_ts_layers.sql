-- 0034_findings_ts_layers.sql
-- Persist per-layer timing-axis attribution on the finding itself
-- (Phase 0 of the beacon-channel / timing-validation arc).
--
-- The composed ts_score a beacon emits is max(ts_raw, ts_mm, ts_ent, spectral).
-- Those individual layer values were computed at emit time and stamped on the
-- in-memory Finding (TSRaw/TSMultimodal/TSEntropy/SpectralRescued/SpectralPeriod,
-- all json:"-") but, like the sub-scores before migration 0018, they were
-- dropped on persist. They survived only in beacon_history (daily granularity,
-- 30-day retention, peakWin-gated) and the free-text detail string.
--
-- The timing-axis validation work needs per-finding attribution that survives
-- a restart and joins directly to the finding's current analyst disposition —
-- "which layer won, and was that finding confirmed or dismissed" — without
-- parsing the detail string or reaching into a separate daily table. Hence
-- real columns, mirroring the 0018 move for the sub-scores.
--
-- ts_raw  : raw Bowley/MAD statistical score
-- ts_mm   : multimodal augmentation score (0 when distribution is single-mode)
-- ts_ent  : entropy augmentation score (0 when sub-6-sample or low-entropy)
-- spectral_rescued : 1 when the Lomb-Scargle periodogram drove the final score
-- spectral_period  : dominant period (seconds) the periodogram found (0 if none)
--
-- All DEFAULT 0: pre-0034 rows and non-beacon findings read back as zero, which
-- the UI/tooling treat as "no layer attribution" (gated on finding type plus a
-- non-zero sample_size, same as the 0018 sub-scores). Note 0 is also a
-- legitimate live value for ts_mm/ts_ent and for spectral_period on a
-- non-rescued beacon; the ambiguity is harmless here because these columns
-- characterise the most-recent emit, refreshed on every full analysis.

ALTER TABLE findings ADD COLUMN ts_raw           REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN ts_mm            REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN ts_ent           REAL    NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN spectral_rescued INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN spectral_period  REAL    NOT NULL DEFAULT 0;
