-- 0024_beacon_history_ts_layers.sql
-- Surface per-layer timing-axis scores for beacon validation (1.9).
-- The composed ts_score is max(tsRaw, tsMM, tsEnt, spectral); these three
-- columns capture the individual pre-spectral layer values so analysts can
-- determine which layer drove each peak-score observation.
--
-- ts_raw  : raw Bowley/MAD statistical score
-- ts_mm   : multimodal augmentation score (0 when distribution is single-mode)
-- ts_ent  : entropy augmentation score (0 when sub-6-sample or low-entropy)
--
-- All three follow the same peakWin update gate as ts_score/ds_score/etc. —
-- they characterise the max-score write, not the most-recent write.
--
-- DEFAULT 0 for all three: pre-0024 rows read back as 0. Note that 0 is also
-- a legitimate live value for ts_mm and ts_ent (single-mode and low-entropy
-- distributions genuinely score 0). The ambiguity self-heals within the
-- 30-day retention window as old rows age out.

ALTER TABLE beacon_history ADD COLUMN ts_raw  REAL NOT NULL DEFAULT 0;
ALTER TABLE beacon_history ADD COLUMN ts_mm   REAL NOT NULL DEFAULT 0;
ALTER TABLE beacon_history ADD COLUMN ts_ent  REAL NOT NULL DEFAULT 0;
