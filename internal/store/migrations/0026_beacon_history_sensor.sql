-- 0026_beacon_history_sensor.sql
-- Add sensor column to beacon_history so the SuggestedPairAllowlist query
-- can group and join on sensor independently. Without this, observations
-- from two Quiver collectors on the same beacon pair merge into one history
-- group and one suggestion — contradicting the per-sensor identity the
-- detectors and Fingerprint() enforce.
--
-- Existing rows get sensor='' (pre-sensor history). The suggestion query
-- joins findings on f.sensor = bh.sensor; existing rows with sensor=''
-- match findings with sensor='' (single-sensor or pre-Sensor deployments),
-- so history carry-forward is intact for operators who have only one sensor.

ALTER TABLE beacon_history ADD COLUMN sensor TEXT NOT NULL DEFAULT '';
