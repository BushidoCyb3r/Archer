-- 0028_notifications_sensor.sql
-- Add sensor column to notifications so that sensor-scoped pair
-- allowlist rules can retroactively dismiss the correct notifications
-- when a rule is added after a finding was already notified.
--
-- Existing rows get sensor='' which matches any sensor-agnostic rule
-- (sensor='' in pair_allowlist), preserving current suppression
-- behavior for pre-sensor deployments.

ALTER TABLE notifications ADD COLUMN sensor TEXT NOT NULL DEFAULT '';
