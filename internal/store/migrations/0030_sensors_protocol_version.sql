-- 0030_sensors_protocol_version.sql
-- Persist the Quiver protocol version each sensor reports.
--
-- The enroll and checkin handlers already validate the incoming
-- protocol_version against supportedQuiverProtocols, but the value was
-- discarded after the check. With nothing stored there was no way to
-- answer "which protocol version is each fielded sensor actually
-- speaking?" — the data the Sensors-modal compatibility matrix needs to
-- show "N sensors on vX, server speaks vY" once a future bump (v3) makes
-- the fleet non-uniform.
--
-- Go writes the resolved (already-validated, therefore supported) version
-- on every enroll and on every checkin, so a sensor's row tracks the
-- version of the binary that last checked in, not just its enroll-time
-- value.
--
--   sensors.protocol_version  integer Quiver wire-protocol version the
--                             sensor last reported. 0 = unknown (only
--                             possible on a row no post-upgrade checkin
--                             has refreshed yet).
--
-- Backfill existing rows to the current QuiverProtocolVersion (2): v1
-- enrollment has been impossible since v0.12.0 (no in-band path to issue
-- the HMAC checkin secret a v1 sensor lacks), so every surviving sensor
-- row was necessarily enrolled under v2. New rows get the real reported
-- value from Go; the DEFAULT 0 only ever applies if a future code path
-- inserts without setting it.

ALTER TABLE sensors ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 0;

UPDATE sensors SET protocol_version = 2 WHERE protocol_version = 0;
