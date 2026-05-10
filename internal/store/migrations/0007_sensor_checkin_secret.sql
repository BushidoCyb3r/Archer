-- v0.12.0 NEW-16: per-sensor HMAC secret for checkin authentication.
-- Pre-v0.12.0 the /api/quiver/checkin endpoint trusted the Name field
-- alone — anyone who knew (or guessed) a sensor's name could POST a
-- checkin and forge the LastSeenAt heartbeat. Quiver protocol v2 fixes
-- this by signing checkin payloads with HMAC-SHA256 keyed on a secret
-- established at enrollment.
--
-- Existing rows pre-migration are sensors that enrolled under v1.
-- They get an empty checkin_secret here; the server treats empty as
-- "v1 sensor — must re-enroll under v2 to upgrade" rather than
-- silently authenticating without a key. The upgrade path is
-- documented in CHANGELOG / docs/QUIVER.md as a Breaking change
-- requiring re-enrollment of every sensor.

ALTER TABLE sensors ADD COLUMN checkin_secret TEXT NOT NULL DEFAULT '';
