-- 0019_beacon_ja3.sql
-- Sprint (beacon-depth slice, item 1.3). JA3/JA4 inline cross-reference.
--
-- conn-level Beaconing findings already resolve the destination SNI out
-- of sslUIDIndex at emit time (the Hostname field). The same sslEntry
-- already carries the JA3 client fingerprint; ja4 is read opportunistic-
-- ally from the same record when the sensor's Zeek emits it. Lifting
-- those onto the finding lets the detail pane show "JA3: <hash> —
-- matched N other beacons in this dataset" and pivot, instead of the
-- analyst mentally joining the separate Malicious JA3 detector.
--
-- Persisted (not derived at render) for the same restart-survival reason
-- as the 0018 triage fields: SetFindings carries a non-re-fired beacon
-- forward, and loadFindings rehydrates from the columns, so the
-- fingerprint survives a restart instead of blanking to ''.
--
-- TEXT NOT NULL DEFAULT '': pre-0019 rows and every non-TLS / non-beacon
-- finding read back as empty, which the detail render treats as "no TLS
-- fingerprint, omit the JA3 block" — no regression, just no enriched
-- line until the next full analysis re-emits a TLS beacon.
--
-- The JA3 sibling count is NOT a column: it's a transient cross-finding
-- aggregate the detail handler computes from the in-memory finding set
-- per request. Nothing persists it (project rule: add columns when a
-- feature needs to survive a restart; a per-request count does not).

ALTER TABLE findings ADD COLUMN ja3 TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN ja4 TEXT NOT NULL DEFAULT '';
