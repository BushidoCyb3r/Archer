-- 0031_rename_beaconing_to_beacon.sql
-- Rename the beacon finding types: "Beaconing" -> "Beacon",
-- "HTTP Beaconing" -> "HTTP Beacon", "DNS Beaconing" -> "DNS Beacon".
--
-- The type string is the user-facing label, but it is ALSO load-bearing
-- in three persisted places, so a code-only rename would silently regress
-- existing data on upgrade:
--
--   1. findings.type — the finding's identity. Fingerprint() is computed
--      from fields (not stored), and Type is one of them. Rewriting the
--      column in place means the next analysis pass fingerprint-matches
--      the migrated rows, so analyst notes / status / IDs carry forward
--      and the corrected finding is NOT duplicated as a historical row.
--      Without this, every beacon re-emits under a new fingerprint and the
--      old row lingers with the analyst's work stranded on it.
--
--   2. pair_allowlist.finding_type — the scope of a "known-good relationship"
--      suppression rule. isPairAllowedLocked matches it against the finding's
--      Type with exact-string equality, so a rule scoped to "Beaconing" would
--      stop matching the now-"Beacon" finding and the suppressed pair would
--      reappear in the table and bell. Rewriting the scope keeps suppression
--      continuous across the rename.
--
--   3. beacon_history.finding_type and .fingerprint — the spectral /
--      persistence history. The read-path join keys on finding_type (plus the
--      decomposed src/dst/port/host/uri), so rewriting finding_type preserves
--      persistence continuity; rewriting the fingerprint PK prefix (the type
--      is its first \x1f-delimited field) keeps the next save's BeaconHistoryKey
--      upserting onto the same row instead of forking a duplicate.
--
-- Empty tables (fresh DB) match nothing — every statement is a no-op there.

UPDATE findings SET type = 'HTTP Beacon' WHERE type = 'HTTP Beaconing';
UPDATE findings SET type = 'DNS Beacon'  WHERE type = 'DNS Beaconing';
UPDATE findings SET type = 'Beacon'      WHERE type = 'Beaconing';

UPDATE pair_allowlist SET finding_type = 'HTTP Beacon' WHERE finding_type = 'HTTP Beaconing';
UPDATE pair_allowlist SET finding_type = 'DNS Beacon'  WHERE finding_type = 'DNS Beaconing';
UPDATE pair_allowlist SET finding_type = 'Beacon'      WHERE finding_type = 'Beaconing';

UPDATE beacon_history SET finding_type = 'HTTP Beacon' WHERE finding_type = 'HTTP Beaconing';
UPDATE beacon_history SET finding_type = 'DNS Beacon'  WHERE finding_type = 'DNS Beaconing';
UPDATE beacon_history SET finding_type = 'Beacon'      WHERE finding_type = 'Beaconing';

-- The type is the first field of the fingerprint, terminated by the \x1f
-- (char 31) unit separator; anchor on that prefix and rewrite only it.
UPDATE beacon_history
   SET fingerprint = 'HTTP Beacon' || substr(fingerprint, length('HTTP Beaconing') + 1)
 WHERE fingerprint LIKE 'HTTP Beaconing' || char(31) || '%';
UPDATE beacon_history
   SET fingerprint = 'DNS Beacon' || substr(fingerprint, length('DNS Beaconing') + 1)
 WHERE fingerprint LIKE 'DNS Beaconing' || char(31) || '%';
UPDATE beacon_history
   SET fingerprint = 'Beacon' || substr(fingerprint, length('Beaconing') + 1)
 WHERE fingerprint LIKE 'Beaconing' || char(31) || '%';
