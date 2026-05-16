-- Pair allowlist — tuple-scoped, view-only finding filter.
--
-- The existing allowlist is a flat IP/CIDR/glob list compiled into a
-- single matcher: it hides every finding touching that address in
-- either direction, on any port, of any type. Too blunt for the
-- canonical beacon false-positive — an internal host on a regular
-- interval to known infrastructure (DNS, NTP, AD, update/SIEM
-- servers). Suppressing the server IP blinds you to real C2 to it;
-- suppressing the source host blinds you to its other beacons.
--
-- A pair_allowlist rule scopes the exclusion to one (src, dst, port)
-- tuple, optionally narrowed to a single finding_type. finding_type
-- empty = every type on that tuple; set = only that type (so an
-- analyst can mute "Beaconing" on a known-good DNS pair while leaving
-- DNS Tunneling / exfil detectors live on the same pair — real
-- tradecraft to a legitimate resolver still surfaces).
--
-- This is a pure view filter, mirroring the IP allowlist semantics:
-- the rule is consulted only in findings_filter.go (and the
-- bell-suppression mirror), never at finding-emit time. Findings are
-- never dropped from the store, so adding a rule hides matching rows
-- on the next /api/findings fetch and removing it brings them back
-- immediately — no re-analysis.
--
-- Row-managed (id PK), unlike the flat allowlist text list: every
-- rule is individually listed and deletable in the Pair Allowlist
-- manager. No expiry column — "permanent" means it lives until an
-- analyst removes it, not until a sweep prunes it.

CREATE TABLE IF NOT EXISTS pair_allowlist (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    src          TEXT NOT NULL,
    dst          TEXT NOT NULL,
    port         TEXT NOT NULL DEFAULT '',
    finding_type TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pair_allowlist_tuple
    ON pair_allowlist (src, dst, port, finding_type);
