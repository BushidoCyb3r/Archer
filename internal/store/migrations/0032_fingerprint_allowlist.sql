-- Fingerprint allowlist — analyst "mark benign" for the TLS Fingerprints wall.
--
-- The TLS Fingerprints inventory (FingerprintInventory) is stateless: it
-- recomputes the JA3/JA4 high-signal set from the latest prevalence snapshot
-- on every fetch. Rare/cross-host client shapes that an analyst has already
-- triaged as benign (corporate EDR agents, a niche SDK, a scanner the team
-- runs) re-surface every pass — the wall never shrinks, so each visit means
-- re-examining the whole list.
--
-- A fingerprint_allowlist row marks one (kind, fingerprint) as benign so it
-- drops out of the inventory and matching findings carry an "allowlisted"
-- marker. Known-bad C2 fingerprints are never hidden: FingerprintInventory
-- forces them critical regardless of any allowlist entry, so an analyst can't
-- accidentally mute a Cobalt Strike / Sliver match.
--
-- Pure view filter, mirroring pair_allowlist (0017): consulted at read time,
-- never at finding-emit time. Add hides on the next fetch; remove brings the
-- fingerprint back immediately with no re-analysis. Row-managed (id PK), each
-- entry individually listed and deletable in the modal's "Benign" section.

CREATE TABLE IF NOT EXISTS fingerprint_allowlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprint_allowlist_kind_fp
    ON fingerprint_allowlist (kind, fingerprint);
