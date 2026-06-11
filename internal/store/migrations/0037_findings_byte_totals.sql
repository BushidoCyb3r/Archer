-- 0037_findings_byte_totals.sql
-- Per-pair byte totals: the conn analyzers already sum each (sensor,src,dst)
-- pair's sent (orig) and received (resp) payload bytes; persisting both on the
-- finding backs the `outratio:` query field (orig/resp) — the query-language
-- version of the beacon chart's upload-heavy flag, queryable instead of only
-- visible per-bucket in the Bytes mirror.
--
-- Stamped on conn-derived pair findings (Beacon, Port-Hopping Beacon, Data
-- Exfiltration). Not part of Finding.Fingerprint(): volume is a descriptive
-- attribute, not an identity discriminator. Carried fresh from each run like
-- Detail and the 0018 triage fields.
--
-- DEFAULT 0: pre-0037 rows and every finding without byte data read back as
-- zero, which matches no `outratio:` predicate.

ALTER TABLE findings ADD COLUMN orig_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN resp_bytes INTEGER NOT NULL DEFAULT 0;
