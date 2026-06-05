-- 0036_findings_service.sql
-- Protocol-on-unexpected-port detection: Zeek's dynamic protocol detection
-- (DPD) names the actual L7 protocol of a flow regardless of port, so an
-- analyzer comparing that service against the port's expected set can surface
-- http-on-8443 or ssl-on-4444 — egress that slips past port-based controls.
-- The detector ("Protocol on Unexpected Port") stamps the DPD service onto the
-- finding so it survives a restart and backs the `service:` query field.
--
-- Not part of Finding.Fingerprint(): service is a descriptive attribute of the
-- conn-derived finding, not an identity discriminator — the (Type,src,dst,port)
-- fingerprint already dedups these. Carried fresh from each run like Detail.
--
-- DEFAULT '': pre-0036 rows and every finding that doesn't carry a DPD service
-- read back as the empty string, which matches no `service:` predicate.

ALTER TABLE findings ADD COLUMN service TEXT NOT NULL DEFAULT '';
