-- Phase 7 follow-up — opt-in TLS-verification bypass per feed.
--
-- Internal MISP / OpenCTI deployments very commonly run with self-signed
-- certs (or certs signed by an internal CA the Archer container does not
-- trust). Forcing operators to mount custom CA bundles into the container
-- per-deployment is fragile; a per-feed opt-in flag is the conventional
-- shape. Default 0 (verify) — operators have to deliberately opt in per
-- feed, with a UI warning explaining what they are turning off.

ALTER TABLE feeds ADD COLUMN tls_skip_verify INTEGER NOT NULL DEFAULT 0;
