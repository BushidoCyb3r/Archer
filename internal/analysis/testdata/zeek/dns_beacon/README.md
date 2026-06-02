# dns_beacon

Exercises the **DNS Beacon** detector (§2g) — the DNS-cadence
scorer on the `(src, apex)` key. This is the Cobalt-Strike-style DNS
C2 heartbeat that slips *both* existing DNS-aware detectors.

## Inputs

- `dns.log` — 120 records from `192.168.2.60` → `192.168.1.1:53`,
  every one a query for the fixed FQDN `gateway.update-svc.net`
  (`qtype A`, `rcode NOERROR`), spaced exactly 300s apart over
  ~9.9 hours. 120 samples pushes `beaconConfMod` to 1.0.
- No `conn.log` — deliberately. A DNS beacon need not produce a
  conn-level beacon (the C2 cadence is at the resolver layer).

## Why it slips the other detectors

- **DNS Tunneling**: the label `gateway` is 7 chars (≪
  `DNSTunnelLabelLen=40`), low-entropy, and there is exactly one
  unique subdomain under the apex (≪ `DNSUniqueSubdomainMin=50`).
  Nothing in the per-query length/entropy path or the diversity
  path fires.
- **Beacon** (conn-level): keyed on IP pairs from `conn.log`,
  which this fixture does not contain. The conn detector never
  consumes DNS query timing, so it sees nothing.

## Why DNS Beacon fires

`(192.168.2.60, update-svc.net)` accumulates 120 NOERROR queries
(≥ `DNSBeaconMinQueries=20`), perfectly regular intervals
(`ts≈1.00`), one subdomain so the apex is far below the diversity
gate (`div≈0.98`), and the ~9.9-hour span covers multiple hour-of-day
buckets (`cov≈1.00`). Composition `ts·0.5 + div·0.25 + cov·0.25` ×
confMod=1.00 → score 99, CRITICAL.

## Expected

- `DNS Beacon` — CRITICAL, score 99, `192.168.2.60 →
  update-svc.net:53`.
- `Host Risk Score` — MEDIUM, score 30, the roll-up.
