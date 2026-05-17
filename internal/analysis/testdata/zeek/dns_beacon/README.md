# dns_beacon

Exercises the **DNS Beaconing** detector (§2g) — the DNS-cadence
scorer on the `(src, apex)` key. This is the Cobalt-Strike-style DNS
C2 heartbeat that slips *both* existing DNS-aware detectors.

## Inputs

- `dns.log` — 60 records from `192.168.2.60` → `192.168.1.1:53`,
  every one a query for the fixed FQDN `gateway.update-svc.net`
  (`qtype A`, `rcode NOERROR`), spaced exactly 300s apart over
  ~4.9 hours.
- No `conn.log` — deliberately. A DNS beacon need not produce a
  conn-level beacon (the C2 cadence is at the resolver layer).

## Why it slips the other detectors

- **DNS Tunneling**: the label `gateway` is 7 chars (≪
  `DNSTunnelLabelLen=40`), low-entropy, and there is exactly one
  unique subdomain under the apex (≪ `DNSUniqueSubdomainMin=50`).
  Nothing in the per-query length/entropy path or the diversity
  path fires.
- **Beaconing** (conn-level): keyed on IP pairs from `conn.log`,
  which this fixture does not contain. The conn detector never
  consumes DNS query timing, so it sees nothing.

## Why DNS Beaconing fires

`(192.168.2.60, update-svc.net)` accumulates 60 NOERROR queries
(≥ `DNSBeaconMinQueries=20`), perfectly regular intervals
(`ts≈1.00`), one subdomain so the apex is far below the diversity
gate (`div≈0.98`), and the activity spans enough of the capture
window for the histogram/duration coverage axis to contribute
(`cov≈0.50`). Composition `ts·0.5 + div·0.25 + cov·0.25` →
score 87, CRITICAL. The Host Risk Score roll-up follows from the
DNS Beaconing risk weight (30 → composite 30, MEDIUM).

## Expected

- `DNS Beaconing` — CRITICAL, score 87, `192.168.2.60 →
  update-svc.net:53`.
- `Host Risk Score` — MEDIUM, score 30, the roll-up.
