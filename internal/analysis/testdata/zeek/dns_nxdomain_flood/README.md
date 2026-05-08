# dns_nxdomain_flood

Exercises the **DNS NXDOMAIN Flood** detector — high count of
NXDOMAIN responses from a single source, the classic DGA-malware
indicator.

## Inputs

- `dns.log` — 250 records from `192.168.2.40` to `192.168.1.1:53`,
  all with `rcode_name = NXDOMAIN`. Threshold is
  `DNSNXDomainThreshold = 200`, so 250 is comfortably above. All 250
  queries are the same string (`nonexistent.example.com`) so the
  *unique-subdomain* count under the apex stays at 1, well below the
  `DNSUniqueSubdomainMin = 50` threshold — only NXDOMAIN flood fires,
  not the subdomain-diversity DNS Tunneling variant.

## Findings produced

- `DNS NXDOMAIN Flood` (HIGH, 80) — primary target.
