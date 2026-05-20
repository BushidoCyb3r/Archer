# dns_subdomain_diversity

Exercises the **DNS Subdomain DGA** detector — many unique subdomains
under one apex from a single source, indicating an algorithmically-
driven query stream rather than human browsing.

## Inputs

- `dns.log` — 50 records from `192.168.2.50` to `192.168.1.1:53`
  querying `sub0000.diverse.com` through `sub0049.diverse.com`. All
  NOERROR (so NXDOMAIN flood doesn't also fire). 50 unique subdomains
  exactly meets the `DNSUniqueSubdomainMin = 50` threshold.

## Findings produced

- `DNS Subdomain DGA` (MEDIUM) — primary target. Detail: "High
  subdomain diversity — apex: …". Distinct from the per-query
  `DNS Tunneling` findings in `dns_tunneling/`.
