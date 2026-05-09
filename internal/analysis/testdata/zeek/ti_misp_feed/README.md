# ti_misp_feed

Exercises the **TI Hit (IP)**, **TI Hit (Domain)**, and
**Suspicious URL** detectors against a stub MISP/OpenCTI feed. The
analyzer normalizes both upstream source types to the same
`feeds.SourcedIndicators` shape, so one scenario covers the
per-source fan-out path regardless of which adapter produced the
bucket. (Hash matches are exercised by the sibling `ti_misp_hash`
scenario.)

Distinct from the URLhaus / Feodo scenarios in two ways: feed-driven
hits are HIGH/90 (built-in feeds are CRITICAL/97-99), and the per-hit
Detail line carries upstream tags inline when present.

## Inputs

- `conn.log` — two outbound connections from `192.168.8.30`:
  - → `198.51.100.55:443` (IP exact-match against the feed's `ips`)
  - → `203.0.113.42:8080` (CIDR match via the feed's `203.0.113.0/24`)
- `dns.log` — one A query for `badactor.example` (domain match).
- `http.log` — one GET to `malware.example` (domain match via HTTP
  host header, which also fires the Suspicious URL detector).
- `feeds.json` — one stub `feed:demo-misp` with all four indicator
  types plus tags on the IP and one domain.

## Findings produced

- 2 × `TI Hit (IP)` (HIGH, 90):
  - 198.51.100.55 — IP indicator with tags `malware:emotet`,
    `tlp:white`, observed via conn on port 443.
  - 203.0.113.42 — CIDR-matched, no tags, observed via conn on
    port 8080.
- 2 × `TI Hit (Domain)` (HIGH, 90):
  - badactor.example — domain indicator with tag `c2:server`,
    observed via DNS A query.
  - malware.example — domain indicator, observed via HTTP request.
- 1 × `Suspicious URL` (HIGH, 90) — fires from `checkSuspiciousURLs`
  when a feed-domain matches an HTTP host.
- 1 × `Suspicious File Download` (HIGH, 72) — collateral from the
  HTTP fixture's `application/octet-stream` MIME; not the path
  under test but stable output.
- 1 × `Host Risk Score` (MEDIUM, 35) — composite roll-up.

## What this covers vs. `feedprovider_test.go`

The unit tests in `feedprovider_test.go` exercise the inner match
logic via in-memory stubs and assert one feed-driven hit per call.
This scenario validates the higher-level wiring:

- `prefetchFeeds` correctly snapshots the provider's buckets onto
  the analyzer.
- The per-source fan-out emits one finding per (dst, source) pair
  across IP, CIDR, and domain types.
- Tag formatting in `feedHitDetail` lands in the finding Detail
  field correctly when tags are present and absent.
- `checkSuspiciousURLs` fires alongside the `checkTI` domain-match
  path when a feed domain shows up in an HTTP host header.

A regression in any of those wiring points produces a diff in
`expected_findings.json` instead of slipping through.
