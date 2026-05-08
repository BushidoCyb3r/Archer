# Zeek log fixtures for golden-file detection tests

Synthetic, hand-crafted NDJSON fixtures used by `golden_test.go` to verify
detector output stays stable across refactors. Each scenario lives in its
own subdirectory.

## Conventions

- Format: NDJSON (one Zeek record per line). The parser auto-detects JSON
  vs TSV from the first data line, so no `#fields` header is needed.
- Filenames use the Zeek convention (`conn.log`, `http.log`, `dns.log`,
  etc.) — `filterFiles` keys off the basename prefix.
- Synthetic IPs only:
  - Internal: `192.168.0.0/16`, `10.0.0.0/8` (RFC 1918).
  - External: `203.0.113.0/24`, `198.51.100.0/24` (TEST-NET-3,
    TEST-NET-2 — RFC 5737, never routed on the public internet).
- Synthetic hostnames in `.test` (RFC 6761 reserved).
- Timestamps in UTC noon to avoid the off-hours window (22:00–06:00).

## Scenarios

### Top level (`testdata/zeek/`)

The default fixture exercises two clean detection paths:

- `conn.log` — 30 connections from `192.168.1.5` to `203.0.113.10:443`,
  exactly 60s apart, identical byte counts. Designed to fire **Beaconing**
  with maximum interval/byte regularity (ts/ds sub-scores = 1.0) and
  near-zero histogram/duration sub-scores (the 30-minute span is too tight
  to spread across hourly buckets, by design — keeps the score stable
  without depending on a wide synthetic time window).
- `http.log` — One request to `malware.test/payload.bin`. Designed to
  fire **Suspicious URL** when `urlhausHosts` is pre-injected with
  `{"malware.test": true}` via the `prefetchFeeds` skip guard. No other
  HTTP detectors trigger (UA, MIME, extension, CS checksum8, C2 URI
  patterns all deliberately miss).

The fixture is intentionally minimal. Add new scenarios as new
subdirectories rather than enriching this one — golden stability degrades
quickly when a fixture has to satisfy too many expectations.
