# Zeek log fixtures for golden-file detection tests

Synthetic, hand-crafted NDJSON fixtures used by `golden_test.go` to verify
detector output stays stable across refactors. Each scenario lives in its
own subdirectory; the test discovers subdirectories under `testdata/zeek/`
and runs each as its own subtest.

## Conventions

- Format: NDJSON (one Zeek record per line). The parser auto-detects JSON
  vs TSV from the first data line, so no `#fields` header is needed.
- Filenames use the Zeek convention (`conn.log`, `http.log`, `dns.log`,
  `ssl.log`, etc.) — `filterFiles` keys off the basename prefix.
- Synthetic IPs only:
  - Internal: `192.168.0.0/16`, `10.0.0.0/8` (RFC 1918).
  - External: `203.0.113.0/24`, `198.51.100.0/24` (TEST-NET-3,
    TEST-NET-2 — RFC 5737, never routed on the public internet).
- Synthetic hostnames in `.test` (RFC 6761 reserved).
- Default timestamps in UTC noon to avoid the off-hours window
  (22:00–06:00). The `off_hours/` scenario is the one exception.

## Scenario layout

Each scenario subdirectory contains:

- `*.log` — fixture log files (one or more).
- `expected_findings.json` — the golden, captured by running the test
  with `-update` and committed alongside the fixture.
- `README.md` — what this scenario exercises and which detector(s) it
  primarily targets.
- `feeds.json` (optional) — per-scenario TI feed injection. Schema:
  `{"feodo_ips":[…], "urlhaus_ips":[…], "urlhaus_hosts":[…]}`. Each
  field is independently optional; omitted fields fall back to the
  default (empty Feodo/URLhaus IP maps, plus a single `malware.test`
  URLhaus host so the original `beacon_url/` scenario keeps working
  without a `feeds.json` file).

## Adding a new scenario

1. Create a subdirectory (e.g., `testdata/zeek/dns_tunnel/`).
2. Hand-craft the `*.log` files. Aim to trip exactly one detector
   family — fixtures that satisfy too many expectations grow brittle.
   Cross-detector triggers are fine when they're *expected* (e.g., 1500
   regular connections fire both Strobe and Beacon — that's the
   real-world behavior; capture both).
3. If the scenario needs specific TI-feed entries (Feodo IP, URLhaus
   IP, URLhaus host), drop a `feeds.json` next to the `*.log` files.
   See `ti_feodo_ip/feeds.json` for the schema.
4. Run `go test ./internal/analysis/... -run TestGoldenZeek -update` to
   capture the golden for the new subdirectory.
5. Read the resulting `expected_findings.json`. Verify the expected
   detector(s) appear with sensible scores. If the fixture missed the
   threshold, debug and re-capture.
6. Add a scenario `README.md` explaining what's exercised.
7. Commit fixture + golden + README in the same commit.

## Existing scenarios

| Scenario | Primary detector(s) |
|----------|---------------------|
| `beacon_url/` | Beacon, Suspicious URL, Threat Intel Hit |
| `strobe/` | Strobe |
| `long_connection/` | Long Connection |
| `exfil/` | Data Exfiltration |
| `lateral/` | Lateral Movement |
| `c2_port/` | C2 Port |
| `off_hours/` | Off-Hours Transfer |
| `dns_doh_bypass/` | DoH Bypass |
| `dns_suspicious_tld/` | Suspicious TLD |
| `dns_tunneling/` | DNS Tunneling (per-query) |
| `dns_nxdomain_flood/` | DNS NXDOMAIN Flood |
| `dns_subdomain_diversity/` | DNS Tunneling (subdomain diversity) |
| `http_suspicious_ua/` | Suspicious UA |
| `http_cobalt_strike_uri/` | Cobalt Strike URI |
| `http_c2_uri_pattern/` | C2 URI Pattern |
| `http_domain_fronting/` | Domain Fronting (uses paired ssl.log) |
| `http_suspicious_file/` | Suspicious File Download |
| `http_beacon/` | HTTP Beacon |
| `ssl_malicious_ja3/` | Malicious JA3 |
| `ssl_weak_tls/` | Weak TLS |
| `ssl_no_sni/` | SSL No-SNI |
| `ssl_no_sni_c2_port/` | SSL No-SNI on C2 Port |
| `x509_self_signed/` | Suspicious Certificate (self-signed) |
| `x509_default_subject/` | Suspicious Certificate (default subject) |
| `x509_short_validity/` | Suspicious Certificate (short validity) |
| `x509_long_validity/` | Suspicious Certificate (long validity) |
| `files_suspicious_mime/` | Suspicious File Download (MIME) |
| `files_suspicious_ext/` | Suspicious File Download (extension) |
| `weird_protocol_anomaly/` | Protocol Anomaly (low-interest) |
| `weird_high_interest/` | Protocol Anomaly (high-interest) |
| `notice_zeek/` | Zeek Notice (default HIGH) |
| `notice_critical/` | Zeek Notice (critical keyword) |
| `ti_feodo_ip/` | Threat Intel Hit (FeodoTracker IP — uses `feeds.json`) |
| `ti_urlhaus_ip/` | Threat Intel Hit (URLhaus IP — uses `feeds.json`) |
