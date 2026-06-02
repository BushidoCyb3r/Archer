# http_beacon

Exercises the **HTTP Beacon** detector — periodic HTTP requests to
the same `(src, dst, host, uri)` key with regular timing and
consistent byte counts, the C2 check-in pattern.

## Inputs

- `http.log` — 104 requests from `192.168.3.60` →
  `203.0.113.105:80`, exactly 60s apart, all to
  `tracker.evil.com/api/heartbeat`, identical byte counts. 104
  samples pushes `beaconConfMod` to 1.0. The URI checksum and pattern
  set don't trip CS or C2 URI detectors; the UA is benign.

The fixture has no `conn.log`, so the histogram/duration scores
reflect HTTP-only coverage across the ~1.7-hour span.

## Findings produced

- `HTTP Beacon` (HIGH, 71) — primary target.
- `Host Risk Score` (LOW, 24) — HTTP Beacon contributes to roll-up.
