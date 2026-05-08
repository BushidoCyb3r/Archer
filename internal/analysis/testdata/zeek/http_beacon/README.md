# http_beacon

Exercises the **HTTP Beaconing** detector — periodic HTTP requests to
the same `(src, dst, host, uri)` key with regular timing and
consistent byte counts, the C2 check-in pattern.

## Inputs

- `http.log` — 10 requests from `192.168.3.60` →
  `203.0.113.105:80`, exactly 60s apart, all to
  `tracker.evil.com/api/heartbeat`, identical byte counts. 10
  requests is above `HTTPBeaconMinRequests = 8`. The URI checksum
  (56) and pattern set don't trip CS or C2 URI detectors; the UA is
  benign.

The fixture has no `conn.log`, so dataset min/max stays at the
analyzer's initial sentinel values. `histScoreFromHourMap` and
`durationScoreFromHourMap` both return zero in that state, so the
beacon score comes purely from the `tsScore` (interval regularity)
and `dsScore` (byte regularity) sub-scores — both saturate at 1.0
with the perfect 60s spacing and identical byte counts, yielding a
total score of 50 / 100 (`(1.0 + 1.0 + 0 + 0) * 25`).

## Findings produced

- `HTTP Beaconing` (HIGH, 50) — primary target.
- `Host Risk Score` (MEDIUM, 28) — HTTP Beaconing contributes 28.
