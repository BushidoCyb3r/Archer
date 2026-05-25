# slow_c2_beacon

Regression fixture for the strobe rate-gate fix.

## What this tests

Under the old count-only strobe gate (`StrobeMinConnections = 1000`), a pair
with ≥ 1000 connections was always excluded from beacon scoring — regardless of
rate. A 60-second C2 beacon observed over a multi-week capture generates
thousands of connections at ~0.017/s, which the old code silently reclassified
as Strobe with no beacon chart, no timing breakdown, and half the host-risk
weight. This fixture is the regression anchor that proves the fix holds.

## Inputs

- `conn.log` — 1000 connections from `192.168.1.20` → `203.0.113.30:443`
  with intervals of 1–31 seconds (average ~16 s). Span ≈ 270 minutes.
  Rate ≈ 0.06/s — well below `StrobeMinRatePerSec = 0.5`.

## Invariant

- **No Strobe finding** — rate (0.06/s) is below the threshold.
- **Beaconing fires** — count (1000) ≥ BeaconMinConnections (4); the pair
  reaches the beacon scorer unimpeded.
