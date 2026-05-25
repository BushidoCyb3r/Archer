# strobe

Exercises the **Strobe** detector — sustained high-rate connection traffic
from one source to one destination (port scanner / aggressive automated tool).

## Inputs

- `conn.log` — exactly 1000 connections from `192.168.1.20` →
  `203.0.113.30:443`. Intervals jitter between 0.1 and 1.0 seconds via a
  deterministic LCG (seed 12345). Span ≈ 548 seconds (9 minutes).
  Rate ≈ 1.83/s — well above `StrobeMinRatePerSec = 0.5`.

## Findings produced

- `Strobe` (HIGH) — primary target. Rate gate (≥ 0.5/s) and count floor
  (≥ 100) both satisfied.
- `Host Risk Score` — composite roll-up.

## What is NOT produced

- `Beaconing` — the strobe gate excludes this pair from beacon scoring
  because rate ≥ StrobeMinRatePerSec. `TestStrobeExcludesBeacon` asserts
  this invariant.
