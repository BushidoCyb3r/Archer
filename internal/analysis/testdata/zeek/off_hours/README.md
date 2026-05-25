# off_hours

Exercises the **Off-Hours Transfer** detector — outbound byte volume
during the configured off-hours window (default 22:00–06:00 UTC).

This is the one scenario where timestamps deliberately fall *inside*
the off-hours window. All other scenarios use noon-UTC anchoring to
keep off-hours out of the picture.

## Inputs

- `conn.log` — 5 records from `192.168.1.70` → `203.0.113.70:443`,
  starting at `2024-01-15 02:00:00 UTC` (well inside the 22–06
  window). Each record `orig_bytes = 300 KB`, total 1.5 MB — above the
  `OffHoursMinMB = 1.0` threshold.

## Findings produced

- `Off-Hours Transfer` (MEDIUM) — primary target. Off-Hours Transfer
  is not in `riskWeights`, so no `Host Risk Score` rolls up from it.
  The 5 connections are above `BeaconMinConnections = 4` but
  `beaconConfMod` at n=5 suppresses the incidental beacon below the
  emit floor — intended, since the scenario targets Off-Hours Transfer
  detection, not beacon detection.
