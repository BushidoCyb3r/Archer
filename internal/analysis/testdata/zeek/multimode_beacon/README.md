# multimode_beacon

Exercises the **multi-period beacon** rescue path on the timing axis.

## The scenario

A single source IP beaconing to one destination on TCP/443 with two
distinct cadences:

- **Heartbeat phase**: 50 connections at ~60s intervals (±2s LCG jitter)
- **Tasking phase**: 50 connections at ~600s intervals (±10s LCG jitter)
- All 100 connections share `(src=192.168.1.30, dst=203.0.113.40, port=443)`

Sorted by timestamp, the inter-arrival intervals split bimodally:
~49 around 60s (bucket 5 in `intervalMultimodalScore`'s log2 binning)
and ~50 around 600s (bucket 9). 100 samples pushes `beaconConfMod` to 1.0.

## Why this scenario exists

Bowley + MAD on the raw interval distribution penalise multi-modal
beacons heavily — the median lands between the modes, MAD is large
relative to median, and `mad_score` collapses to ~0.18. Without
augmentation `ts_score` lands around 0.59 instead of the ~0.99 the
underlying signal deserves. `intervalMultimodalScore` recognises the
two-peak shape, scores each peak's tightness independently, and the
caller takes `max(raw, multimodal)` so single-mode beacons are
unchanged but multi-period beacons stop being punished.

## Findings produced

- `Beacon` (HIGH, score 72) — primary target. The multimodal
  augmentation lifts the ts sub-score above the raw Bowley/MAD result.
- `Host Risk Score` (MEDIUM, score 26) — automatic roll-up.
