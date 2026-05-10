# multimode_beacon

Exercises the **multi-period beacon** rescue path on the timing axis.

## The scenario

A single source IP beaconing to one destination on TCP/443 with two
distinct cadences:

- **Heartbeat phase**: 20 connections at ~60s intervals (±2s LCG jitter)
- **Tasking phase**: 20 connections at ~600s intervals (±10s LCG jitter)
- All 40 connections share `(src=192.168.1.30, dst=203.0.113.40, port=443)`

Sorted by timestamp, the 39 inter-arrival intervals split bimodally:
~19 around 60s (bucket 5 in `intervalMultimodalScore`'s log2 binning)
and ~20 around 600s (bucket 9). Each cluster is individually tight; the
distribution as a whole is genuinely bimodal.

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

- `Beaconing` (HIGH, score 54) — primary target. The `ts=0.99`
  component in the Detail line is the multimodal augmentation kicking
  in. `hist=0.24` and `dur=0.00` reflect the small data window (3.6h
  of activity), which keeps the overall composite below CRITICAL.
- `Host Risk Score` (MEDIUM, score 30) — automatic roll-up.

The fixture deliberately stays small (40 connections) to keep the
intervals reservoir well below cap so the scoring is fully
deterministic.
