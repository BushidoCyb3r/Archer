# dga_beacon

Exercises the **DGA hostname augmentation** layered on top of the
**HTTP Beacon** detector. Same shape as `http_beacon` but with a
DGA-shaped registrable domain.

## Inputs

- `http.log` — 104 requests from `192.168.4.70` →
  `203.0.113.205:80`, exactly 60s apart, all to
  `kx9j3qm2pflw.com/api/heartbeat`, identical byte counts. 104
  samples pushes `beaconConfMod` to 1.0 so the fixture exercises
  detection logic rather than sample-size ramp behaviour.

The SLD `kx9j3qm2pflw` has Shannon entropy ≈ 3.58 (above the
`dga_entropy_threshold` default of 3.5) and mean bigram log-
probability near the `bigramFloor` of -5.5 (well below the
`dga_bigram_threshold` default of -4.5) — both metrics cross their
thresholds, so the augmentation fires.

## Findings produced

- `HTTP Beacon` (CRITICAL, 86) — baseline 71 + DGA bump 15;
  severity HIGH → CRITICAL. Detail string carries the DGA diagnostic
  tag (SLD, entropy, bigram) appended after the standard score
  breakdown so analysts can verify what tripped the bump.
- `Host Risk Score` (MEDIUM, 26) — HRS aggregation uses fixed
  per-detector-type weights, not per-finding scores, so the DGA bump
  on the contributing HTTP Beacon doesn't propagate up to the host
  roll-up. The DGA value lives at the per-finding triage layer.
