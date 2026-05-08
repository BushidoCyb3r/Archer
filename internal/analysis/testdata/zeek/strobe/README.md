# strobe

Exercises the **Strobe** detector — sustained high-volume connection
fan-out from one source to one destination.

## Inputs

- `conn.log` — exactly 1000 connections from `192.168.1.20` →
  `203.0.113.30:443`, totalling ~16 minutes of real time. Intervals
  jitter between 1.0 and 31.0 seconds via a deterministic LCG (seed
  12345); byte counts also LCG-jittered. Exactly 1000 records is
  deliberate: it satisfies the strobe threshold (`StrobeMinConnections
  = 1000`) and keeps both interval and byte reservoirs at-cap without
  triggering reservoir-sample replacement (`beaconIvCap = 1000`,
  `beaconByteCap = 1000`), so the beacon score is fully deterministic.

## Findings produced

- `Strobe` (HIGH) — primary target.
- `Beaconing` (HIGH) — expected side-effect: 1000 regular connections
  also trip beaconing with a moderate score reflecting the deliberate
  interval/byte irregularity. Capturing both locks in real-world
  behavior where strobing C2 and periodic beacons can co-occur.
- `Host Risk Score` — composite roll-up.
