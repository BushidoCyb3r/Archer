# exfil

Exercises the **Data Exfiltration** detector — high outbound byte
volume with skewed out/in ratio to an external destination.

## Inputs

- `conn.log` — 5 records from `192.168.1.40` → `203.0.113.50:443`.
  Each record: `orig_bytes = 1.5 MB`, `resp_bytes = 50 KB`. Total
  outbound = 7.5 MB (over the 5 MB threshold), ratio = 30 (over the
  10× threshold). 5 records is above `BeaconMinConnections = 4` but
  `beaconConfMod` at n=5 reduces the beacon score below the emit
  floor, so the beacon is correctly suppressed and doesn't dilute the
  scenario.

## Findings produced

- `Data Exfiltration` (CRITICAL) — primary target.
- `Host Risk Score` (LOW) — Data Exfiltration is the sole contributing
  detector.
