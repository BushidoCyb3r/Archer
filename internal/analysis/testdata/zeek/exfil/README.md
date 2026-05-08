# exfil

Exercises the **Data Exfiltration** detector — high outbound byte
volume with skewed out/in ratio to an external destination.

## Inputs

- `conn.log` — 5 records from `192.168.1.40` → `203.0.113.50:443`.
  Each record: `orig_bytes = 1.5 MB`, `resp_bytes = 50 KB`. Total
  outbound = 7.5 MB (over the 5 MB threshold), ratio = 30 (over the
  10× threshold). Exactly 5 records keeps the pair below
  `BeaconMinConnections = 10` so beaconing doesn't fire and dilute the
  scenario.

## Findings produced

- `Data Exfiltration` (CRITICAL) — primary target.
- `Host Risk Score` (MEDIUM) — Data Exfiltration contributes 25 to
  composite risk, which lands at the MEDIUM boundary.
