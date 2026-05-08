# long_connection

Exercises the **Long Connection** detector — connections held open for
unusually long durations.

## Inputs

- `conn.log` — one record from `192.168.1.30` → `203.0.113.40:443` with
  `duration = 7200.0` (2 hours). Threshold is `LongConnMinHours = 1.0`,
  so 2 hours is comfortably above. Above 1 hour but below 24 hours
  resolves to `model.SevMedium` per `analyzeConn`.

## Findings produced

- `Long Connection` (MEDIUM) — primary target.
- `Host Risk Score` (LOW) — Long Connection contributes 10 to composite
  risk, which falls under `<25` → LOW.
