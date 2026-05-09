# beacon_url

Original golden-file scenario. Exercises Beaconing (perfectly-regular conn
fan-out) and Suspicious URL (URLhaus host match).

## Inputs

- `conn.log` — 30 connections from `192.168.1.5` → `203.0.113.10:443`,
  exactly 60s apart, identical 500/2000 byte counts. Designed to fire
  **Beaconing** with maximum interval/byte regularity (ts/ds sub-scores
  = 1.0) and near-zero histogram/duration sub-scores (the 30-minute
  span is too tight to spread across hourly buckets, by design — keeps
  the score stable without depending on a wide synthetic time window).
- `http.log` — One request to `malware.test/payload.bin`. Fires
  **Suspicious URL** because the runner injects `urlhausHosts =
  {"malware.test": true}`. No other HTTP detectors trigger (UA, MIME,
  extension, CS checksum8, C2 URI patterns all deliberately miss).

## Findings produced

- `Beaconing` (HIGH, 50)
- `Suspicious URL` (CRITICAL, 96)
- `TI Hit (Domain)` (CRITICAL, 97) — URLhaus domain match in `checkTI`
- `Host Risk Score` (HIGH, 65) — composite roll-up of the above
