# beacon_url

Original golden-file scenario. Exercises Beacon (perfectly-regular conn
fan-out) and Suspicious URL (URLhaus host match).

## Inputs

- `conn.log` — 100 connections from `192.168.1.5` → `203.0.113.10:443`,
  exactly 60s apart, identical 500/2000 byte counts. 100 samples pushes
  `beaconConfMod` to 1.0 (full confidence), so the golden exercises
  detection logic rather than sample-size ramp behaviour.
- `http.log` — One request to `malware.test/payload.bin`. Fires
  **Suspicious URL** because the runner injects `urlhausHosts =
  {"malware.test": true}`. No other HTTP detectors trigger (UA, MIME,
  extension, CS checksum8, C2 URI patterns all deliberately miss).

## Findings produced

- `Beacon` (HIGH, 70)
- `Suspicious URL` (CRITICAL, 96)
- `TI Hit (Domain)` (CRITICAL, 97) — URLhaus domain match in `checkTI`
- `Host Risk Score` (HIGH, 60) — composite roll-up of the above
