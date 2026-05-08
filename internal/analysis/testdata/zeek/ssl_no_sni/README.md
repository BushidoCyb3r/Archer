# ssl_no_sni

Exercises the **SSL No-SNI** detector — established TLS connection
with no Server Name Indication, on a non-C2 port. Suspicious because
modern HTTPS clients always send SNI; an empty SNI is often a tunnel
or scripted client.

## Inputs

- `ssl.log` — one record on port 443 with `established = true` and
  `server_name = ""`. JA3 empty (no Malicious JA3 trigger), TLSv12 (no
  Weak TLS), port 443 (not in `KnownC2Ports` so the C2-port variant
  doesn't fire).

## Findings produced

- `SSL No-SNI` (LOW, 35) — primary target. SSL No-SNI isn't in
  `riskWeights`, so no Host Risk Score rolls up.
