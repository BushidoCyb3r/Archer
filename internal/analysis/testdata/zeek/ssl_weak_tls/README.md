# ssl_weak_tls

Exercises the **Weak TLS** detector — connection negotiated a
deprecated TLS protocol version (`SSLv2`, `SSLv3`, `TLSv10`,
`TLSv11`).

## Inputs

- `ssl.log` — one record with `version = TLSv10`. Other fields kept
  benign (non-empty SNI, no malicious JA3, non-C2 port) so only the
  weak-TLS path fires.

## Findings produced

- `Weak TLS` (LOW, 48) — primary target. Weak TLS isn't in
  `riskWeights`, so no Host Risk Score rolls up.
