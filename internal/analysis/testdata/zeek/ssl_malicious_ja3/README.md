# ssl_malicious_ja3

Exercises the **Malicious JA3** detector — TLS client fingerprint
matches a known C2-framework JA3 from `model.KnownBadJA3`.

## Inputs

- `ssl.log` — one record from `192.168.4.10` →
  `203.0.113.110:443` with JA3
  `72a589da586844d7f0818ce684948eea` (Cobalt Strike beacon). All
  other SSL signals are deliberately benign — TLSv12, non-empty SNI,
  non-self-signed subject — so only the malicious-JA3 path fires.

## Findings produced

- `Malicious JA3` (CRITICAL, 95) — primary target.
- `Host Risk Score` (MEDIUM, 40) — Malicious JA3 contributes 40.
