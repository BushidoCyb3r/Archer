# http_domain_fronting

Exercises the **Domain Fronting** detector — SSL handshake's SNI
points at one host (typically a CDN) while the inner HTTP `Host:`
header points at a different host, the canonical CDN-abuse pattern.

This is the only HTTP-family scenario that needs a paired SSL record:
domain fronting is detected post-hoc in HTTP analysis by looking up
the connection UID in `sslUIDIndex` (built earlier by `analyzeSSL`).

## Inputs

- `ssl.log` — one record with SNI `cdn.example.com`, TLSv12,
  `established = true`, and an empty JA3 so no SSL-side detector
  trips (Malicious JA3, SSL No-SNI both skipped).
- `http.log` — same UID as the SSL record but `Host: hidden.evil.com`.
  URI is `/` (length-1, skips CS/C2 URI checks) and UA is `Mozilla/5.0`
  so no other HTTP detectors fire.

## Findings produced

- `Domain Fronting` (CRITICAL, 88) — primary target.
- `Host Risk Score` (MEDIUM, 32) — Domain Fronting contributes 32.
