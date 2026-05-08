# ssl_no_sni_c2_port

Exercises the **SSL No-SNI on C2 Port** variant — same trigger as
SSL No-SNI but elevated severity because the destination port is in
`model.KnownC2Ports`. The combination is a strong C2-tunnel signal.

## Inputs

- `ssl.log` — one record on port 4444 (Metasploit default) with
  `established = true` and `server_name = ""`. The fixture uses only
  `ssl.log` (no `conn.log`), so the conn-side **C2 Port** detector
  doesn't fire — only the SSL-side variant.

## Findings produced

- `SSL No-SNI on C2 Port` (HIGH, 82) — primary target. Not in
  `riskWeights`, so no Host Risk Score rolls up.
