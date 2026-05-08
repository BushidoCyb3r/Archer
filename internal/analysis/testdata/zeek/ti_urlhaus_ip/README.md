# ti_urlhaus_ip

Exercises the **Threat Intel Hit** detector via the URLhaus IP match
path. URLhaus is the abuse.ch malware-distribution feed; an IP match
scores 97 / CRITICAL. Distinct from the URLhaus *host* match path
which is exercised by `beacon_url/`.

## Inputs

- `conn.log` — one connection from `192.168.8.20` →
  `203.0.113.201:443`.
- `feeds.json` — `{"urlhaus_ips": ["203.0.113.201"]}` so the dst
  matches the injected feed.

## Findings produced

- `Threat Intel Hit` (CRITICAL, 97) — primary target.
- `Host Risk Score` (MEDIUM, 35) — Threat Intel Hit contributes 35.
