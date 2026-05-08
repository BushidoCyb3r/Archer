# ti_feodo_ip

Exercises the **Threat Intel Hit** detector via the FeodoTracker IP
match path in `checkTI`. FeodoTracker is the Emotet/TrickBot/Dridex
botnet C2 feed; an IP match scores 99 / CRITICAL.

This is the first scenario to use the optional **`feeds.json`** —
the runner reads it to inject specific IPs into the analyzer's
feodoIPs cache before running. Without that, every test would have
to share one global feed configuration.

## Inputs

- `conn.log` — one connection from `192.168.8.10` →
  `203.0.113.200:443`.
- `feeds.json` — `{"feodo_ips": ["203.0.113.200"]}` so the dst
  matches the injected feed. URLhaus and host feeds stay at their
  scenario defaults.

## Findings produced

- `Threat Intel Hit` (CRITICAL, 99) — primary target.
- `Host Risk Score` (MEDIUM, 35) — Threat Intel Hit contributes 35
  to composite risk.
