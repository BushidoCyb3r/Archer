# dns_suspicious_tld

Exercises the **Suspicious TLD** detector — DNS query for a domain in
one of the free/abused TLD zones (`analysis.SuspiciousTLDs`).

## Inputs

- `dns.log` — one record from `192.168.2.20` → `192.168.1.1:53`
  querying `evil.tk`. `.tk` is in the suspicious-TLD list. First label
  is short and low-entropy, depth is 1, qtype is `A`, so the per-query
  DNS Tunneling heuristics deliberately don't trigger.

## Findings produced

- `Suspicious TLD` (MEDIUM, 52) — primary target.
