# dns_doh_bypass

Exercises the **DoH Bypass** detector — a TLS session to a known
DNS-over-HTTPS resolver IP on port 443, which bypasses plain-text DNS
logging entirely.

## Inputs

- `ssl.log` — one TLS connection from `192.168.2.10` → `8.8.8.8:443`
  (Google Public DNS, in `analysis.DoHIPs`), SNI `dns.google`.
  Detection reads `ssl.log`, not `dns.log` — DoH is an HTTPS session,
  not a DNS transaction, so it is invisible to Zeek's dns.log.

## Findings produced

- `DoH Bypass` (MEDIUM, 62) — primary target. Detail includes the SNI
  when present so the analyst can confirm the resolver identity.
