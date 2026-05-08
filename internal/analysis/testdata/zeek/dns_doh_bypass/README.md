# dns_doh_bypass

Exercises the **DoH Bypass** detector — DNS traffic to a known
DNS-over-HTTPS resolver IP on port 443, which evades plain-text DNS
logging.

## Inputs

- `dns.log` — one record from `192.168.2.10` → `8.8.8.8:443` (Google
  Public DNS, in `model.DoHIPs`). The query field is non-empty so the
  parser doesn't early-skip the record; the actual query string
  (`example.com`) is benign and trips no other detectors.

## Findings produced

- `DoH Bypass` (MEDIUM, 62) — primary target.
