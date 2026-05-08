# dns_tunneling

Exercises the **DNS Tunneling** detector via the per-query path —
specifically the `qtype = TXT/NULL` signal, which is one of four
indicators (long label, high entropy, deep nesting, or TXT/NULL
qtype) that any one of can trip the detector.

## Inputs

- `dns.log` — one record from `192.168.2.30` → `192.168.1.1:53`
  querying `data.evil.com` with `qtype_name = TXT`. The first label
  (`data`) is short and low-entropy, depth is 2, apex is `.com` (not
  in `SuspiciousTLDs`) — only the qtype signal fires the detector,
  which keeps the score predictable and the scenario tightly focused
  on one tunnel indicator.

## Findings produced

- `DNS Tunneling` (HIGH, 64) — primary target.
