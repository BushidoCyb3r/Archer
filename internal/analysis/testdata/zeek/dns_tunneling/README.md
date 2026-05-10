# dns_tunneling

Exercises the **DNS Tunneling** detector via the per-query path —
specifically the length and entropy signals on a realistic
covert-channel-shaped query.

## Inputs

- `dns.log` — one record from `192.168.2.30` → `192.168.1.1:53`
  with a 60-character base32-shaped label under `evil.com`,
  `qtype_name = TXT`. The label is long (60 ≥
  `DNSTunnelLabelLen=50`), high-entropy (Shannon ≈ 4.68 ≥
  `DNSTunnelEntropy=3.5`), and qtype is TXT for realism. Real
  DNS tunneling tools (iodine, dnscat2, Cobalt Strike's DNS
  beacon) couple TXT/NULL with long high-entropy labels because
  that's the channel capacity.

## Why this scenario exists

Pre-v0.9.x the per-query detector also fired on `qtype IN
{TXT, NULL}` *alone* — every legitimate SPF/DKIM/DMARC/ACME
query produced a HIGH-severity DNS Tunneling finding, burying
real tunneling under a flood of false positives. The
2026-05-10 audit's Bug 3 called this out explicitly. The
qtype-alone path was dropped; the fixture was rewritten to
exercise the surviving signals (length, entropy, depth) which
catch real tunnel-shaped traffic regardless of qtype.

The companion fixture `dns_txt_legitimate` exercises the
inverse: realistic SPF/DKIM/DMARC/ACME TXT patterns from a
single host across multiple apexes, asserting **no** DNS
Tunneling findings — the empty-array result that proves the
false-positive flood is gone.

## Findings produced

- `DNS Tunneling` (HIGH) — primary target. Detail line names
  the long-label and high-entropy reasons (depth doesn't fire
  on a 3-label query; that's expected). Score is captured in
  `expected_findings.json`.
