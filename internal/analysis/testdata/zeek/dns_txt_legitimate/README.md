# dns_txt_legitimate

Regression fixture for the qtype-alone DNS Tunneling false-positive
flood surfaced by the 2026-05-10 audit (Bug 3, deferred from v0.9.0).
Pre-fix any query with `qtype_name IN {TXT, NULL}` produced a
HIGH-severity DNS Tunneling finding regardless of label content,
flooding any environment with mail (SPF, DKIM, DMARC), TLS
automation (ACME DNS-01), or SaaS verification with false positives
that buried real tunneling signal.

## The scenario

Seventeen TXT/NULL queries from one source (`192.168.10.42`) across
a realistic mix of legitimate apexes:

- **SPF lookups** during outbound mail flow: `google.com`,
  `outlook.com`, `amazonses.com`, `sendgrid.net`, `mailgun.org`
- **DKIM key lookups**: `selector1._domainkey.google.com`,
  `selector2._domainkey.outlook.com`, etc.
- **DMARC policy lookups**: `_dmarc.google.com`, `_dmarc.outlook.com`,
  etc.
- **ACME DNS-01 challenges** (Let's Encrypt rotates these
  constantly): `_acme-challenge.example.com`,
  `_acme-challenge.api.example.com`, etc.
- **One NULL qtype** record (rare but seen in SPF lookup chains)

Every label is short, low-entropy, and shallow. None of them cross
the surviving signals — `DNSTunnelLabelLen=50`, `DNSTunnelEntropy=3.5`,
`DNSTunnelMinDepth=6`. None should fire DNS Tunneling.

SaaS domain-ownership tokens (`google-site-verification.*`,
`atlassian-domain-verification.*`, `stripe-verification.*`) are
deliberately excluded from this fixture — their first label is
long enough and varied enough to cross the entropy floor on its
own merits, so they'd fire DNS Tunneling regardless of the
qtype-alone path. That's a separate threshold-tuning conversation;
the fixture here is specifically about the qtype-alone removal.

## Why this scenario exists

Pre-Bug-3-fix this fixture would have emitted ~20 DNS Tunneling
findings (one per distinct `(src, apex)` after dedup). That's the
false-positive flood the auditor flagged. The empty-array result
in `expected_findings.json` is the proof that the qtype-alone
path was actually removed — any future regression that re-adds
the `if qtype IN {TXT, NULL}` fire path would break this golden
loudly.

The companion fixture `dns_tunneling` covers the inverse case: a
realistic 60-char base32 label under TXT that *does* fire the
detector via the surviving length/entropy signals. Together they
demonstrate the post-fix detection contract: TXT/NULL is no
longer a sole signal, but TXT/NULL with actual tunnel structure
still gets caught.

## Findings produced

`expected_findings.json` is the empty array.
