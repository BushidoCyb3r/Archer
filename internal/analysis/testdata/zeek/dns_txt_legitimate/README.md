# dns_txt_legitimate

Regression fixture covering two DNS Tunneling false-positive bugs
surfaced by the 2026-05-10 audit cycle:

1. **Bug 3 (deferred from v0.9.0): qtype-alone DNS Tunneling.**
   Pre-fix any query with `qtype_name IN {TXT, NULL}` produced a
   HIGH-severity DNS Tunneling finding regardless of label content.
2. **Post-v0.10.0 follow-up: entropy-alone on short compound
   labels.** Pre-fix the entropy signal fired on any label
   crossing 3.5 bits Shannon entropy, which trapped legitimate
   compound English-with-hyphens labels of length 20-30 — SaaS
   verification tokens like `google-site-verification` (24 chars,
   ent 3.61), `atlassian-domain-verification` (29 chars, ent 3.62),
   `stripe-verification` (19 chars, ent 3.51). Compound English
   has higher per-char entropy than long base32 streams because
   the alphabet is less constrained. The entropy signal now
   requires `len(firstLabel) >= 30` so short high-entropy
   compound labels fall under the floor.

## The scenario

Twenty TXT/NULL queries from one source (`192.168.10.42`) across
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
- **SaaS domain-ownership tokens** that previously tripped the
  entropy-alone path: Google Site Verification, Atlassian
  Domain Verification, Stripe Verification.
- **One NULL qtype** record (rare but seen in SPF lookup chains)

Every label is short, low-to-moderate entropy, and shallow. None
of them cross the surviving signals — label-length-alone at
`DNSTunnelLabelLen=50` (none long enough), entropy-with-length
at `>= 3.5 bits` AND `>= 30 chars` (none long enough), or
depth-alone at `DNSTunnelMinDepth=6` (none deep enough).

## Why this scenario exists

Pre-Bug-3-fix this fixture would have emitted ~20 DNS Tunneling
findings on qtype alone. Pre-entropy-floor-fix the SaaS
verification labels would have emitted three more on entropy
alone. The empty-array result in `expected_findings.json` is the
proof that both paths actually got narrowed — any future
regression that re-adds either trigger would break this golden
loudly.

The companion fixture `dns_tunneling` covers the inverse case: a
realistic 60-char base32 label under TXT that *does* fire the
detector via the length+entropy signals (length 60 ≥ 30, entropy
≥ 3.5). Together they demonstrate the post-fix detection
contract: TXT/NULL is no longer a sole signal, entropy is no
longer a sole signal on short labels, but a label with actual
tunnel structure (long + high-entropy together) still gets
caught.

## Findings produced

`expected_findings.json` is the empty array.
