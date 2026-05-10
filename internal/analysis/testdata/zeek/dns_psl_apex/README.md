# dns_psl_apex

Regression fixture for the apex-extraction bug surfaced in the
2026-05-10 audit. Pre-fix the analyzer treated multi-component
public suffixes (`.co.uk`, `.com.au`, `.ac.jp`) as the apex,
bucketing every host under the suffix into one diversity counter
and trivially tripping `DNSUniqueSubdomainMin: 50` against the
public suffix itself.

## The scenario

One source IP (`192.168.5.10`) queries 60 distinct `.co.uk`
registrable domains plus 6 distinct `.com.au` / `.ac.jp` domains.
Each query is its own apex — none of these are subdomains of one
another. A correctly-implemented eTLD+1 extraction (Mozilla's
Public Suffix List) yields 66 distinct apex buckets, each with
zero subdomains beyond the registrable domain itself.

## Why this scenario exists

Pre-fix `apex := strings.Join(labels[len(labels)-2:], ".")` reduced
every `<name>.co.uk` to apex `co.uk`, so all 60 hosts shared a
single bucket `(192.168.5.10, "co.uk")` with 60 unique subdomain
labels. That cleared `DNSUniqueSubdomainMin: 50` and emitted a
HIGH-severity DNS Tunneling finding against `co.uk` — a false
positive in any UK-heavy environment. The same false positive
hit `.ac.jp` and `.com.au` exactly the same way.

Post-fix `apexFromQuery` calls `publicsuffix.EffectiveTLDPlusOne`,
returning the correct registrable domain for each query. Every
bucket has exactly one entry; the diversity floor never trips.

## Findings produced

`expected_findings.json` is the empty array. This is the right
outcome — none of these 66 queries are abnormal individually, and
the diversity counter under correct apex extraction sees no
abnormal accumulation. Any future regression that re-introduces
the naive `labels[-2:]` fallback would produce one or more DNS
Tunneling findings on `.co.uk` / `.com.au` / `.ac.jp` and break
this golden.
