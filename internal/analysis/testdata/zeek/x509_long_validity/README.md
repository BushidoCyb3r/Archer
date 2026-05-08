# x509_long_validity

Exercises the **Suspicious Certificate** detector via the
long-validity indicator — `notAfter - notBefore > 10 years`. Modern
public CAs cap validity at ~13 months; certificates good for decades
are typically attacker-issued or legacy internal infrastructure.

## Inputs

- `x509.log` — one record with `notBefore = 2024-01-01T00:00:00Z`
  and `notAfter = 2050-01-01T00:00:00Z` — a 26-year validity window.
  Subject (`forever.example.org`) doesn't match any default-subject
  substring; subject ≠ issuer; only the long-validity path fires.

## Findings produced

- `Suspicious Certificate` (MEDIUM, 58) — Detail shows
  `validity > 10 years`.
