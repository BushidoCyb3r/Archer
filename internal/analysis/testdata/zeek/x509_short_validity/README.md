# x509_short_validity

Exercises the **Suspicious Certificate** detector via the
short-validity indicator — `notAfter - notBefore < 48h`. Real CAs
don't issue certificates that short; this is typical of throwaway
infrastructure.

## Inputs

- `x509.log` — one record with `notBefore = 2024-01-15T12:00:00Z`
  and `notAfter = 2024-01-15T20:00:00Z` — an 8-hour validity window.
  Subject (`ephemeral.example.org`) deliberately doesn't match any
  default-subject substring; subject ≠ issuer; so only the
  short-validity path fires.

## Findings produced

- `Suspicious Certificate` (MEDIUM, 58) — Detail shows
  `short validity (8h)`.
