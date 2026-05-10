# x509_short_validity

Exercises the **Suspicious Certificate** detector via the
short-validity indicator — `notAfter - notBefore < 48h`. Real CAs
don't issue certificates that short; this is typical of throwaway
infrastructure.

## Inputs

- `x509.log` — one record with
  `not_valid_before = 1705320000.0` (2024-01-15T12:00:00Z) and
  `not_valid_after = 1705348800.0` (2024-01-15T20:00:00Z) — an
  8-hour validity window. Timestamps are Unix-epoch floats — the
  Zeek default `time` encoding. See `x509_long_validity/README.md`
  for the v0.12.0 audit context behind the format change.
  Subject (`ephemeral.example.org`) deliberately doesn't match any
  default-subject substring; subject ≠ issuer; so only the
  short-validity path fires.

## Findings produced

- `Suspicious Certificate` (MEDIUM, 58) — Detail shows
  `short validity (8h)`.
