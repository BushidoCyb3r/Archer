# x509_self_signed

Exercises the **Suspicious Certificate** detector via the
self-signed indicator — `subject == issuer` (case-insensitive) on an
x509 record.

## Inputs

- `x509.log` — one record with `subject = issuer = CN=evil.local`.
  Validity window kept normal (one year) so the validity-based
  indicators don't also fire and confuse the Detail string.

## Findings produced

- `Suspicious Certificate` (MEDIUM, 58) — Detail field shows the
  `self-signed (subject==issuer)` indicator.
