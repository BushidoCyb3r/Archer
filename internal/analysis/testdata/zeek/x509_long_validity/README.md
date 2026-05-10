# x509_long_validity

Exercises the **Suspicious Certificate** detector via the
long-validity indicator — `notAfter - notBefore > 10 years`. Modern
public CAs cap validity at ~13 months; certificates good for decades
are typically attacker-issued or legacy internal infrastructure.

## Inputs

- `x509.log` — one record with
  `not_valid_before = 1704067200.0` (2024-01-01T00:00:00Z) and
  `not_valid_after = 2524608000.0` (2050-01-01T00:00:00Z) — a
  26-year validity window. Both timestamps use Zeek's default
  encoding for the `time` type: a Unix-epoch float, NOT RFC3339.
  This fixture was rewritten in v0.12.0 (audit NEW-20) — pre-rewrite
  it carried RFC3339 strings that masked a bug where the analyzer
  silently failed `time.Parse(time.RFC3339, ...)` on real Zeek
  output and the entire validity-window check was dead. The
  RFC3339 fallback path is still exercised by `x509_self_signed`
  and `x509_default_subject` (which don't depend on time math but
  retain RFC3339 inputs so a future regression in the fallback
  still gets caught). Subject (`forever.example.org`) doesn't
  match any default-subject substring; subject ≠ issuer; only the
  long-validity path fires.

## Findings produced

- `Suspicious Certificate` (MEDIUM, 58) — Detail shows
  `validity > 10 years`.
