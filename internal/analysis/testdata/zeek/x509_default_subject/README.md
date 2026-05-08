# x509_default_subject

Exercises the **Suspicious Certificate** detector via the
default-subject indicator — `subject` substring-matches one of
`model.DefaultCertSubjects` (`internet widgits`, `localhost`, `test`,
`openssl`, `self-signed`, etc.).

## Inputs

- `x509.log` — one record with `subject = CN=openssl cert`. The
  detector's match loop runs in list order and the first hit wins;
  the subject is deliberately chosen so only `openssl` matches (not
  `test`, `localhost`, etc.) and the captured indicator is clean.

## Findings produced

- `Suspicious Certificate` (MEDIUM, 58) — Detail field shows
  `default subject ("openssl")`.
