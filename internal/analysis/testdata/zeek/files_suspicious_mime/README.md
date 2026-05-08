# files_suspicious_mime

Exercises the **Suspicious File Download** detector via Zeek's
`files.log` analyzer (`analyzeFiles`) on the MIME path. Distinct from
the HTTP-side check in `http_suspicious_file/`, which keys off URI
extension and HTTP `resp_mime_types`.

## Inputs

- `files.log` — one record with `mime_type =
  application/x-dosexec`, the canonical Windows PE indicator. The
  `tx_hosts` (sender) is external, `rx_hosts` (receiver) is
  internal.

## Findings produced

- `Suspicious File Download` (HIGH, 72) — Detail shows the MIME
  reason. The detector reports `SrcIP = rx_hosts` (the host that
  received the file) and `DstIP = tx_hosts` (the source).
