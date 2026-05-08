# http_suspicious_file

Exercises the **Suspicious File Download** detector — HTTP requests
ending with an executable/script extension (`.exe`, `.dll`, `.ps1`,
etc.) or returning a MIME type in `model.SuspiciousMIMETypes`.

## Inputs

- `http.log` — one record requesting `/payload.exe` from
  `192.168.3.50` → `203.0.113.104:80`. `.exe` is in
  `SuspiciousFileExts` so the extension branch fires. URI checksum is
  137 (no CS match), URI doesn't match any C2 pattern, UA is
  benign — only the file-download check fires.

## Findings produced

- `Suspicious File Download` (HIGH, 72) — primary target.
  Suspicious File Download isn't in `riskWeights`, so no Host Risk
  Score rolls up.
