# files_suspicious_ext

Exercises the **Suspicious File Download** detector via the
filename-extension path in `analyzeFiles`. The MIME-based check runs
first; if it doesn't fire, the extension fallback kicks in.

## Inputs

- `files.log` — one record with `mime_type = text/plain` (not
  suspicious) and `filename = loader.ps1`. PowerShell scripts are in
  `analysis.SuspiciousFileExts` so the extension branch fires.

## Findings produced

- `Suspicious File Download` (HIGH, 72) — Detail shows the filename
  reason ("filename: loader.ps1").
