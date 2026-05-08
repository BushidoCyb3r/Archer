# http_suspicious_ua

Exercises the **Suspicious UA** detector — HTTP requests with
scripting/automation user agents (`curl/`, `python-requests`, etc.)
that legitimate browsers don't send.

## Inputs

- `http.log` — one record from `192.168.3.10` →
  `203.0.113.100:80` with `user_agent = curl/7.79.1`. Host, URI,
  MIME, and extension are all benign so no other HTTP detectors fire.

## Findings produced

- `Suspicious UA` (LOW, 30) — primary target. Suspicious UA isn't in
  `riskWeights`, so no Host Risk Score rolls up.
