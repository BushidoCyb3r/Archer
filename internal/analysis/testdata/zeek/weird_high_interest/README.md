# weird_high_interest

Exercises the **Protocol Anomaly** detector with a high-interest
weird name — score and severity bumped up because the weird is in
`analysis.highInterestWeird` (e.g., `bad_HTTP_request`,
`malformed_ssh_identification`, `RST_with_data`).

## Inputs

- `weird.log` — one record with `name = bad_HTTP_request`, which is
  in the high-interest map.

## Findings produced

- `Protocol Anomaly` (MEDIUM, 65) — Detail shows the weird name
  passed through verbatim.
