# weird_protocol_anomaly

Exercises the **Protocol Anomaly** detector with a low-interest
weird name — passes through Zeek's weird.log directly with default
score (22 / LOW).

## Inputs

- `weird.log` — one record with `name = data_before_established`,
  which isn't in `analysis.highInterestWeird`, so it falls into the
  default low-severity branch.

## Findings produced

- `Protocol Anomaly` (LOW, 22) — Detail shows the weird name passed
  through verbatim.
