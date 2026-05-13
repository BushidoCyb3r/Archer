# lateral

Exercises the **Lateral Movement** detector — internal-to-internal
traffic on common admin protocol ports.

## Inputs

- `conn.log` — one record from `192.168.1.50` → `192.168.1.51:445`
  (SMB). Both endpoints are RFC 1918 internal; port 445 is in
  `analysis.LateralMovementPorts`.

## Findings produced

- `Lateral Movement` (HIGH) — primary target.
- `Host Risk Score` (LOW) — Lateral Movement contributes 20 to
  composite risk.
