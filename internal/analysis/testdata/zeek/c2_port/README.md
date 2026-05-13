# c2_port

Exercises the **C2 Port** detector — outbound traffic to ports
historically associated with C2 frameworks or malware.

## Inputs

- `conn.log` — one record from `192.168.1.60` → `203.0.113.60:4444`.
  Port 4444 is the Metasploit default in `analysis.KnownC2Ports`.

## Findings produced

- `C2 Port` (HIGH) — primary target. C2 Port is not in
  `riskWeights`, so no `Host Risk Score` rolls up from a single C2
  Port hit; that's accurate to the current scoring map.
