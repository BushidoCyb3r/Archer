# notice_critical

Exercises the **Zeek Notice** detector with a critical-keyword
notice — when the note type contains `scan`, `attack`, `brute`, or
`sensitive` (case-insensitive), severity bumps to CRITICAL and score
to 92.

## Inputs

- `notice.log` — one record with `note = Scan::Port_Scan`. The
  substring `scan` triggers the critical-keyword branch.

## Findings produced

- `Zeek Notice` (CRITICAL, 92) — Detail combines the note type and
  msg, truncating to 200 chars if longer (the fixture stays well
  under that).
