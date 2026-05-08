# notice_zeek

Exercises the **Zeek Notice** detector with a generic notice — Zeek's
notice.log piped through with the default high-severity score (68).

## Inputs

- `notice.log` — one record with `note =
  SSH::Login_From_New_Country`. The note name doesn't contain any of
  the critical-keyword substrings (`attack`, `scan`, `brute`,
  `sensitive`), so it falls into the default HIGH branch.

## Findings produced

- `Zeek Notice` (HIGH, 68) — Detail combines the note type and msg.
