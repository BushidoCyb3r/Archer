# http_c2_uri_pattern

Exercises the **C2 URI Pattern** detector — URI matches one of the
known C2-framework regex signatures (`/submit.php`, `/news.php`,
8-char alphanumeric Metasploit stagers, etc.).

## Inputs

- `http.log` — one record requesting `/submit.php` from `192.168.3.30`
  → `203.0.113.102:80`. URI byte-sum modulo 256 is 57 (not 92/93), so
  the CS-checksum branch falls through to the regex-pattern check,
  which matches `^/submit\.php$` and labels it "Cobalt Strike
  /submit.php".

## Findings produced

- `C2 URI Pattern` (CRITICAL, 91) — primary target.
- `Host Risk Score` (MEDIUM, 38) — C2 URI Pattern contributes 38.
