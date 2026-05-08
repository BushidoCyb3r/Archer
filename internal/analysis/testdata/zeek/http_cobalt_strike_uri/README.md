# http_cobalt_strike_uri

Exercises the **Cobalt Strike URI** detector — URIs whose ASCII
byte-sum modulo 256 equals 92 (x86 stager) or 93 (x64 stager), the
classic Cobalt Strike beacon checksum signature.

## Inputs

- `http.log` — one record requesting `/xyzaa` from `192.168.3.20` →
  `203.0.113.101:80`. The URI byte-sum (`/`+`x`+`y`+`z`+`a`+`a` =
  47+120+121+122+97+97 = 604) modulo 256 is 92 → x86 variant fires.
  Host, MIME, extension, UA all kept benign so only the CS check
  trips. Note the URI deliberately is not 8 alphanumeric characters,
  so it doesn't also match the Metasploit-stager regex (which would
  fire C2 URI Pattern instead — but that branch is bypassed since the
  CS check fires first when checksum is 92/93).

## Findings produced

- `Cobalt Strike URI` (CRITICAL, 93) — primary target.
- `Host Risk Score` (MEDIUM, 40) — Cobalt Strike URI contributes 40.
