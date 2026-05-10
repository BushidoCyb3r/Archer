# files_drive_by_outbreak

Regression fixture for the `analyzeFiles` dedup-key bug surfaced in
the 2026-05-10 audit (NEW-2). Pre-fix the dedup key was
`(sender, filename+mime)`, which means a drive-by where one
external host pushes the same malware sample to N internal victims
collapsed to a single Suspicious File Download finding (whichever
victim was logged first); the other N-1 victims were silently
swallowed.

## The scenario

Three internal hosts (`192.168.5.10`, `192.168.5.20`,
`192.168.5.30`) each download `malware.exe` (MIME
`application/x-dosexec`) from one external sender (`203.0.113.50`).
A textbook outbreak: same upstream, same payload, multiple
victims, staggered timestamps.

## Why this scenario exists

Under the broken dedup key, `seen[("203.0.113.50",
"malware.exeapplication/x-dosexec")]` is set after the first record
and the next two emit nothing. The auditor's framing was that the
`src` / `dst` variable naming made the bug visually invisible —
`src` held the sender (`tx_hosts`) but the finding's `SrcIP` was
the receiver, so a fast read of "key uses `src`, finding uses
`SrcIP`" misses the inversion. v0.10.0 renamed to
sender / receiver and re-keyed dedup on `(receiver,
filename+mime)`, mirroring `checkFileHashes`'s `(rx, hash)`
convention.

## Findings produced

Three `Suspicious File Download` findings, one per victim. Each
carries `SrcIP` = victim, `DstIP` = sender, score 72. A regression
that re-introduces the sender-keyed dedup would produce one
finding instead of three and break this golden loudly.
