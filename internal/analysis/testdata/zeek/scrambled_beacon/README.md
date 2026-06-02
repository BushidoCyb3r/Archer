# scrambled_beacon

Regression fixture for the out-of-order-timestamp `lastTs` rewind
bug surfaced in the 2026-05-10 audit. Real-world triggers for the
underlying scenario: multi-sensor capture merges where clock drift
puts records out of strict timestamp order, rotated logs processed
out of mtime sequence, and Zeek's own connection-close-time logging
which can emit records out of strict order at high load (because
the log entry is keyed on close time, not start time, and longer
connections close later than shorter ones started later).

## The scenario

100 connections from a single source to one destination on TCP/443.
Inter-arrival is exactly 60 seconds for the clean records. Record
index 10 (after 10 well-ordered samples) deliberately jumps
backward 90 seconds — i.e. its timestamp predates record 9 by 30
seconds. The remaining 89 records resume the clean 60-second
cadence from where index 9 left off. 100 samples pushes
`beaconConfMod` to 1.0.

## Why this scenario exists

Pre-fix `st.lastTs = ts` ran unconditionally even when `ts < st.lastTs`.
The skipped-interval branch correctly avoided recording the negative
duration into the reservoir, but the assignment still rewound `lastTs`
to the out-of-order record's earlier value. The next valid forward
record (index 11, real ts = `t0 + 11*60`) computed its interval against
the rewound timestamp (`t0 + 9*60 - 30`), producing a bogus 150-second
interval that landed in the timing reservoir and dragged `ts_score`
down for an otherwise textbook 60-second beacon.

Post-fix the assignment is gated by the same forward-only guard as
the interval recording, so the out-of-order record contributes
nothing — `lastTs` keeps the value from index 9, and index 11's
interval is the correct ~120 seconds (since index 10 was skipped).

## Findings produced

`Beacon` (HIGH) at `192.168.7.10 → 203.0.113.50:443`. The
golden's exact score and component breakdown is captured in
`expected_findings.json`. A regression that re-introduced the
unconditional `lastTs` assignment would shift `ts_score` down
visibly because the bogus 150s sample would re-poison the
reservoir.
