# beacon_channel_split

Exercises **per-channel beacon scoring** (Fork A, the non-destructive
overlay): a single conn-level beacon to one destination that blends two
TLS channels distinguished only by JA3.

## The scenario

`192.168.9.10 → 203.0.113.90:443`, 212 connections, two channels:

- **Clean C2** (JA3 `bbbb…`, SNI `telemetry.example.org`): 72 connections at
  an exact 1200 s cadence with constant payload, spread evenly across a full
  24-hour day. On its own this is a textbook CRITICAL beacon.
- **Noisy CDN** (JA3 `aaaa…`, SNI `cdn.example.net`): 140 connections crammed
  into a single one-hour window mid-day, payloads varying wildly. Concentrated
  in time, it spikes one histogram bucket and shreds the merged inter-arrival
  stream.

## What it proves

Blended on `(src, dst, 443)` the aggregate scores only **MEDIUM (58)** — the
concentrated CDN burst drags the timing and data-size axes down and skews the
histogram, so an analyst skimming MEDIUM beacons could deprioritise it. The
analyzer additionally emits a distinct per-channel `Beacon` finding for the
clean C2 channel at **CRITICAL (85)** — 27 points sharper than the blend —
because that channel, scored alone, is perfectly periodic with full-day
coverage.

Invariants the fixture locks (see `TestPerChannelBeacon_HiddenC2Surfaces`):

1. The blend is **always kept** (overlay never replaces it — no detection lost
   to fragmentation).
2. Exactly one channel is promoted: the C2. The noisy CDN channel scores below
   the blend and is **not** promoted (no duplicate, no fragmentation flood).
3. The promoted channel scores **strictly higher** than the blend — the whole
   point is surfacing a beacon the aggregation was under-scoring.
4. Host Risk Score reflects the channel's 85 via its max-per-type rule, so the
   hidden C2 raises host risk rather than being averaged away.
