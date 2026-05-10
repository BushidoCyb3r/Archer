# Changelog

All notable changes to Archer are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) plus a custom
**Detection changes** section that flags any change to score formulas,
thresholds, or finding semantics — analysts use that section to decide
whether their existing baselines need re-grounding.

## Versioning

Archer is versioned with [Semantic Versioning](https://semver.org/) under
the **0.x prefix**: pre-1.0 minor versions may break any of four surfaces
without a major bump. Once Archer reaches 1.0 those four surfaces become
the stability contract.

The four breaking-change categories:
1. **HTTP/SSE API contract** — renamed/removed fields in `/api/*`, changed
   SSE event shapes.
2. **DB schema** — table changes that require data migration on upgrade.
3. **Quiver sensor protocol** — enrollment payload, rsync layout, ports,
   `quiver.sh` schedule contract.
4. **Detection semantics** — score formulas, thresholds, finding types,
   feed-matching logic.

Any of those changing at minor-bump granularity (e.g. v0.1 → v0.2) is
expected pre-1.0. They will be called out under `### Breaking` and, where
relevant, `### Detection changes` in each release entry.

---

## [Unreleased]

## [v0.10.0] — 2026-05-10

Second audit-driven correctness release in two days. Six new
issues surfaced by the 2026-05-10 external review (third pass on
the codebase) plus the deferred Bug 3 from v0.9.0. The auditor's
meta-point landed harder than any single bug: the v0.9.0 parser
trust-fix should have generalised "where else do we swallow
errors and infer no-result?" The TI HTTP clients were doing
exactly that (NEW-1) — same lesson, different surface. That
discipline gap is recorded in MATURATION_PLAN section 8.

### Added

- **`Analyzer.TIErrors()` API + SSE status surface for TI source
  failures.** Mirrors `ParseErrors()` from v0.9.0. Pre-fix every
  external HTTP client (OTX, AbuseIPDB, Feodo Tracker, URLhaus)
  silently treated non-2xx responses as "no hit" — JSON decoded
  into the empty struct, count == 0 → operator saw a clean
  finding-detail panel and concluded the dataset was clean when
  the upstream had returned 401 (bad key), 429 (rate limited),
  or 503 (upstream sick). New `recordTIError(source, err)` helper
  accumulates failures on the analyzer and pushes them through
  the SSE status banner (`"TI warning: <source> — <err> (results
  may be incomplete)"`). Trust-bug class generalised from the
  v0.9.0 parser path. Audit 2026-05-10 NEW-1.

- **`files_drive_by_outbreak` regression fixture.** Three
  internal hosts download `malware.exe` from one external
  sender. Pre-fix the dedup key used the sender, collapsing the
  three victims to one finding. Post-fix yields three findings,
  one per victim — see NEW-2 below.

### Changed

- **`extractHost` now uses `net/url.Parse` for URL parsing.**
  The hand-rolled trim chain mishandled `user:pass@host` URLs:
  the early colon in the userinfo confused the port-strip step
  ("only one colon before the last colon") and left
  `user:pass@evil.com` unmatched against URLhaus / feed buckets.
  Edge case for malware URLs but fragile. Falls back to the
  legacy chain (with an added `@`-strip) for scheme-less inputs
  that `net/url.Parse` won't recognise as URLs. Audit 2026-05-10.

- **Login form lowercases the email before authenticating.**
  Registration already lowercased; login relied on the SQL's
  `COLLATE NOCASE` for case-insensitive match. Anyone removing
  the COLLATE clause thinking emails were normalised at write
  time would silently break login. Now consistent at both
  edges. Audit 2026-05-10.

### Removed

- **`Analyzer.httpUIDIndex` dead state.** Same shape as the
  `st.total` cleanup in v0.9.0: the map was written for every
  HTTP request via `a.httpUIDIndex[uid] = httpEntry{...}` but
  never read anywhere. Wasted one map entry per HTTP record
  for a feature that didn't exist. The `httpEntry` type goes
  with it. If a real cross-protocol pivot against `http.log`
  emerges later, the right shape is to mirror `sslUIDIndex` and
  reintroduce intentionally. Audit 2026-05-10.

### Fixed

- **TI HTTP clients now check `resp.StatusCode` and surface
  failures (NEW-1).** Per the new TIErrors API above. The four
  package-level functions (`fetchFeodo`, `fetchURLhaus`,
  `checkOTX`, `checkAbuseIPDB`) became methods on `*Analyzer` so
  they can route failures through `recordTIError`. Decode errors
  also flow through the same path now (pre-fix decode-fail and
  no-hit were indistinguishable to the caller).

- **`analyzeFiles` dedup no longer swallows multi-victim
  drive-by outbreaks (NEW-2).** Pre-fix the dedup key was
  `(sender, filename+mime)`, so 100 internal victims downloading
  the same file from one external sender collapsed to one
  finding (whichever was logged first). Audit framed the
  variable naming as the footgun: `src` held the sender
  (`tx_hosts`) but the finding's `SrcIP` was the receiver, so a
  fast read of "key uses src, finding uses SrcIP" missed the
  inversion. Variables renamed to `sender` / `receiver` and the
  dedup key now uses the receiver, matching `checkFileHashes`'s
  `(rx, hash)` convention next door. New
  `files_drive_by_outbreak` golden asserts three findings on
  three victims of one outbreak.

- **`isIPAddr` 3-dot heuristic replaced with `net.ParseIP`
  (NEW-3).** The dot-counting heuristic treated any string with
  exactly 3 dots as an IP. Real-world casualties:
  `cdn.staging.example.com`, `subdomain.team.acme.io`,
  `mail.engineering.example.org` — all 3-label FQDNs — were
  routed to the IP bucket and never matched against URLhaus
  hosts or feed domains, so a malicious 3-label hostname on
  URLhaus silently missed. One-line fix. Audit 2026-05-10.

- **Findings filter respects the operator timezone (NEW-4).**
  Pre-fix `parseFindingTime` used `time.Parse` (UTC by default)
  for HTML datetime-local strings, so a Tampa operator entering
  "9:00 AM" got findings between 04:00–12:00 UTC (i.e. the
  previous local day evening through next local morning). The
  off-hours detector already honoured `cfg.Timezone`; the
  findings filter didn't. Now consistent. Caller passes the
  operator's `*time.Location`; analyzer-emitted Timestamp
  parsing still uses UTC. New `Server.operatorLocation()`
  helper. Audit 2026-05-10.

- **`parseIPMatcher` substring fallback gated on hostname shape
  (NEW-5).** Pre-fix typing `1` in the Src IP filter
  substring-matched every finding whose IP contained a 1 (most
  of the dataset). Same problem with any partial-IP-being-typed.
  The substring fallback (which exists to support hostnames in
  the SrcIP/DstIP fields for unresolved records) now requires at
  least one ASCII letter — purely numeric inputs that aren't
  valid IPs/CIDRs return nil (no filter applied) instead of
  matching everything. Audit 2026-05-10.

- **`Strobe` / `Exfil` / `Lateral Movement` / `Off-Hours
  Transfer` detectors now partition by sensor (NEW-6).** v0.8.0
  added sensor to `pairKey` for beacons; the four other conn-
  level detectors kept their `(src, dst)` keys. A Quiver
  deployment with overlapping sensor captures was double-
  counting strobe records, summing exfil bytes across sensors,
  and emitting one Lateral Movement / C2 Port finding per
  sensor for the same connection — thresholds calibrated on
  single-sensor traffic spuriously tripped. Single-sensor
  deployments unchanged (sensor field is constant); multi-
  sensor overlapping deployments stop double-counting. Audit
  2026-05-10. The asymmetry with beacons is now resolved.

- **`notice.go` truncation is rune-aware.** The previous byte-
  slice at index 197 could land mid-multi-byte-character on
  UTF-8 input and the trailing ellipsis would produce invalid
  UTF-8. New `truncateRunes` helper iterates runes. Audit
  2026-05-10 cosmetic.

### Detection changes

- **TI source coverage is now legible.** Pre-fix any non-2xx
  response from OTX / AbuseIPDB / Feodo Tracker / URLhaus
  silently became "no hit" downstream. Post-fix the same
  failure surfaces in the SSE status banner during the run and
  is retrievable via `Analyzer.TIErrors()` afterwards. The set
  of *findings emitted* doesn't change for clean upstream runs;
  the change is that incomplete coverage stops being invisible.

- **`analyzeFiles` emits one finding per (victim, file) instead
  of one per (sender, file).** Multi-victim drive-by outbreaks
  now produce one Suspicious File Download per victim — a
  change in count of findings emitted on the same input.
  Single-victim scenarios unchanged. Re-baseline alerting that
  was tuned to the under-counted pre-fix volume.

- **DNS Tunneling firing population narrows — the qtype-alone
  path is gone.** Pre-fix any TXT/NULL query produced a finding;
  post-fix only queries with structurally tunnel-shaped labels
  (long, high-entropy, or deeply nested) fire. Real DNS tunneling
  tools (iodine, dnscat2, Cobalt Strike's DNS beacon) couple
  TXT/NULL with long high-entropy labels because that's the
  channel capacity, so the surviving length / entropy / depth
  signals keep coverage on real attacks. Re-baseline DNS
  Tunneling alerting in any environment where the false-
  positive flood was being filtered downstream — the upstream
  now does the filtering. Bug 3 was deferred from the v0.9.0
  audit for design work; option A (drop outright) shipped per
  the auditor's explicit endorsement. See TODO 1f for the four
  alternatives that were considered (gate on second signal,
  volume detector, apex allowlist, behavior-based gate).
  `dns_tunneling` golden rewritten to a realistic 60-char base32
  label (now scores 83 vs the prior 64 because length+entropy
  combine); new `dns_txt_legitimate` fixture asserts the empty
  array on 17 realistic SPF/DKIM/DMARC/ACME queries.

### Breaking

- **`/api/findings?src_ip=...` and `?dst_ip=...` no longer
  substring-match purely numeric inputs.** Pre-fix any input was
  routed through the substring fallback when not a valid IP/CIDR;
  numeric partials (`1`, `19`, `192.168`) matched every finding
  containing the digits. Now those return no matcher (filter not
  applied). Hostname-shaped inputs (containing at least one
  letter) still substring-match the SrcIP/DstIP fields.
  External scripts that were using purely numeric substring
  searches will need to switch to either a complete IP/CIDR or
  a hostname-shaped query.

## [v0.9.0] — 2026-05-10

Audit-driven correctness release. The 2026-05-10 external review
surfaced six issues that span the conn analyzer, the DNS analyzer,
and the parser layer. Five resolved here (Bug 3, the TXT/NULL
single-signal DNS Tunneling false positive, deferred for design
work). Plus the cosmetic items the auditor flagged and three new
regression fixtures so this class of bug doesn't recur silently.

### Added

- **`Analyzer.ParseErrors()` API.** Returns the list of files that
  failed to parse during the analysis pass with the underlying error
  string per file. Intended for higher-level callers (web UI, future
  CLI) to surface a "this analysis didn't see everything" indicator
  to operators rather than reporting a finding count that implies
  cleanly-parsed-the-whole-corpus when the parser had bailed
  mid-file. Empty slice on a clean run.

- **Regression fixtures for the audit's failure modes.**
  `internal/analysis/testdata/zeek/scrambled_beacon/` exercises a
  30-connection beacon with one out-of-order record (multi-sensor
  clock-drift simulation) — pre-Bug-1-fix the bogus rewound `lastTs`
  poisoned the next valid interval, dragging `ts_score` down for a
  textbook beacon; the fixture's golden captures the post-fix
  `ts=1.00` state.
  `internal/analysis/testdata/zeek/dns_psl_apex/` exercises 60
  distinct `.co.uk` registrable domains plus six `.com.au` / `.ac.jp`
  ones — pre-Bug-6-fix all 60 lumped under apex `co.uk` and tripped
  `DNSUniqueSubdomainMin: 50`, emitting a HIGH-severity DNS
  Tunneling false positive against the public suffix itself; the
  fixture's golden is the empty array (post-fix correctly buckets
  per registrable domain). Auditor explicitly noted that golden
  fixtures with perfectly-ordered timestamps and high connection
  counts hid this entire class of bug; these fixtures invert that.
  `internal/parser/zeeklog_test.go` covers the Bug 4 oversized-line
  behavior at the parser level: a 2 MiB record now parses cleanly,
  a 17 MiB record (past the new 16 MiB ceiling) returns a non-nil
  error rather than silently truncating.

### Changed

- **Parser scanner buffer raised from 1 MiB to 16 MiB; per-file
  parse errors now propagate.** External review (2026-05-10) framed
  this as the most important issue of the audit — a "trust bug,"
  not a detection bug. Pre-fix every analyzer used
  `_ = parser.ParseLog(...)`, discarding the error. A single record
  longer than the 1 MiB scanner buffer (large HTTP POST URI,
  base64-encoded upload, fat `set[string]` field, JSON record with
  hundreds of services) returned `bufio.ErrTooLong` from the parser
  and the analyzer silently truncated the file at the long line.
  The analyst saw a finding count that implied the whole capture
  had been processed when the parser had bailed mid-file. Modern
  HTTP captures regularly exceed 1 MiB on a single record.
  Considered: streaming JSON decode (rejected as scope creep — the
  buffer raise covers realistic captures and the streaming work
  belongs in a future release if 16 MiB ever proves insufficient).
  Shipped: 16 MiB ceiling on the scanner buffer, plus a new
  `Analyzer.parseLog` helper that surfaces failures via the SSE
  status channel (`"Parser warning: <file> — <err> (file
  partially read)"`) and accumulates them on the analyzer for
  end-of-run reporting through the new `ParseErrors()` API. Every
  swallow site in `internal/analysis/` migrated to the helper. The
  raw-log pivot endpoint (`internal/server/findings_raw.go`) logs
  per-file failures to the server log instead.

- **Settings section "Threat Intelligence" renamed to "Threat Intel
  Lookup APIs".** Operator question raised whether the per-finding
  enrichment keys (VirusTotal, AbuseIPDB, OTX, CrowdSec, GreyNoise,
  Censys) should move into the Feeds dialog alongside MISP/OpenCTI
  for one-stop TI configuration. Considered: consolidating into the
  Feeds dialog as a second zone. Preserved: the split between
  detection-input feeds (bulk indicator pulls on a watch cadence)
  and lookup APIs (per-finding analyst pivots), since they have
  different operational shapes and the Feeds dialog's CRUD-row UI
  doesn't fit flat key-value config. Shipped: the cheaper rename
  plus a one-line helper text pointing operators at the Feeds
  dialog if they're looking for bulk-indicator sources.

### Removed

- **Dead code: `Analyzer.observeWindow` method, `beaconState.total`
  and `httpBeaconState.total` fields.** External review noted both
  were defined-but-unused — `observeWindow` was never called
  (analyzers manipulate `localWindows` directly to avoid taking
  `a.mu` per record), and `total` was incremented in two places
  but never read. The actual connection-count source is
  `pairCounts[pk]`. Considered: migrating analyzers to call
  `observeWindow` for single-point-of-control. Rejected: that path
  forces a mutex acquisition per record on the hot loop, regressing
  performance for an aesthetic gain. Deletion is the right call.

### Fixed

- **Out-of-order timestamps no longer rewind `lastTs` and poison
  the next valid interval.** External review (2026-05-10) flagged
  this in both `conn.go` and `http_analysis.go`. Pre-fix
  `st.lastTs = ts` ran unconditionally even when `ts < st.lastTs`;
  the skip-recording branch correctly avoided sampling the negative
  interval, but the assignment still rewound `lastTs` to the earlier
  value. The next valid forward record then computed its interval
  against the rewound timestamp, sampling an inflated bogus value
  into the timing reservoir. Real-world triggers: multi-sensor
  capture merges with clock drift, rotated logs processed out of
  mtime order, and Zeek's own connection-close-time logging which
  emits records out of strict order at high load. Fix is the
  forward-only guard around the assignment, matching the guard that
  was already protecting the interval recording.

- **Lazy-init beacon-state replay now back-fills every dimension,
  not just intervals.** External review framed this as the same
  class of bug as the v0.8.0 lazy-init fix: that fix addressed the
  framing of the prior auditor's critique (timing-axis intervals)
  without addressing what the critique was about (data fidelity for
  borderline beacons). The lazy-init guard at conn 3 dropped
  connections 1 and 2's contribution to *every* axis, not just
  `ivs`. Pre-fix `firstTs` reported conn 3's timestamp (analyst
  chasing "when did this start" got the wrong answer), `minTs` was
  used by `durationScoreFromHourMap` for coverage so the duration
  span was 2 connections too narrow, `byteVals` (data-size axis)
  ran on N-2 samples while the finding still claimed N, `hourMap`
  (histogram axis) was missing two buckets, and `tsData` (Beacon
  Chart) was missing the first two data points. For a beacon at
  exactly `BeaconMinConnections=10` that's 20% of every axis
  silently dropped. Fix: `preBeaconTs map[pairKey][]float64`
  becomes `preBeaconRecs map[pairKey][]preBeaconRec` carrying
  full `(ts, origB, respB)` triples; the replay path now touches
  `firstTs`, `minTs`, `maxTs`, `ivs`, `byteVals`, `tsData`, and
  `hourMap`. Same fix in HTTP beacon path. The `Timestamp` shift
  on existing goldens (`strobe`, `beacon_url`, `http_beacon`,
  `multimode_beacon`) reflects the corrected `firstTs` semantic.

- **DNS NXDOMAIN-flood `Timestamp` no longer poisoned by an initial
  `ts == 0`.** External review noted same class as the
  out-of-order bug: pre-fix `nxFirst[src]` could be set to 0 on a
  leading record with a missing `ts` field, after which any valid
  forward timestamp failed the `ts < nxFirst[src]` comparison and
  never updated. The NXDOMAIN Flood finding then reported
  `Timestamp: ""`. Fix is the same `ts > 0` guard pattern
  `apexMap[k].firstTS` already used in the next block down.

- **DNS apex extraction now uses the Mozilla Public Suffix List.**
  External review flagged that the `labels[len-2:]` heuristic
  treated `.co.uk`, `.com.au`, `.ac.jp`, `.gov.cn` as bare apexes,
  bucketing every host under the public suffix into a single
  diversity counter. UK-heavy environments tripped
  `DNSUniqueSubdomainMin: 50` against `co.uk` itself trivially —
  HIGH-severity DNS Tunneling false positives that buried any real
  tunneling under the noise. Fix: new `apexFromQuery` helper calls
  `golang.org/x/net/publicsuffix.EffectiveTLDPlusOne` (Mozilla's
  canonical PSL binding, already in our indirect deps); falls back
  to the legacy heuristic only when the PSL doesn't recognise the
  input as a public name. Promotes `golang.org/x/net` from
  indirect to direct.

- **Misleading `seenPerQuery` map name in `dns.go` renamed to
  `seenTunnel`.** Audit noted the key shape was `[2]string{src,
  apex}` so the map deduplicates per (src, apex) for tunneling
  findings, not per query. Pure rename, no behavior change.

- **Off-hours config validation: `OffHoursStart == OffHoursEnd`
  now rejected at PUT time.** Pre-fix the wraparound branch
  (`start > end`) was false and the standard branch
  (`hour >= X && hour < X`) was always false, silently disabling
  off-hours detection without any operator signal. New
  `/api/config` PUT validation rejects equal values with HTTP 400
  and a descriptive error. Out-of-range start/end (outside `[0,23]`)
  also now rejected. See `### Breaking` below.

### Detection changes

- **Beaconing/HTTP-Beaconing `Timestamp` field reports the first
  connection's true ts, not conn 3's.** A direct consequence of
  the lazy-init replay fix above. Visible on the existing golden
  fixtures: `strobe` `Timestamp` shifted from `12:00:38` to
  `12:00:00`, `beacon_url` from `12:02:00` to `12:00:00`,
  `http_beacon` from `12:02:00` to `12:00:00`, `multimode_beacon`
  from `12:02:01` to `12:00:00`. Score is unchanged on the
  already-deterministic high-volume fixtures (`strobe`,
  `beacon_url`, `http_beacon`); `multimode_beacon` shifted from
  54 → 53 because the now-correct full-record contribution to
  byte-size and hour-bucket axes adjusts `ds_score` (0.96 → 0.97)
  and `hist_score` (0.24 → 0.19) on a 40-connection fixture where
  the missing 2 records were 5% of the data. Direction is
  uniformly toward correctness. Re-baseline any min-score alerting
  that was tuned to the pre-fix scores on at-or-near-threshold
  beacons.

- **Out-of-order capture timestamps now produce correct interval
  reservoirs.** Multi-sensor merges with clock drift and
  high-load Zeek captures with close-time records produce out-of-
  order timestamps. Pre-fix any such occurrence dragged `ts_score`
  down via the rewound-`lastTs` poisoning. Post-fix the
  out-of-order records contribute nothing to interval timing
  (they still increment connection counts and other axes). On
  cleanly-ordered captures there is no change. On out-of-order
  captures `ts_score` rises toward the correct value.

- **DNS Tunneling no longer fires false positives against
  multi-component public suffixes.** PSL apex extraction means
  `.co.uk`, `.com.au`, `.ac.jp`, etc. environments stop emitting
  HIGH-severity DNS Tunneling findings against the public suffix
  itself. Conversely, real DNS tunneling under e.g. `evil.co.uk`
  now correctly accumulates diversity within its own
  `evil.co.uk` apex bucket rather than being smeared across all
  `.co.uk` traffic. Re-baseline diversity-based DNS Tunneling
  alerting in non-US environments — false-positive volume drops
  meaningfully and any true positives that were being masked by
  the noise should surface cleanly.

### Breaking

- **`/api/config` PUT now rejects `off_hours_start == off_hours_end`
  with HTTP 400.** Pre-fix equal values silently disabled
  off-hours detection. External scripts that uploaded a config
  with equal values to "disable" off-hours will need a different
  approach (set start to a time the analyst's traffic doesn't
  fall into, or wait for a future explicit `off_hours_enabled`
  flag). Out-of-range start/end (outside `[0,23]`) also now
  rejected.

## [v0.8.0] — 2026-05-10

### Added

- **Type-sharded parallel MISP fetch with larger pages.** A full
  MISP pull no longer issues one big restSearch query covering all
  seven attribute types — instead it dispatches one query per type
  (`ip-src`, `ip-dst`, `domain`, `hostname`, `md5`, `sha1`,
  `sha256`) and runs them in parallel, capped at four in flight at
  once. Each shard restarts pagination from page 1 of just its
  type, so the offset-pagination cost that used to push deep pages
  to multi-second responses gets distributed across seven shallower
  walks running concurrently. Hardcoded concurrency=4 is sized for
  a 6-core single-VM MISP — leaves headroom for Apache, the OS, and
  background MISP work while still bringing wall-clock down
  meaningfully on large feeds. Single-feed PageSize default raised
  from 10 000 to 25 000 attributes per page; fewer round trips per
  shard with no measurable memory pressure on either side. First
  shard error cancels the rest via context and is surfaced to the
  feeds dialog. Tests cover the request fanout, the concurrency
  cap, and the per-shard `timestamp` filter pass-through under the
  race detector.

- **Incremental MISP feed sync.** Watch-tick feed refreshes now use
  MISP's `restSearch` `timestamp` filter to fetch only attributes
  modified since the previous run, instead of paginating the full
  snapshot every time. On feeds with hundreds of thousands of
  attributes, restSearch's offset pagination degrades from ~150ms at
  page 1 to several seconds at page 100; cutting the result set down
  with the `timestamp` filter keeps the fetch in the cheap
  shallow-page region. New `last_full_refresh_at` column on the
  `feeds` table tracks the most recent full pull separately from
  `last_refresh_at` (which now records any kind of fetch). The
  scheduler picks full vs incremental per-feed based on the
  full-refresh cadence: half the configured aging window with a
  24-hour floor, or weekly when aging is disabled. The cadence is
  sized below the aging window so unchanged-but-still-current
  indicators get `last_seen` bumped before the aging sweep would
  delete them. Aging-prune runs only on full pulls. The per-row
  Refresh button on the admin Feeds dialog is unchanged in shape but
  now always forces a full pull — operators clicking Refresh are
  asking for verification, not a cheap delta. The Feeds row's
  refresh-time cell gains a tooltip showing the last full refresh
  timestamp so operators can tell which fetches were cheap
  incrementals vs the periodic deep sync. OpenCTI's adapter accepts
  the `since` argument to satisfy the new interface but ignores it
  for now — its cursor pagination doesn't suffer from the
  offset-degradation problem MISP's does, so the urgency is lower.

- **Live indicator-count progress in the Feeds dialog.** While a feed's
  `status` is `fetching` the row now shows the running `feed_indicators`
  row count for that feed (e.g. `184,237 ingesting…`) instead of the
  stale `last_indicator_count` from the previous settled fetch. The
  Feeds dialog auto-polls `/api/feeds` every 2.5 s while open, so a
  long MISP import that's been paginating for tens of minutes shows
  visible progress instead of a yellow `fetching` pill that never
  changes. New `live_indicator_count` field on the `/api/feeds`
  response, backed by a single `SELECT feed_id, COUNT(*) … GROUP BY
  feed_id` query per request. Settled feeds keep showing the existing
  `last_indicator_count` exactly as before.

- **Jittered-single-mode beacon detection via interval entropy.** A
  new `intervalEntropyScore` helper bins intervals on a log2 axis
  and computes Shannon entropy of the bin counts, normalised against
  `log2(nBuckets)`. A beacon at 60s ± 50% jitter scores poorly on
  Bowley + MAD (deviations are large relative to the median) but
  every interval still lands in the same one or two log2 buckets,
  so entropy stays low and the score stays high. Wired into the
  timing-axis composite as `tsScore = max(raw, multimodal, entropy)`,
  so single-mode tight beacons (where all three score ~1) and
  multi-period beacons (where multimodal already rescues) are
  unaffected. Existing golden fixtures pass without re-baseline
  because none of them exercise the jittered-single-mode case.
  See `docs/DETECTION_METHODS.md` § 2.2(a) for the math.

- **Multi-period beacon detection on the timing axis.** A new
  `intervalMultimodalScore` helper rescues beacons whose intervals
  cluster around 2–4 distinct values (heartbeat + tasking, idle +
  active, etc.) — those would otherwise be under-scored by Bowley
  and MAD applied to the raw distribution. Algorithm: log2-bin
  intervals, find peaks, score each peak's tightness via
  `(median − MAD) / median`, weighted-average the per-peak scores.
  Returns 0 (deferring to the existing math) for single-mode
  distributions, ≥5-mode distributions (too noisy), or any peak
  loose enough to score below 0.5. Caller takes `max(raw, multimodal)`,
  so single-mode beacons are unaffected. New
  `multimode_beacon` golden fixture exercises a 60s-heartbeat plus
  600s-tasking pattern and demonstrates the rescue: `ts=0.99` lifts
  the Beacon finding into HIGH severity (score 54) where the raw
  math would have left it well below threshold.

- **`/api/findings/{id}/position` endpoint.** Returns the absolute
  zero-indexed position of a finding within `/api/findings` under
  the same filter + sort parameters. Backs the Jump action's
  page-offset lookup; useful to any external script that wants to
  navigate to a specific finding within a paginated view.

- **HTTP Min Requests input in the Settings dialog.** The
  `http_beacon_min_requests` threshold was already documented in
  the README and read by the analyzer, but the Settings dialog
  never exposed an input for it — admins had to drive `/api/config`
  directly to tune it. New control sits next to Min Connections
  in the Beaconing section and round-trips through the same
  `/api/config` PUT the existing controls use.

### Changed

- **MISP/OpenCTI feed-fetch timeouts raised for larger deployments.**
  Manual refresh cap (`POST /api/feeds/{id}/refresh`) raised from 60s
  to 5 minutes. Watch full-pass pre-fetch cap raised from 2 minutes
  to 10 minutes. Per-page HTTP client timeout in
  `internal/feeds/misp.go` raised from 30s to 90s. Confirmed against
  a real 100k+ indicator MISP where offset-based pagination degrades
  with depth (page 1 at 0.16s, page 100 at 3.5s — total walk ~3
  minutes). The bumped caps unblock the existing full-sweep adapter;
  the principled fix (incremental sync via `timestamp` parameter,
  streaming decode, periodic full re-sync) is queued in
  MATURATION_PLAN section 11c, with a per-feed operator-supplied
  query filter as the intermediate step queued in TODO.md 1d.

### Removed

- **Four beacon-config fields that no analyzer ever read.**
  `beacon_max_jitter_cv`, `beacon_min_interval_sec`,
  `beacon_gap_multiplier`, and `http_beacon_max_cv` were
  documented in the README's threshold table as tunable knobs
  and round-tripped through `/api/config`, but referenced
  exactly twice each — once in the struct, once in the default
  — and never read anywhere in `internal/analysis/`. An
  operator who set them via the API saw them persist to SQLite
  and have zero effect on detection. Dropped from the struct,
  defaults, and README. Only `beacon_min_connections` and
  `http_beacon_min_requests` continue to gate detection (both
  remain).

### Fixed

- **`/logs/_archived/` is now excluded from the live logs tree and
  every analyze pass.** The purge bucket — where the admin **Purge
  data** action rotates a disenrolled sensor's `/logs/<name>/`
  aside to `/logs/_archived/<name>-<timestamp>/` — was leaking into
  two paths: the sidebar Logs preview tree showed `_archived` as if
  it were a sensor (`handleLogsTree`), and `scanLogsDir` walked it
  recursively so every full analyze pass re-processed purged-sensor
  data and emitted fresh findings tagged `sensor=_archived`. Both
  paths now skip the subtree, matching the convention already used
  by `disk_usage.go`. Findings tagged `sensor=_archived` from prior
  runs stay in the database (fingerprint-merge preserves them) and
  will simply stop refreshing — operators wanting them gone can
  prune via `/api/archive/run` once they age past the archive
  retention cutoff. Raw-log pivot via `/api/findings/{id}/raw` still
  searches `_archived` so analysts can review historical records on
  pre-purge findings.

- **Lazy-init beacon state no longer drops the first two intervals.**
  Per-pair `beaconState` is allocated lazily on connection 3
  (`beaconLazyMinConn = 3`) to bound memory on high-cardinality
  low-count streams. The struct literal initialised `firstTs`/`minTs`/
  `maxTs` from the current record but left `lastTs` at zero, so the
  reservoir-recording guard (`if st.lastTs > 0 && ts > st.lastTs`)
  silently skipped the first interval, and the ts values from
  connections 1 and 2 were never seen at all. Result: every beacon
  paid a two-interval tax — irrelevant on a 1000-connection stream,
  ~22% of the timing data on a 10-connection stream right at the
  detection threshold. Fix: stash the timestamps of pre-allocation
  connections in a `preBeaconTs` map; on state allocation, replay
  them so intervals 1→2 and 2→3 land in the reservoir alongside
  every later interval. Same fix applied to `analyzeHTTP`'s lazy
  init path. ~16 bytes/pair worst-case extra memory before
  allocation; freed on allocation.

- **Beacon hist + duration scoring no longer smears across sensors.**
  The conn analyzer was computing one global `(dsMin, dsMax)` capture
  window across every conn.log file in `/logs/`, regardless of which
  sensor produced it. A real beacon inside a January capture got
  scored against a window that ran from January through whatever the
  newest log in any other sensor's tree was — coverage cratered, and
  every per-pair hour-bucket collapsed into 1 of 24 global buckets,
  zeroing both the histogram and duration components (50% of the
  beacon score). Fix: each sensor (the first path component under the
  analyzer's path root) gets its own capture window, stored in
  `Analyzer.sensorWindows`, and beacon pairs carry the originating
  sensor in their map key so scoring picks up the right window. Same
  fix applied to HTTP Beaconing in `analyzeHTTP`. As a side effect the
  same `(src, dst)` from two sensors no longer merges into one beacon
  state — that latent bug went away with the pair-key change.

- **Bell-notification Jump now lands on the target finding regardless
  of filter/pagination/delta state.** Pre-fix the Jump button silently
  no-op'd when the active tab's filter excluded the target, when the
  current page didn't contain it, or when delta mode was on. The
  handler now resets every filter input (search, src/dst/port,
  severity, type, sensor, score floor, time range → All time, delta
  off), switches to the tab matching the finding's status, queries
  the new `/api/findings/{id}/position` endpoint to compute the
  absolute offset under the cleared filter, fetches the page that
  contains the finding, and scrolls the table row into view. Filters
  the analyst had set are intentionally lost — the Jump is a "show
  me this finding now" action.

### Detection changes

- **Multi-period beacon scores rise on the timing axis.** See the
  `### Added` entry for the new `intervalMultimodalScore` path.
  A beacon with a 60s heartbeat plus a 600s tasking cycle that
  scored ts≈0.59 under raw Bowley+MAD now scores ts≈0.99 — moving
  the overall composite from below detection threshold into HIGH
  severity. Single-mode beacons are unaffected (the helper
  returns 0 and the caller falls back to the existing math).
  Re-baseline any min-score alerting if your environment has
  multi-period beacons that were previously being missed.

- **Beacon `ts_score` rises slightly when intervals 1→2 and 2→3
  are recovered.** The lazy-init replay fix above feeds two
  additional samples into the timing-regularity reservoir for
  every beacon pair. Magnitude is small — the strobe golden
  fixture's beacon finding shifts from `ts=0.75` to `ts=0.76`
  (+0.01) on 1000 connections; the final integer score is
  unchanged at 57. Low-connection beacons right at the
  10-connection threshold gain ~22% more samples on the timing
  axis and may see a larger shift. Direction is uniformly
  upward (more samples = better statistical confidence in
  regularity); no false-positive risk added.

- **Beacon (TCP and HTTP) scores rise on multi-sensor `/logs/`
  trees.** The cross-sensor smearing fix above un-suppresses
  beacons that were being penalised on the histogram + duration
  axes when more than one sensor's logs sat in `/logs/` at
  analyze time. Operators with single-sensor deployments see
  no change. Multi-sensor operators should expect beacons in
  each sensor's capture to score closer to what they would
  have scored if analysed alone — re-baseline any min-score
  alerting that was tuned to the artificially-deflated
  numbers. Golden fixtures (single-sensor by construction) are
  unchanged.

### Breaking

- **`/api/config` no longer carries the four removed beacon
  fields.** Responses drop them; PUTs that include them are
  silently ignored by Go's JSON decoder. No DB migration —
  config is a single JSON blob in the `settings` table; the
  next config save naturally drops the dead fields.

## [v0.7.0] — 2026-05-09

### Fixed

- **`Store.SetFindings` ID-collision bug.** The analyzer assigns
  per-run sequential IDs starting at 1, while the merge logic
  preserved historical findings (those whose fingerprint didn't
  match anything in the new run) with their original DB IDs. When
  the analyzer's fresh IDs (1, 2, 3…) overlapped with preserved
  historical IDs, `saveFindings` failed with `UNIQUE constraint
  failed: findings.id` and the analyze pass's findings were lost
  on rollback. Latent pre-v0.7.0 — most analyses regenerated
  nearly every fingerprint each run so collisions were rare. The
  TI Hit type split surfaced it: every legacy `Threat Intel Hit`
  finding is preserved as historical (its fingerprint doesn't
  match any new `TI Hit (IP/Domain/Hash)` finding), and the new TI
  findings stomp through the same low-ID range. Fix: `SetFindings`
  now carries stable IDs forward on fingerprint matches and
  assigns truly-new fingerprints IDs above the maximum historical
  ID — collision-free regardless of how many old findings get
  preserved.

### Added

- **Multi-sheet XLSX export.** New "XLSX (multi-sheet)" option on
  the **Export all** dropdown produces an `.xlsx` workbook with six
  sheets — `Findings` (open), `Acknowledged`, `Escalated`,
  `IOC Hits`, `Campaigns`, `Hosts` — that opens cleanly in Excel,
  Numbers, and LibreOffice. Driven server-side via
  `/api/export/xlsx`; the campaigns and hosts roll-ups are
  computed in Go (mirrors the JS UI logic) so the file is
  self-contained. CSV and JSON options unchanged. Adds the
  `github.com/xuri/excelize/v2` dependency (pure-Go, no CGO, MIT).

### Changed

- **Hosts CSV column order matches the UI.** `archer_hosts_*.csv`
  now leads with `risk_score`, then `host_ip`, `findings`,
  `severity`, `finding_types` — same order as the Hosts tab.
  Pre-v0.7.0 the CSV led with `host_ip`. The XLSX export's Hosts
  sheet uses the same order.

### Detection changes

- **`Threat Intel Hit` finding type split.** Pre-v0.7.0 every
  feed-driven match (FeodoTracker IP, URLhaus IP/domain, OTX,
  AbuseIPDB, MISP/OpenCTI IP/CIDR, MISP/OpenCTI domain) collapsed
  into a single `Threat Intel Hit` type, which made the Type
  filter dropdown useless for narrowing down "show me only domain
  hits" or "show me only the new file-hash matches." The type now
  splits three ways based on what was matched:
  `TI Hit (IP)` / `TI Hit (Domain)` / `TI Hit (Hash)`. Suspicious
  URL is unchanged. The IOC Hits tab continues to surface all of
  them together (notification bell, host-risk weighting, IOC tab
  inclusion all updated to recognize the three new types).
  Old findings with the legacy `Threat Intel Hit` type still
  classify correctly via a backwards-compat helper (`IsThreatIntelType`),
  so pre-v0.7.0 findings persisted in operator DBs continue to
  land in the right tab and trigger notifications.

  **Re-baseline note.** The fingerprint includes Type, so old
  `Threat Intel Hit` findings will NOT merge with newly-emitted
  `TI Hit (IP)/(Domain)/(Hash)` findings on the next Analyze —
  fresh entries appear alongside the old ones. Two upgrade paths:
  (a) accept the temporary duplication; old findings age out via
  archive prune, or the operator can manually clean them up; or
  (b) run **Discard findings & re-analyze** once after upgrade to
  start clean (loses analyst state on existing TI findings, but
  the new fingerprints are stable going forward). Phase 4 golden
  fixtures regenerated to match the new type strings.

- **File-hash matching against MISP / OpenCTI feeds.** Pre-v0.7.0,
  hash-typed feed indicators (md5 / sha1 / sha256) were persisted
  to `feed_indicators` correctly but `Store.EnabledFeedIndicators`
  silently dropped them because no analyzer-side field carried a
  hash candidate. The `Hashes` map on `feeds.SourcedIndicators` is
  now populated with lowercased hex strings, and a new analyzer
  step `checkFileHashes` (Phase 3, alongside `checkSuspiciousURLs`
  and `checkTI`) scans `files.log`'s md5 / sha1 / sha256 columns
  against the bucket. Matches emit a `Threat Intel Hit` (HIGH /
  score 90) attributed to the matching feed, with the detail line
  carrying algorithm + hash hex + filename + MIME + tags.
  Algorithm-agnostic on the analyzer side: a single Hashes map per
  feed combines all three algorithms and each row's three hash
  columns are tested against it. The `(downloader, hashvalue)`
  fingerprint dedups so a file with all three algorithms in the
  feed only fires once. Re-baseline expected: hash-rich feeds
  (MISP master, ThreatFox) start producing findings on file
  downloads that were previously invisible.

### Changed

- **Cached `EnabledFeedIndicators` on the store.** The analyzer-side
  feed-bucket snapshot used to rebuild on every analyze tick — a
  `ListFeeds` + per-feed `ListFeedIndicators` + CIDR-parse pass that
  ran whether or not feed state had actually changed. The result is
  now memoized on `Store`; feed CRUD (`CreateFeed`, `UpdateFeed`,
  `DeleteFeed`) and indicator writes (`UpsertFeedIndicators`,
  `RemoveStaleIndicators`) drop the cache so the next read rebuilds.
  Invisible from the outside — every analyze pass sees the same
  bucket shape it always did, just without the redundant
  reconstruction.

### Added

- **Interactive zoom on the beacon chart Timeline view.** Click-drag
  on the canvas to brush-select a time range; the view re-fits to
  that slice without re-fetching anything (the data was already in
  `f.ts_data`). Right-click resets to auto-fit, or use the
  Reset zoom button that appears next to the view tabs once a zoom
  is active. Zoom is dropped automatically when switching to the
  Interval histogram or Bytes view since those have their own X
  mappings; opening the chart for a new finding starts at auto-fit.

- **MISP adapter pagination + truncation visibility.** The MISP
  fetcher now walks `/attributes/restSearch`'s `page` + `limit`
  parameters in batches of 10000 up to 100 pages (1M attributes),
  instead of issuing a single 100k-attribute request and silently
  truncating large feeds. When the adapter hits the cap with the
  upstream still indicating more data, the feed row's new
  `last_fetch_truncated` field flips to `true` and the Feeds
  dialog surfaces a "⚠ truncated" badge next to the indicator
  count. OpenCTI already paginated correctly via cursors;
  truncation visibility is wired up there too. Schema change:
  `feeds.last_fetch_truncated` column added via migration
  `0005_feeds_last_fetch_truncated.sql`.

### Removed

- **Per-feed `refresh_cadence_minutes` field.** Dead since v0.6.0,
  when feed refresh moved to the watch full-pass cadence. The
  `feeds.refresh_cadence_minutes` column is dropped via migration
  `0004_drop_refresh_cadence_minutes.sql` and the field is removed
  from the wire shapes (`/api/feeds` request/response), the Feeds
  dialog (column + edit input), the `feeds.Feed` Go struct, and
  the per-feed worker code (which now ticks on a fixed 60-minute
  cadence if anyone re-enables `startFeedWorker`).

### Breaking

- **`/api/feeds` request shape.** External scripts that POST or PUT
  feeds with a `refresh_cadence_minutes` field will get a JSON
  decode error. Drop the field from the request body. The default
  validation that required `refresh_cadence_minutes ≥ 1` is gone.
- **`/api/feeds` response shape.** External scripts that read
  `refresh_cadence_minutes` from the response will get an
  unmarshal-into-int-zero or KeyError. The field is no longer
  emitted.
- **DB schema.** The `feeds.refresh_cadence_minutes` column is
  dropped. Existing values are lost. Forward-only — restoring
  requires a new migration that adds the column back.

### Added

- **`/api/logs/tree` endpoint.** Returns a sensor → date roll-up of
  what's currently under `/logs/`, with file counts, total bytes,
  and newest mtime. Drives the new logs preview pane.
- **Logs preview pane in the sidebar.** A read-only tree showing
  the sensor → date layout under `/logs/`; clicking a sensor
  expands its dates with file counts and sizes. Refreshes
  automatically when an analyze pass finishes (so newly-arrived
  logs become visible without a page reload). The `Analyze logs`
  button is disabled when the tree is empty — an unambiguous
  signal that there's nothing to act on.

### Changed

- **`/api/analyze` is now the sole analyze entry point and always
  scans `/logs/`.** Pre-v0.7.0 the dashboard `Analyze` button
  required that `Import` be clicked first (which actually called
  `/api/logs/scan` to register `/logs/` paths into an uploaded-files
  list); calling `/api/analyze` with nothing imported returned
  `{"error":"no files to analyze"}`. The endpoint now scans
  `/logs/` directly and runs a full pass with fingerprint-merge
  on every invocation. The `files` field in the request body is
  no longer honored — the only input is what's on disk under
  `/logs/`. The `Analyze logs` button is the sole UI trigger.
- **`/api/analyze/reset` always scans `/logs/`.** Removes the
  uploaded-files preference path. Same input source as
  `/api/analyze`, with the difference being the findings wipe
  before re-analysis.

### Removed

- **`/api/upload` endpoint.** Was never wired to the UI (the
  handler existed in `upload.go` but no route registration
  pointed at it) and had structural fit problems for the use
  case it would serve — multipart total cap of 512 MB,
  no streaming or resume, no progress feedback, files saved
  to `/tmp/archer_uploads/` in the container layer (lost on
  rebuild), and a separate code path from `/logs/`.
  Operators with ad-hoc bundles drop them into `/logs/<name>/<date>/`
  on the host (mount, `docker cp`, or SCP via the Quiver SSH
  dropbox), where the unified pipeline picks them up.
- **`/api/logs/scan` endpoint.** Both GET (read-only logs-dir
  hint) and POST (register `/logs/` paths into uploaded-files
  list) are gone. The new `/api/logs/tree` covers the read role
  with structured output; the POST role no longer has a purpose
  since `/api/analyze` scans `/logs/` directly.
- **`/api/files` and `/api/files/clear` endpoints.** The
  uploaded-files registry no longer exists, so reading and
  clearing it are meaningless.
- **Import / Clear buttons + uploaded-bundle UI.** The sidebar's
  Zeek Logs section is replaced with a single Logs section
  containing the preview tree and an `Analyze logs` button.
- **`Store.GetUploadedFiles` / `SetUploadedFiles` /
  `AppendUploadedFile` and the in-memory `uploadedFiles`
  field.** Internal Go API, but call sites in `watch.go` are
  also dropped (the watch loop's persisted-paths copy was
  decorative — the analyzer always took its file list from the
  same scan). The DB has no table for this; nothing to migrate.

### Breaking

- **`/api/analyze` request shape.** External scripts that POST a
  `files` array will see those files ignored — `/logs/` is
  scanned regardless. Empty `/logs/` now returns
  `{"error":"no logs found in /logs"}`.
- **Removed endpoints.** `/api/upload`, `/api/logs/scan`,
  `/api/files`, `/api/files/clear` return 404. Any scripts
  depending on these need to either drop their bundle into
  `/logs/<name>/<date>/` on the host or read `/api/logs/tree`
  for the inventory view.

Working theme: usability and predictable cost. v0.5.0 was feature-complete
on Phase 7 but the dashboard hit a wall on real-world data — list responses
ballooned to ~170 MB on six-figure finding counts, and the auto-cadence
MISP worker was firing 10-minute fetches on the hour that pegged CPU
during analyst sessions. This bundle fixes both, plus a long pass of UI
polish, a major beacon-chart redesign, and per-tab pagination across the
whole dashboard.

### Added
- **Server-side pagination on `/api/findings`.** New `limit` and `offset`
  query params (default 1000, max 50000). Responses set
  `X-Total-Count` and `X-Has-More` so the UI can drive paginated
  navigation, and `Access-Control-Expose-Headers` is set so the headers
  reach JS in CORS contexts.
- **`GET /api/findings/counts`** returning `{open, ack, esc, ioc, total}`
  honoring the active filter set (minus `status` / `ioc_only`). Powers
  the info-line counters without forcing the UI to scan the full
  finding set every render.
- **`GET /api/findings/facets`** returning `{types, sensors}` — distinct
  values across the entire dataset (subject to non-dropdown filters).
  The Type and Sensor filter dropdowns now reflect every available
  value across all data, not just what's on the currently-rendered
  page. Type and sensor are stripped from the facets query so picking
  one doesn't collapse the dropdown to that single option.
- **Per-tab pagination on every tab** with first / previous / next / last
  navigation buttons (« ‹ › »). Findings, Acknowledged, Escalated, and
  IOC paginate server-side via `/api/findings`. Campaigns and Hosts
  paginate client-side over the cached aggregate set — same UX,
  different mechanics. Each tab maintains its own offset; switching
  tabs is an O(1) cache hit. Footer reads "Showing 101–200 of 5,000 ·
  Page 2 of 50" and disables boundary buttons.
- **Sortable Campaigns / Hosts columns.** Click any of Score /
  Destination / Port / Hosts on Campaigns, or Host IP / Risk Score /
  Findings / Severity on Hosts, to sort. Clicking the same column
  toggles ascending / descending. Sort indicator (↑/↓) appears next to
  the active column header, mirroring the existing Findings-table
  convention. Severity sorts by analyst-visible order
  (CRITICAL < HIGH < MEDIUM < LOW < INFO) so descending lands worst-
  first.
- **Beacon Chart redesign — three views, one dialog.** The fixed
  time-window presets (5m / 30m / 1h / …) are gone; every view auto-
  fits the X axis to the full data span. View-mode tabs at the top
  switch between:
    - **Timeline** (default) — every connection event as a vertical
      tick on a continuous time axis from first to last observation.
      Density-modulated alpha so dense regions stay visible while
      sparse ticks aren't washed out. The eye-test for "is this
      regular?".
    - **Interval histogram** — distribution of inter-arrival gaps
      between consecutive connections, top 1% trimmed so a single
      outlier gap doesn't squash the histogram. A dashed accent line
      marks the mean-interval position so you can see whether the
      peak lines up with the analyzer's reported mean. Tall single
      peak = beacon's heartbeat.
    - **Bytes** — the legacy bytes-sent-per-bucket chart, kept for
      verifying whether a beacon also exfils alongside its heartbeat.
  Plus a stats strip above the canvas: connections, mean interval,
  jitter (CV), span. And a per-view PNG / JPEG export dropdown that
  snaps the active canvas with a filename including the src→dst pair
  and view name (mirrors the cytoscape graph export pattern).
- **HTTP Beaconing findings now carry `TSData`.** The HTTP beacon
  detector (`internal/analysis/http_analysis.go`) was tracking inter-
  arrival intervals and byte values for the score, but didn't collect
  the per-event `[ts, origBytes, respBytes]` triples the chart needs.
  The state struct now reservoir-samples those triples (capped at
  `beaconTsCap = 200`, same cap conn-level beacons use), and they're
  attached to the emitted finding. Existing HTTP Beaconing findings
  show empty timeline data until they're re-detected by the next
  analysis run; the merge then overwrites the empty `TSData` field.
- **Time-range preset dropdown** in the filter bar (All time / 1d / 7d /
  1mo / 3mo / 6mo). Selecting a preset re-queries immediately; the
  manual From / To inputs in the advanced filter panel are gone — the
  preset is the only time-range control and defaults to "Last 1
  month" on first load.
- **WAL journaling** on the SQLite store (`PRAGMA journal_mode = WAL` in
  `RunMigrations`). Concurrent reader/writer behavior matches what the
  dashboard's read traffic actually does — reads no longer block on the
  long writes from analysis runs and feed indicator upserts.
- **Watch full-pass pre-flight feed refresh.** The first watch tick of
  each UTC day (and every tick when `WatchAlwaysFull` is on) now calls
  `refreshFeedsBeforeFullPass` synchronously before launching analysis.
  Every enabled MISP / OpenCTI feed is fetched in parallel under a
  two-minute global cap; failures log but do not block the analysis. A
  status SSE event (`Watch: refreshing N feed(s) before full pass.`)
  surfaces the pre-flight on the dashboard.
- **Watch incremental ticks now match against cached MISP / OpenCTI
  indicators.** `launchIncrementalAnalysis` sets `FeedProvider` so
  `AnalyzeTIOnly` consults whichever indicators the most recent full
  pass loaded. No fetch — incremental ticks remain network-free —
  closes the "wait until tomorrow" gap on fresh hits from configured
  feeds. Adds a few seconds per tick to rebuild the indicator buckets
  from SQLite; the cost is bounded by total enabled-feed indicator
  count, not log volume.

### Changed
- **Page layout reshuffle.** Sidebar runs full-height from the top of
  the page to the bottom — no jog where the topbar used to interrupt
  it. The Archer crosshairs + wordmark moved into the sidebar at the
  top, with "Silent Hunter" centered underneath as a small uppercase
  tagline. The topbar in the right column shrunk to 48px (action
  buttons only: bell, Sensors, Feeds, Users, Settings, user-badge).
- **Right-click menu auto-positions.** The static 220×200 fallback
  margin under-counted the menu after font bumps; clicks near the
  right or bottom edge cut it off. JS now measures the rendered menu
  with `getBoundingClientRect()` and clamps into the viewport with an
  8px margin. Click-anchor arrow at one of the menu's four corners
  (↖↗↙↘) points back at the click — useful when the menu had to flip
  away from the cursor to fit.
- **Findings list responses are now projection-shaped.** New internal
  `listFinding` type drops `TSData`, `Intervals`, and `Notes` from
  every `/api/findings` row — those fields balloon to hundreds of KB
  per row on beacon-rich datasets and are only consulted on detail
  pages anyway. The detail endpoint (`/api/findings/{id}`) still
  returns the full `model.Finding`, and a row click now upgrades
  `_selectedFinding` via a follow-up fetch so the chart, intervals,
  and notes render correctly without bloating the list. Beacon-Chart
  visibility on the right-click menu and detail-pane button now gates
  on finding type (`Beaconing` / `HTTP Beaconing`) instead of
  ts_data presence — type is in the projection, ts_data is not.
- **Right-click menu on Campaigns / Hosts** hides Acknowledge,
  Escalate, and Suppress (and the separator above them). Those
  actions operate on a single finding's status and don't make sense
  on a synthesised aggregate row. They still appear on Findings,
  Acknowledged, Escalated, and IOC tabs.
- **Feed indicator upserts now batch in 1000-row chunks.** Each batch is
  its own transaction (`upsertFeedIndicatorBatch`) so a 100k-row MISP
  refresh no longer holds the writer for the whole upsert duration.
- **Per-feed `RefreshCadenceMinutes`** is now effectively unused. The
  field stays on the row for forward compatibility (and the validator
  still requires `≥ 1`), but no scheduler reads it. Refreshes are
  driven by the watch full-pass cadence — see `docs/FEEDS.md`.
- **Settings → Watch Mode** "Always run full scan on every watch tick"
  now also forces a feed refresh on every tick (because every tick is
  a full pass under the override). Previously this checkbox only
  affected the analyzer phase selection.
- **UI text and chrome polish.** Body font bumped 13 → 17 px; every
  explicit `font-size` in `archer.css` bumped by 2 px. Filter
  dropdowns and dialog inputs got thicker (taller padding, larger
  text) without growing wider. Sidebar inputs (`.sidebar-input`)
  bumped to match (`padding: 9px 10px`, `font-size: 16px`). Findings
  table cells normalize to the body font size — the previous explicit
  `font-size: 11px` on src-ip / dst-ip / sensor / detail cells is
  removed. The Findings table's first column (icon) widened 38 → 56
  px so the icon no longer clips next to "icon…". The pagination
  control moved inline with the tab bar instead of its own row,
  right-justified. Sortable column widths bumped on Campaigns and
  Hosts so the sort-indicator arrow doesn't truncate the header text.
  Sensors-dialog Pending Tokens "Override name" 130 → 180 px;
  Unauthorized Attempts "Count" 80 → 110 px so longer values render
  without ellipsis.

### Removed
- **`POST /api/feeds/refresh-all`** and the dashboard sidebar "Refresh
  feeds" button that called it. Watch-tick auto-refresh covers the
  steady-state case; the per-feed Refresh button (still in the Feeds
  dialog) covers admin one-shot validation.
- **From / To time-range inputs** in the advanced filter panel — the
  filter-bar preset dropdown is the only time-range control now.
- **Auto-cadence MISP / OpenCTI fetcher worker.** `s.startFeedWorker()`
  in `server.New` was already commented out behind a feature comment;
  this release commits to the watch-driven model and updates the
  surrounding documentation. Re-enabling is still a one-line change
  if a deployment wants per-feed cadence back.
- **Beacon-chart preset time-window buttons** (5m / 30m / 1h / 6h / 24h
  / 7d / 1mo / 1y). Replaced by the auto-fit X axis and the three
  view-mode tabs described above.

### Breaking
- `POST /api/feeds/refresh-all` removed — no replacement. Force a
  refresh by triggering a full-pass watch tick (`WatchAlwaysFull`
  toggle, or *Discard findings & re-analyze* which runs as a full
  pass), or use the per-feed `/api/feeds/{id}/refresh` endpoint
  for one-shot validation. Endpoint existed only in v0.5.0 and was
  admin-gated, so practical blast radius is operator scripts only.

### Detection changes
None. Detection semantics are unchanged from v0.5.0 — same score
formulas, same thresholds, same finding types. Two non-semantic
data-shape changes:
- HTTP Beaconing findings now carry `TSData` (previously empty).
  Affects `/api/findings/{id}` and `/api/export/json`; the value is
  reservoir-sampled chart data, not a detection signal.
- Incremental ticks now *see* MISP / OpenCTI indicators that they
  didn't see in v0.5.0, but the matching logic is the same
  `checkTI` / `checkSuspiciousURLs` code path; an indicator that
  produces a Threat Intel Hit in a full pass will produce the same
  Threat Intel Hit in an incremental pass.

---

## [v0.5.0] — 2026-05-08

This release closes Phase 6 (API contract reference + deprecation
policy) and Phase 7 (MISP / OpenCTI threat-intel feed integration).
The full feed pipeline is operator-usable end to end: configure
feeds in the new admin UI, the worker fetches indicators on cadence,
and the analyzer's TI matching paths now consult those feed
indicators alongside the built-in URLhaus / Feodo lists. Findings
that match a feed indicator carry per-feed provenance
(`SourceFile: feed:<name>`) plus any upstream tags inline. Two
phase-7 follow-ups also land here: a per-feed TLS-verify bypass for
self-signed internal MISP / OpenCTI deployments, and the analyzer-
side wiring that consumes `feed_indicators` to actually emit Threat
Intel Hit / Suspicious URL findings from feed matches.

### Added
- **Analyzer-side feed matching.** The TI hot path now consults
  enabled MISP / OpenCTI feeds during phase-0 prefetch and tests
  candidate IPs / CIDRs / domains against them in `checkTI` and
  `checkSuspiciousURLs`. Matches emit `Threat Intel Hit` (HIGH /
  score 90) or `Suspicious URL` (HIGH / score 90) findings tagged
  with `feed:<name>` plus any upstream tags inline in Detail. New
  `analysis.FeedProvider` interface (aliased to `feeds.Provider`)
  is satisfied by the Store; analyzer construction sites in
  `handlers_api.go` and `watch.go` wire it via
  `Analyzer.SetFeedProvider`. Hash indicators are stored but not
  yet matched — no analyzer field today carries a hash candidate;
  closes when file-finding analyzers grow that field.
- **Per-feed TLS-verify bypass.** New `tls_skip_verify` boolean on
  the `feeds` table (migration `0003_feeds_tls_skip_verify.sql`)
  with a checkbox in the feed-edit dialog and a warning sub-text
  ("only enable for trusted internal feeds"). Threaded through to
  `MISPClient` / `OpenCTIClient` constructors as a Transport
  override. Default off — operators opt in deliberately per feed.
  Closes the common deployment friction where a lab MISP runs with
  a self-signed cert that the Archer container's CA bundle doesn't
  trust.
- **Feed-aggregator schema (Phase 7 slice 1).** New `feeds` and
  `feed_indicators` tables land via `0002_feeds.sql` migration.
  Schema-only for now — the fetcher worker, MISP/OpenCTI source-type
  adapters, and admin UI ship in subsequent slices. The `feeds` table
  records configured feed instances (source type, URL, API key,
  refresh cadence, aging window, status); `feed_indicators` records
  the per-indicator stream the fetcher will populate.
- **Feeds admin UI (Phase 7 slice 5b).** New "Feeds" topbar button
  (admin + analyst, like Sensors) opens a management dialog listing
  every configured feed with name, source type, status pill,
  indicator count, last-refresh timestamp, cadence, and aging
  window. Admins get add / edit / delete / refresh row controls;
  analysts get the read-only view. The edit dialog handles both
  create and update; on edit, the API-key field shows a
  "leave blank to keep existing" hint and submitting empty
  preserves the stored key (matches the slice 5a server behavior).
  Manual-refresh button shows the live add/refresh counts inline
  on the row for ~2.5s after a fetch lands. With this slice, the
  full Phase 7 path is operator-usable end to end without SQL —
  configure a feed in the UI, the worker fetches on cadence,
  matching findings get tagged with `ioc_source: "Feed: <name>"`.
- **Feeds admin API endpoints (Phase 7 slice 5a).** `/api/feeds`
  (GET list, POST create) and `/api/feeds/{id}` (PUT update, DELETE
  remove) plus `/api/feeds/{id}/refresh` (POST manual fetch).
  Reads are open to any authenticated user; mutations and
  manual-refresh require admin. The API key field is write-only —
  `POST` and `PUT` accept it in the request body, but `GET`
  responses redact it (replaced with a `has_api_key: bool` flag) so
  a stolen session cookie can't scrape feed credentials. `PUT` with
  an empty `api_key` keeps the existing key (avoids the foot-gun
  where re-saving a config without re-typing the secret blanks it
  out). The manual-refresh endpoint is synchronous with a 60s
  upstream cap and reports added/refreshed indicator counts in the
  response so the admin sees what just happened. Slice 5b will land
  the corresponding admin UI; until then, configuring a feed still
  needs `curl` instead of SQL.
- **Matcher composition + per-finding provenance (Phase 7 slice 4).**
  Feed indicators are now joined into the IOC matching surface used
  by `/api/findings`. The Store exposes `IOCSources() []SourcedMatcher`
  returning the operator IOC matcher first, then one matcher per
  enabled feed in feed-id order. The findings filter walks the
  sourced-matcher slice and short-circuits on the first hit, tagging
  the finding with the matching source label
  ("Operator IOC list" or "Feed: <feed name>").
- **`Finding.IOCSource` field on the API response.** New
  `ioc_source` JSON field surfaces which list flagged each finding —
  what the analyst UI's status icon and detail panel will key off.
  Computed at read time from the current Store snapshot, not
  persisted (feed indicators age out and can switch source on the
  next refresh; the persisted thing is `ioc_match: bool`). Threat
  Intel Hit / Suspicious URL findings (intrinsic IOCs per the
  analyzer) get `"Threat Intel Hit"` as the source label. This is
  an additive HTTP API change — `omitempty` keeps existing clients
  unaffected.
- **Per-feed matcher cache.** Each enabled feed gets a compiled
  matcher cached on first read; `UpsertFeedIndicators` /
  `RemoveStaleIndicators` / `DeleteFeed` invalidate the cache for
  the affected feed so the next IOC-match call rebuilds with current
  state. With this in place the MISP/OpenCTI integration is fully
  end-to-end: configure a feed (currently via SQL until slice 5's
  admin UI lands), the worker fetches and writes indicators, those
  indicators light up matching findings on the next `/api/findings`
  call.
- **OpenCTI source-type adapter (Phase 7 slice 3).** New
  `internal/feeds/opencti.go` mirrors the MISP adapter but speaks
  OpenCTI's GraphQL `/graphql` endpoint with bearer authentication.
  Walks cursor-based pagination (`first` / `after`), capped at 100
  pages × 1000-row default page size so a misconfigured huge tenant
  can't OOM the worker. Reads the canonical
  `x_opencti_main_observable_type` field plus the STIX pattern from
  each indicator node; the type drives bucket selection
  (`IPv4-Addr`/`IPv6-Addr` → `IndicatorIP` or `IndicatorCIDR`,
  `Domain-Name`/`Hostname` → `IndicatorDomain`, `StixFile` →
  `IndicatorHash`), with `Url` and unknown types deliberately
  skipped. STIX-pattern value extraction handles both unquoted and
  quoted property paths (e.g. `file:hashes.'SHA-256' = '<hash>'`)
  by scoping the regex to the right-hand side of `=`. Server's
  AdapterFor switch now constructs an `OpenCTIClient` for
  `source_type = 'opencti'` feed rows. Same caveat as slice 2: no
  admin UI yet (slice 5), so feeds need manual SQL configuration to
  exercise the path; matcher consumption still pending slice 4.
- **MISP source-type adapter + fetcher worker (Phase 7 slice 2).**
  New `internal/feeds` package introduces the source-agnostic
  `Adapter` interface, the normalized `Indicator` type, and a
  `Worker` that schedules per-feed refreshes on each feed's
  configured cadence. The MISP adapter (`misp.go`) hits
  `/attributes/restSearch` with `Authorization: <api-key>`, filters
  to network-indicator attribute types
  (`ip-src`/`ip-dst`/`domain`/`hostname`/`md5`/`sha1`/`sha256`),
  and normalizes into `IndicatorIP`/`IndicatorCIDR`/`IndicatorDomain`/`IndicatorHash`
  with tag round-trip. URLs are skipped at this slice (need
  host/path parser logic to feed into per-finding correlation;
  punted to a follow-up). Worker reconciles its goroutine set
  against the `feeds` table every 30s so admin-UI changes
  propagate without a server restart, fires the first tick
  immediately on start to populate freshly-added feeds, and
  records last-error / status in the feed row on transient
  upstream failures. New Store CRUD methods land for the `feeds`
  and `feed_indicators` tables. SQLite foreign-key enforcement is
  now enabled at migration time so the `ON DELETE CASCADE` on
  `feed_indicators` actually fires when a feed is deleted.
  Without an admin UI yet (slice 5), no feeds get configured by
  default and the worker is a no-op for existing installs.
- **Cached list matchers in the Store.** A new `internal/match`
  package holds the compiled-list matcher type previously inlined
  in `internal/server/findings_filter.go`. The Store builds the
  allowlist and IOC matchers once at startup and rebuilds them
  inside `SetAllowlist` / `SetIOCList` — what was previously
  rebuilt per `/api/findings` request, costing 100-500ms on a hot
  list. Matcher values are immutable post-compile and shared across
  goroutines via pointer copy under the store's read lock.
- **API contract reference (Phase 6).** New `docs/API.md` enumerates
  every `/api/*` endpoint, plus `/login`, `/logout`, `/register`,
  `/events`, and the three sensor-facing `/quiver/*` endpoints.
  Documents the Finding model shape end-to-end, the `/api/findings`
  query-parameter set (search/type/severity/min_score/delta/IPs/
  ports/sensor/from-to/status/ioc_only/sort/dir), the Quiver
  enrollment+checkin protocol and the structured
  protocol-version-mismatch error, the SSE event catalog, and the
  conventions for auth, roles, error format, and time formats.
  Also documents the four breaking-change surfaces by name and lays
  out a one-minor-version-cycle deprecation policy for field/endpoint
  removals (RFC 7234 `Warning: 299 -` header on the deprecated
  surface for one cycle, then removed under `### Breaking`). README
  Operations section links to the new doc.

### Detection changes
- **Threat Intel Hit and Suspicious URL findings now fire from
  MISP / OpenCTI feed matches.** Before this release, those finding
  types only fired from the built-in URLhaus / FeodoTracker /
  OTX / AbuseIPDB sources; feed indicators were stored but never
  produced findings. Behavior change: deployments with at least one
  enabled feed will see additional findings on next analysis whose
  dst-IP / DNS-query / HTTP-host overlaps with the feed's
  indicators. Severity HIGH / score 90 (lower than URLhaus's
  CRITICAL / 96-97 — these are unverified relative to URLhaus's
  curated malware-distribution focus). Re-baseline if your hunt
  workflow filters on IOC source. Deployments with no feeds
  configured see no behavior change.

### Breaking
- **DB schema: `feeds` and `feed_indicators` tables (migration
  `0002_feeds.sql`).** Lands automatically on first start of
  v0.5.0. New install: created from scratch. Existing v0.4.0
  install: forward-only migration applied at startup. No data
  backfill — feeds are operator-configured post-upgrade. Rollback
  to v0.4.0 requires restoring `/data` from backup; there's no
  down-migration tooling.
- **DB schema: `tls_skip_verify` column on `feeds` table (migration
  `0003_feeds_tls_skip_verify.sql`).** Bundled into the same v0.5.0
  upgrade path as 0002 — single restart applies both. Default value
  0 (verification on); operators tick the per-feed checkbox to opt
  in.
- **HTTP API: `Finding.IOCSource` field added to `/api/findings`
  responses.** Additive — existing clients that ignore unknown
  fields are unaffected. Clients that strictly validate response
  schemas will need to allow the new field.

---

## [v0.4.0] — 2026-05-08

The maturation roadmap's Phase 4 (detection-semantics tests) and
Phase 5 (CI) both ship in this release, plus a long-overdue
operator-timezone fix to the off-hours detector. Every offline
detector path in the analyzer is now locked into a checked-in
golden fixture and validated on every push and PR by the new CI
workflow. The single breaking change is a config-key rename
(`watch_timezone` → `timezone`); existing installs need to re-set
their operator timezone once via the Watch sidebar.

### Added
- **CI workflow.** A single GitHub Actions workflow at
  `.github/workflows/ci.yml` runs on every push to `main` and every
  pull request targeting `main`. Three jobs in parallel: `lint`
  (gofmt + go vet), `test` (go test -race), and `build` (CGO_ENABLED=0
  static binary plus a Docker build smoke check that mirrors the
  multi-stage `Dockerfile` flags). The build job depends on lint+test
  passing first so a broken test doesn't waste a Docker image build.
  Each push surfaces as ✅ or ❌ on the commit; the README has a CI
  badge linking to the workflow runs page.
- Phase 5 of the maturation roadmap is complete; future PRs (including
  Phase 4's detection-semantics tests) inherit the gate automatically.
- **Detection-semantics test scaffolding (Phase 4.1).** First slice of
  the golden-file framework. `internal/analysis/stats_test.go` covers
  the math helpers (`fmedian`, `fmean`, `bowleyScore`, `madScore`,
  `statisticalScore`, `computeHistogram`, `cvScore`, `bimodalScore`,
  `histScoreRegularity`, `durationScore`, `shannonEntropy`) with table
  tests and edge cases. `internal/analysis/golden_test.go` runs the
  full analyzer over a synthetic Zeek NDJSON corpus under
  `internal/analysis/testdata/zeek/` and diffs the resulting findings
  against a checked-in `expected_findings.json`. Running with `-update`
  regenerates the golden file when a CHANGELOG-acknowledged detection
  change lands. Findings are projected to a stable subset (no IDs, no
  reservoir-sampled `TSData`, no analyst mutations) and sorted before
  diffing so the result is independent of goroutine scheduling.
- **`prefetchFeeds` test-isolation guard.** When a feed cache is
  pre-populated (non-nil), the corresponding live HTTP fetch is
  skipped. Tests inject empty (non-nil) maps to neutralize the feeds
  without touching the public internet.
- **Conn-detector golden fixtures (Phase 4.2).** The golden-file test
  is now table-driven over scenario subdirectories under
  `internal/analysis/testdata/zeek/`. Six new scenarios cover every
  detector in `analyzeConn`: `strobe/` (1000-conn fan-out, also
  exercises beacon scoring under irregular timing), `long_connection/`
  (2-hour duration), `exfil/` (7.5 MB outbound, 30× ratio), `lateral/`
  (internal SMB), `c2_port/` (Metasploit default port 4444), and
  `off_hours/` (1.5 MB at 02:00 UTC). The original `beacon_url/`
  scenario was moved into its own subdirectory alongside the new
  ones. Each scenario has its own `README.md` documenting what's
  exercised and which findings it produces.
- **DNS-detector golden fixtures (Phase 4.3).** Five new scenarios
  cover every detector in `analyzeDNS`: `dns_doh_bypass/` (DNS to
  8.8.8.8:443), `dns_suspicious_tld/` (`evil.tk`),
  `dns_tunneling/` (qtype=TXT trip), `dns_nxdomain_flood/` (250
  NXDOMAINs of one query so subdomain diversity stays under
  threshold), and `dns_subdomain_diversity/` (50 unique subdomains
  under one apex). Each scenario fires exactly the targeted detector
  with no contamination.
- **HTTP-detector golden fixtures (Phase 4.4).** Six new scenarios
  cover every detector in `analyzeHTTP`: `http_suspicious_ua/` (curl
  UA), `http_cobalt_strike_uri/` (URI `/xyzaa` whose byte-sum modulo
  256 equals 92, the x86 stager checksum), `http_c2_uri_pattern/`
  (`/submit.php` regex match), `http_domain_fronting/` (paired
  `ssl.log` with SNI ≠ HTTP Host), `http_suspicious_file/`
  (`/payload.exe`), and `http_beacon/` (10 perfectly-regular
  requests).
- **SSL/TLS and X.509 golden fixtures (Phase 4.5).** Eight new
  scenarios. SSL: `ssl_malicious_ja3/` (Cobalt Strike beacon JA3),
  `ssl_weak_tls/` (TLSv10), `ssl_no_sni/` (established TLS without
  SNI on port 443), and `ssl_no_sni_c2_port/` (same but on port
  4444). X.509: `x509_self_signed/` (subject == issuer),
  `x509_default_subject/` (`openssl` substring), `x509_short_validity/`
  (8-hour validity window), and `x509_long_validity/` (26-year
  window). Each X.509 scenario locks in a distinct Detail-string
  indicator so a refactor that drops or reorders one of the
  cert-anomaly checks fails the test loudly.
- **Files / Weird / Notice golden fixtures (Phase 4.6).** Six new
  scenarios for the Zeek-passthrough analyzers.
  `files_suspicious_mime/` (MIME `application/x-dosexec`),
  `files_suspicious_ext/` (filename `loader.ps1`),
  `weird_protocol_anomaly/` (low-interest weird, default 22 / LOW),
  `weird_high_interest/` (`bad_HTTP_request` from the
  high-interest map, 65 / MEDIUM), `notice_zeek/`
  (`SSH::Login_From_New_Country`, default 68 / HIGH), and
  `notice_critical/` (note type containing `scan` keyword, 92 /
  CRITICAL).
- **TI-feed golden fixtures + per-scenario feeds (Phase 4.7).** The
  golden runner now accepts an optional `feeds.json` per scenario
  (schema: `feodo_ips`, `urlhaus_ips`, `urlhaus_hosts`). Two new
  scenarios use it: `ti_feodo_ip/` (FeodoTracker IP match,
  CRITICAL/99) and `ti_urlhaus_ip/` (URLhaus IP match,
  CRITICAL/97). The URLhaus *host* match path was already covered by
  `beacon_url/` via the default injection; these add the IP-match
  variants. With these in place, every detector that fires from
  `analyzeConn`, `analyzeDNS`, `analyzeHTTP`, `analyzeSSL`,
  `analyzeX509`, `analyzeFiles`, `analyzeWeird`, `analyzeNotice`,
  `checkSuspiciousURLs`, and `checkTI`'s offline (non-API) paths is
  now locked into a golden fixture.

### Changed
- One-time codebase reformat with `gofmt -w` so the new CI lint job
  passes from day one. Mechanical whitespace-only diff across 18 Go
  files; no behavior change. Aligned `:=` declaration blocks in a
  handful of files (`cmd/archer/main.go`, etc.) collapsed to standard
  single-space form. Future drift is caught by the CI gofmt check.
- README "Version: v0.1.0" stale literal at the top replaced with the
  CI badge plus a generic "Pre-1.0 — see CHANGELOG.md for the current
  release" line. The literal version was already drifting (we shipped
  v0.2.0 and v0.3.0 without updating it); the analyst-UI status pill
  and `/api/version` endpoint are the live source of truth.

### Detection changes
- **Host Risk Score `Detail` field is now sorted alphabetically.** The
  detection-types list rendered into the finding's Detail string was
  iterated from a Go map, which produced non-deterministic ordering
  across runs. Same set, same composite score — only the rendered
  ordering changes. Existing analyst notes referencing the old order
  are unaffected (the Detail field is fresh on each analysis pass and
  not part of the fingerprint).
- **Off-Hours Transfer is now timezone-aware.** The off-hours window
  (`OffHoursStart`/`OffHoursEnd` config fields) is interpreted in the
  operator's configured `Timezone` instead of UTC. A team in
  `America/New_York` setting Timezone to that name will now see
  off-hours fire for activity between 22:00 and 06:00 EST/EDT — what
  an analyst expects when they say "off-hours" — instead of the
  literal UTC window. With the default empty Timezone (= UTC) the
  behavior is unchanged. Bad/unparseable IANA names fall back to UTC
  defensively. The finding's Detail string now also surfaces the
  resolved timezone abbreviation (e.g. "02:xx EST"), where it
  previously hardcoded "UTC". Re-baseline hunts that depend on
  off-hours hits if you change Timezone.

### Breaking
- **Config field renamed: `WatchTimezone` → `Timezone`.** This is the
  same operator-timezone setting, now shared by the watch scheduler
  and the off-hours detector. The HTTP API for `/api/watch` was
  already using `timezone` as the JSON key (so no client/UI change),
  but the underlying stored config used `watch_timezone`. On first
  startup after upgrading, any existing operator timezone setting
  will read as empty (UTC default) — re-set the timezone via the
  Watch sidebar and it'll persist under the new key.

---

## [v0.3.0] — 2026-05-08

DB schema changes are now first-class numbered migrations instead of
inline `CREATE`/`ALTER` calls, so future column additions can't strand
existing installs mid-mission. Operator-facing improvements to the
allowlist / IOC list dialogs (comments, stable order) and a handful of
analyst-loop bug fixes round out the release. Existing installs upgrade
in place — the migration runner detects pre-Phase-3 schemas and stamps
version 1 without touching the data.

### Added
- **DB schema migration framework.** Schema changes are now expressed
  as numbered SQL files under `internal/store/migrations/` (embedded
  via `embed.FS`) and applied transactionally on server start. A new
  `schema_migrations` table records which versions have been applied;
  the runner skips already-applied migrations and aborts startup loudly
  on any failure rather than reaching handler code with a half-applied
  schema. Existing installs that predate the framework are detected by
  the presence of the `findings` table and have version 1 stamped
  without re-running 0001 — operator data is preserved untouched.
  Adding a future schema change is now: drop a new `NNNN_<title>.sql`
  file, write Go code against the new shape, write a CHANGELOG entry.
  See `RELEASING.md` "Schema migrations" for the policy and
  `docs/ARCHITECTURE.md` for the runner's data flow.
- **Comments and stable order in the allowlist / IOC list dialogs.**
  Lines starting with `#` are first-class comments that round-trip
  through save/reload — operators can use them as section headers
  (`# Cloud build agents`, `# Cobalt Strike beacons seen 2026-04`).
  Inline tails like `1.2.3.4 # office` are stripped down to the
  matchable entry at storage time. Whole-line comments are skipped by
  the matcher, never causing false positives or negatives. Both list
  dialogs now show a small hint above the textarea explaining the
  conventions.
- Test coverage for the migration framework
  (`internal/store/migrate_test.go`) and for list comment-handling and
  order preservation (`internal/store/list_test.go`).

### Changed
- `Store.InitDB` and `UserStore.NewUserStore` no longer create or alter
  schema inline — the migration runner does it before either gets the
  DB handle. The previous one-shot `dataset → sensor` rename, the
  `suppressions.detail` ALTER, and the `users.status` ALTER are now
  baked into `0001_init.sql` as column definitions; on existing installs
  these were already applied at boot of the previous version, so the
  bootstrap-stamp logic carries them forward without re-running.
- **Allowlist and IOC list now preserve operator line order across the
  save/reload cycle.** Previously the in-memory storage was a Go map,
  which randomized iteration on every read — operator groupings (and
  any visual structure) shuffled on each list dialog open. The store
  now keeps an ordered slice, persists in slice order via SQLite rowid,
  and reads back with `ORDER BY rowid`. Existing installs are cleaned
  automatically on first start (junk comment-strings stored by older
  Archer get sanitized at load time).
- Right-click context menu no longer carries a wide
  `[severity] Type — src → dst:port` banner that forced the menu wider
  than the longest action label. A small `↖` arrow at the top-left
  visually anchors the menu to the click point; the action labels
  themselves already include the resolved IP, so disambiguation
  survives the simplification.
- Right-click → Lookup → Censys now opens `platform.censys.io/hosts/<ip>`
  instead of `search.censys.io/hosts/<ip>`. Censys migrated their
  analyst-facing UI to the new platform host in 2026; the path is
  unchanged. The programmatic escalation lookup at
  `internal/server/handlers_api.go:601` still hits `search.censys.io`
  because Censys's API endpoint stayed stable across the UI rebrand.

### Fixed
- **Active findings filter is no longer lost when you mutate state from
  the analyst UI.** Adding an IP to the Allowlist (right-click or save
  dialog), suppressing or unsuppressing a finding, and the post-analyze
  refresh all called `loadFindings()` with no params, which dropped the
  current filter (search, src/dst, port, sensor, time window) and
  refetched the unfiltered dataset. The form fields stayed visible but
  the underlying data ignored them until the operator hit Apply or
  refreshed the page. All six call sites now pass `_currentFilterParams()`
  so the filter survives the round-trip.

---

## [v0.2.0] — 2026-05-07

Quiver wire protocol now carries an explicit version handshake so old
sensors against new servers fail loudly with a structured error
instead of silently breaking rsync. v1 is the first pinned protocol;
its full contract surface (wire shapes, sensor name regex, pubkey
algorithm, rsync layout, schedule contract, accepted Zeek log types)
is documented in `docs/QUIVER.md` so future v2 bumps have a clear
baseline. Pre-Phase-2 sensors that omit the version field are accepted
as v1 for one compatibility cycle; the flip to a hard rejection will
be announced under `### Deprecated` before the cycle closes.

### Added
- **Quiver protocol versioning.** Both enrollment (`/api/quiver/enroll`)
  and checkin (`/api/quiver/checkin`) now exchange a `protocol_version`
  integer. The server validates against an internal supported-versions
  set and rejects mismatches with a structured error so operators see
  "your sensor is on v1, server requires v2+" instead of an opaque
  rsync failure later. See `docs/QUIVER.md` "Protocol versioning" for
  the v1 contract surface, when to bump, and the deprecation cycle.
- `internal/server/quiver_protocol.go` — `QuiverProtocolVersion`
  constant, `supportedQuiverProtocols` set, validator helper.
- `PROTOCOL_VERSION=1` constant in `quiver_assets/install.sh` and
  `quiver_assets/quiver.sh`; persisted to `/etc/quiver/config`.
- Enrollment failures from `install.sh` now log the server's response
  body so a protocol mismatch surfaces the supported-versions list at
  install time, before any local state is committed.
- New `protocol_unsupported` checkin status; `quiver.sh` handles it by
  logging the supported set and exiting cleanly (sensor row stays
  enrolled — reinstall from the current Archer build to fix).
- Test coverage for protocol validation:
  `internal/server/quiver_protocol_test.go` exercises
  `resolveQuiverProtocol` (nil default, supported, unsupported), the
  canonical error body, and both handlers' rejection + backwards-compat
  paths (9 cases). First step toward Phase 4 (detection-semantics tests).
- QUIVER.md "Protocol versioning" section now pins the implicit pieces of
  the v1 contract (sensor name regex, pubkey algorithm, accepted Zeek
  log-type regex, `--remove-source-files`-never-set rsync semantics) so a
  future v2 bump has a clear baseline.

### Changed
- Sensors enrolled before this release that omit `protocol_version` are
  accepted as v1 for one compatibility cycle. The flip to a hard error
  on a missing field will be announced under `### Deprecated` before
  the cycle closes.

---

## [v0.1.0] — 2026-05-07

The first versioned release of Archer. Establishes a single source of
truth for the build identifier, surfaces it in the UI and JSON exports,
and starts this changelog. Functional behavior is unchanged from the
in-tree state at the cut.

### Added
- `internal/version` package with `Version`, `Commit`, `BuildTime` vars
  populated by `-ldflags -X` at build time.
- `/api/version` endpoint returning the running build identifier.
  Unauthenticated; same diagnostic tier as a future `/api/health`.
- Version pill in the analyst-UI status bar; click opens an "About"
  dialog with full version, commit, and build-time details.
- `start.sh` derives `ARCHER_VERSION` / `ARCHER_COMMIT` /
  `ARCHER_BUILD_TIME` from the git checkout (`git describe --tags
  --always --dirty`, `git rev-parse --short HEAD`, `date -u +%FT%TZ`)
  and passes them through `docker-compose` build args.
- OCI image labels (`org.opencontainers.image.version`,
  `org.opencontainers.image.revision`, `org.opencontainers.image.title`,
  `org.opencontainers.image.source`) so `docker inspect` reports the
  build identifier without needing to start a container.
- Top-level `RELEASING.md` documenting the release runbook (bump version,
  update changelog, commit, tag, push).

### Changed
- JSON exports now read the `archer_version` field from the build's
  `internal/version.Version` instead of the previous hardcoded
  `"3.0.0-go"` string. Affects `/api/export/json`, the campaigns export,
  the per-campaign Graphology export, and the Hosts JSON export.

### Notable changes since the last informal cut

The following were already merged before versioning landed and are
listed for completeness — they are part of the v0.1.0 baseline:

- **Two-tier watch cadence.** Watch mode runs the full pipeline only on
  the first tick of each UTC day; subsequent same-day ticks run a cheap
  incremental TI/IOC pass over mtime-filtered new files. A `Always run
  full scan on every watch tick` toggle in Settings reverts to the
  previous all-full behavior.
- **Two-phase TI scan.** The TI escalation pass is now a cheap
  destination-only sweep that builds candidate sets, followed by a
  targeted per-source pass restricted to "winning" destinations. On a
  15 GiB log corpus this cuts wall time by ~6-10× and avoids the GC
  thrash that the previous per-source-everywhere implementation hit at
  the GOMEMLIMIT ceiling.
- **TI cross-annotation.** When an automated TI hit produces new info
  for an IP, sibling findings touching the same IP get an analyst note
  pointing to the TI evidence — eliminates the "I have a TI hit but no
  way to find which host saw it" dead end.
- **Per-source TI fan-out.** TI hits now produce one finding per
  distinct source that contacted the bad destination, with real
  src/port/timestamp/URI evidence — instead of a single dead-end
  `(TI) → 1.2.3.4` row.
- **Findings/Hosts tab split.** `Host Risk Score` per-host roll-ups now
  live in the Hosts tab (click a row to drill in). The Findings tab is
  network events only.
- **Quiver: install-time backfill prompt.** The install script asks the
  operator how many days of historical logs to ship on first sync;
  honored by `quiver.sh` on `FIRST_SYNC=1`. Override with
  `INITIAL_BACKFILL_DAYS=N`.
- **Watch sidebar shows full-vs-incremental.** The sidebar surfaces the
  next tick's kind (`Full Scan` or `Incremental TI/IOC`) plus the next
  full scan's relative date — analysts can tell at a glance what the
  cadence will produce.
- **Stop button feedback.** Clicking Stop disables both Stop and Pause
  and relabels the button "Stopping…" while the analyzer drains.
- **Air-gap installation.** README documents the build-on-connected →
  ship-tarball → `docker load` install pattern.
- **Sensors modal.** Enrolled sensors, pending tokens, and unauthorized
  enrollment attempts are surfaced in the UI for admins.
- **TLS auto-bootstrap.** Sensor-facing HTTPS listener generates its
  own cert at first start; sensors pin the fingerprint at enrollment.
- **CIDR-aware allowlist + IOC matching.** Plus a Dst Port filter on the
  Findings tab.
- **Cytoscape graph view.** Plus PNG/JPEG export of the campaign graph.
- **Bounded-memory analyzer + log archive.** Auto-archive of logs older
  than the cutoff; optional findings prune. Disk-usage telemetry pulls
  to the Settings dialog so the admin doesn't need to ssh in.
- **Admin approval for new user registrations.** Pending-count badge on
  the Users button.
- **Detection-methods reference doc** at `docs/DETECTION_METHODS.md`
  covering all 12 detector families plus the retention vs. detection
  window math.

### Detection changes

None at the v0.1.0 cut — this release is versioning scaffolding only.
The baseline detection behavior is the in-tree state at this cut.

### Breaking

- The legacy `archer_version: "3.0.0-go"` string in JSON exports is
  replaced with the runtime version (`v0.1.0` at this cut). Any external
  tooling that parsed the literal as a sentinel needs a one-line update.

[Unreleased]: https://github.com/BushidoCyb3r/Archer/compare/v0.10.0...HEAD
[v0.10.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/BushidoCyb3r/Archer/releases/tag/v0.1.0
