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
  `histScoreRITA`, `durationScore`, `shannonEntropy`) with table
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

[Unreleased]: https://github.com/BushidoCyb3r/Archer/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/BushidoCyb3r/Archer/releases/tag/v0.1.0
