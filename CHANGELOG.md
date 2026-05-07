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

### Added
- **Comments and stable order in the allowlist / IOC list dialogs.**
  Lines starting with `#` are first-class comments that round-trip
  through save/reload — operators can use them as section headers
  (`# Cloud build agents`, `# Cobalt Strike beacons seen 2026-04`).
  Inline tails like `1.2.3.4 # office` are stripped down to the
  matchable entry at storage time. Whole-line comments are skipped
  by the matcher, never causing false positives or negatives. Both
  list dialogs now show a small hint above the textarea explaining
  the conventions.
- Test coverage for list comment-handling and order preservation in
  `internal/store/list_test.go`.

### Changed
- Allowlist and IOC list now preserve operator line order across the
  save/reload cycle. Previously the in-memory storage was a Go map,
  which randomized iteration on every read — operator groupings (and
  any visual structure) shuffled on each list dialog open. The store
  now keeps an ordered slice, persists in slice order via SQLite
  rowid, and reads back with `ORDER BY rowid`. Existing installs are
  cleaned automatically on first start (junk comment-strings stored
  by older Archer get sanitized at load time).

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

[Unreleased]: https://github.com/BushidoCyb3r/Archer/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/BushidoCyb3r/Archer/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/BushidoCyb3r/Archer/releases/tag/v0.1.0
