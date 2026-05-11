# Archer Architecture

Coder-facing reference for how Archer is wired together. Companion to
[DETECTION_METHODS.md](DETECTION_METHODS.md), which covers detection
*math*; this doc covers how data flows, where state lives, what the
process model looks like, and what each file is responsible for.

## Table of contents

- [The 30-second tour](#the-30-second-tour)
- [Process model](#process-model)
- [Dataflow: from Zeek log to UI](#dataflow-from-zeek-log-to-ui)
- [Analyzer phases](#analyzer-phases)
- [Storage](#storage)
- [SSE event catalog](#sse-event-catalog)
- [HTTP route surface](#http-route-surface)
- [Auth and roles](#auth-and-roles)
- [Quiver sensor channel](#quiver-sensor-channel)
- [The watch worker](#the-watch-worker)
- [Build and version metadata](#build-and-version-metadata)
- [Testing](#testing)

---

## The 30-second tour

Archer is a single Go binary, baked into a single Docker container.
Inside the container:

- **HTTPS server on `:8443`** serves the UI, the analyst API, AND the
  Quiver sensor surface — every role uses TLS. v0.14.5 NEW-49 removed
  the pre-existing plaintext `:8080` listener; admin auth had been
  transmitted in cleartext, which is unacceptable for a tool whose
  threat model is "the LAN may be hostile." Sensor pinning still
  works because pinning checks the public key, not the chain; one
  cert satisfies both browser chain validation and sensor pinning.
- **OpenSSH on `:22`** (mapped to host `:2222`) accepts sensor rsync
  pushes via `rrsync` jail.
- **SQLite at `/data/archer.db`** holds findings, config, allowlist/IOC,
  suppressions, sensors, users.
- **Logs at `/logs/<sensor>/...`** are read-only to the analyzer,
  writable to the archive worker.
- **Archive at `/data/archive/...`** holds aged-out logs.

Architectural shape:

```
                    ┌─────────────────────────────────────────────┐
   browser ──HTTP──▶│  cmd/archer/main.go                         │
                    │    │                                         │
                    │    └─▶ internal/server/Server                │
                    │           ├─ HTTP mux + middleware           │
                    │           ├─ SSE broker                      │
                    │           ├─ watch worker (goroutine)        │
                    │           ├─ analyzer goroutine (on demand)  │
                    │           ├─ archive worker (on demand)      │
                    │           └─ TLS listener (:8443)            │
                    │                                              │
   sensor ──rsync──▶│  sshd (rrsync jail) → /logs/<sensor>/...    │
                    │                                              │
   sensor ──HTTPS─▶ │  /api/quiver/{enroll,checkin}                │
                    └─────────────────────────────────────────────┘
                                  │
                                  ▼
                            internal/store
                              SQLite at /data/archer.db
```

---

## Process model

One Linux process inside the container runs the Go binary. Everything
else is goroutines.

| Goroutine | Started by | Lifetime |
|-----------|------------|----------|
| HTTP listener | `main.go` | program lifetime |
| HTTPS listener | `main.go` (`tlsAddr != ""`) | program lifetime |
| SSE broker | `server.New` | program lifetime |
| Watch worker | `server.New` | program lifetime; ticks per cadence |
| Analyzer | `handleAnalyze` / watch tick | per-run; cancellable |
| Archive worker | `handleArchiveRun` / post-watch | per-run |
| Disk-usage refresh | first `/api/disk-usage` call | per-call (5-min cache) |
| Signal handler (stack dump) | `main.go` | program lifetime |

`tini` (PID 1) reaps zombies and forwards signals so sshd dies cleanly
when archer exits. `entrypoint.sh` is the supervised process: it starts
sshd, then archer.

---

## Dataflow: from Zeek log to UI

A new finding's life:

1. **Sensor pushes log.** `quiver.sh` on the sensor host runs `rsync`
   over SSH; the per-sensor `authorized_keys` line forces `rrsync -wo
   /logs/<sensor-name>/`. New files land in `/logs/<sensor>/<date>/...`.
2. **Operator (or watch worker) triggers analysis.** `POST /api/analyze`
   (manual) or the next watch tick (automatic). Both call into
   `internal/server.handleAnalyze` → spawns an analyzer goroutine.
3. **Analyzer runs.** `internal/analysis.Analyzer.Analyze(files)` walks
   the file list through the five phases (see below). Findings are
   collected via `a.add(finding)` into a slice, with a mutex guard.
4. **Findings get persisted.** When `Analyze` returns, the server calls
   `store.SetFindings(findings)`. This is a fingerprint-merge — see
   the [Storage](#storage) section.
5. **TI cross-annotation runs.** `crossAnnotateNewTIHits` walks new TI
   hits and adds analyst notes to sibling findings on the same IP.
6. **Notifications fire.** Critical-severity new findings emit
   `notification` SSE events, dropping into the analyst UI's bell.
   `Host Risk Score` is suppressed (it's a roll-up).
7. **`done` SSE event fires.** UI re-fetches `/api/findings` and
   re-renders. Watch ticks include `incremental: true` so the UI
   distinguishes them from full passes.
8. **Analyst sees the finding, optionally clicks Escalate.** That kicks
   off `runTIEscalation` which fans live TI lookups (VirusTotal, OTX,
   AbuseIPDB, etc.) and streams `ti_result` events as they settle.

---

## Analyzer phases

`internal/analysis/analyzer.go` orchestrates seven phases. Phase 0
runs in the background overlapping phase 1; phases 2–4 are sequential.

| Phase | Work | Files |
|-------|------|-------|
| 0 | Threat-intel feed prefetch. Built-in feeds (Feodo, URLhaus) fetch over the network; configured MISP/OpenCTI feeds load their cached indicators from SQLite via `FeedProvider`. Overlaps with phase 1. | `ti.go: prefetchFeeds` |
| 1 | All log-type analyzers in parallel — they're independent. Conn (beacon/strobe/exfil/long-conn), DNS, SSL, X.509, Files, Weird, Notice. | `conn.go`, `dns.go`, `ssl.go`, `x509.go`, `files.go`, `weird.go`, `notice.go` |
| 2 | HTTP analysis (sequential — needs `sslUIDIndex` populated by `analyzeSSL` in phase 1). | `http_analysis.go` |
| 2.5 | DGA hostname augmentation. Post-Phase-2 sweep over Beaconing / HTTP Beaconing findings; bumps score (+15) and severity when the destination Hostname's SLD looks algorithmically generated (high entropy + low English bigram log-likelihood). | `dga.go: applyDGAScoring` |
| 3 | URL + TI checks in parallel (need cached feeds from phase 0, plus the per-file dst sets). Two-phase TI scan: cheap dst-only sweep, then targeted per-source for "winners" only. | `ti.go`, `http_analysis.go: analyzeURLs` |
| 3.5 | Cross-detector correlation. Walks emitted findings, groups by (sensor, src, dst), emits a Correlated Activity roll-up when ≥N distinct detector types fire on the same pair. Contributing findings get their sibling IDs in `Correlations`. Sees historical findings via `findingsProvider` (same NEW-67 union pattern aggregateRisk uses). | `correlate.go` |
| 4 | Host risk scoring — composite per-host roll-up of all findings touching each host. Excludes roll-up types from the contributor set (HRS recursion + Correlated Activity double-counting). | `risk.go` |

The bounded-parallelism helper `parallelEach(files, fn)` is the
universal worker; it spawns `memoryBoundedWorkers(cpus)` goroutines,
each pulling from a file channel.

`AnalyzeTIOnly(files)` is the incremental path used by watch's
non-full ticks: only phase 0 and phase 3, over the mtime-filtered
file subset. Phase 0 still loads the cached MISP/OpenCTI indicator
buckets so cached-feed matches surface within one tick interval —
the upstream HTTPS fetch, however, only runs in the watch full-pass
path (`refreshFeedsBeforeFullPass` in `internal/server/watch.go`).

See [DETECTION_METHODS.md](DETECTION_METHODS.md) for the math behind
each detector.

---

## Storage

Single SQLite database at `/data/archer.db`. Driver: `modernc.org/sqlite`
(pure Go, no CGO).

### Schema

Created idempotently in `store.InitDB`:

```sql
CREATE TABLE allowlist (entry TEXT PRIMARY KEY);
CREATE TABLE ioc_list  (entry TEXT PRIMARY KEY);

CREATE TABLE findings (
    id           INTEGER PRIMARY KEY,
    type         TEXT,         -- 'Beaconing', 'TI Hit (IP)', etc.
    severity     TEXT,         -- 'low'/'medium'/'high'/'critical'
    score        INTEGER,      -- 0-100
    src_ip       TEXT,
    dst_ip       TEXT,
    dst_port     TEXT,
    detail       TEXT,         -- human-readable description
    timestamp    TEXT,
    source_file  TEXT,         -- path under /logs
    status       TEXT,         -- ''/'acknowledged'/'escalated'
    analyst      TEXT,         -- email of analyst who set status
    analyst_note TEXT,         -- free-text note
    status_ts    TEXT,         -- when status was set
    ioc_match    INTEGER DEFAULT 0,  -- 0/1 matches the IOC list
    is_new       INTEGER DEFAULT 0,  -- 0/1 fresh from this run
    sensor       TEXT,         -- formerly 'dataset'; renamed in-place
    intervals    TEXT,         -- JSON, beacon-chart raw intervals
    ts_data      TEXT,         -- JSON, beacon-chart raw timestamps
    notes        TEXT,         -- JSON array of operator notes (escalation, TI cross-notes)
    correlations TEXT          -- JSON []int of sibling finding IDs (Correlated Activity participants)
);

CREATE TABLE beacon_history (
    fingerprint    TEXT NOT NULL,        -- BeaconHistoryKey: canonical-string identity
                                         -- (Type|SrcIP|DstIP|DstPort|Host|URI joined by \x1f)
    day_utc        TEXT NOT NULL,        -- YYYY-MM-DD
    finding_type   TEXT NOT NULL,        -- 'Beaconing' or 'HTTP Beaconing'
    src_ip         TEXT NOT NULL,
    dst_ip         TEXT NOT NULL,
    dst_port       TEXT NOT NULL DEFAULT '',
    host           TEXT NOT NULL DEFAULT '',
    uri            TEXT NOT NULL DEFAULT '',
    max_score      INTEGER NOT NULL,     -- highest composite seen this day (0-100)
    max_score_at   INTEGER NOT NULL,     -- Unix-second when the max was observed
    last_score     INTEGER NOT NULL,     -- most recent composite seen this day
    last_score_at  INTEGER NOT NULL,     -- Unix-second when the last reading was observed
    severity       TEXT NOT NULL,        -- severity from the max-score write
    ts_score       REAL NOT NULL DEFAULT 0,  -- sub-axes from the max-score write
    ds_score       REAL NOT NULL DEFAULT 0,
    hist_score     REAL NOT NULL DEFAULT 0,
    dur_score      REAL NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    PRIMARY KEY (fingerprint, day_utc)
);

CREATE TABLE settings (
    id     INTEGER PRIMARY KEY,
    config TEXT NOT NULL       -- JSON-encoded internal/config.Config
);

CREATE TABLE suppressions (
    target TEXT PRIMARY KEY,
    expiry INTEGER NOT NULL,   -- Unix seconds
    detail TEXT DEFAULT ''
);

CREATE TABLE sensors (
    id              INTEGER PRIMARY KEY,
    name            TEXT,
    pubkey          TEXT,
    enrolled_at     INTEGER,
    last_seen_at    INTEGER,
    schedule_minute INTEGER,
    status          TEXT          -- 'enrolled' / 'disenrolling' / 'disenrolled'
);

CREATE TABLE enrollment_tokens (...);
CREATE TABLE unauthorized_attempts (...);

-- Users live in a separate file (/data/users.db, sometimes co-located):
CREATE TABLE users (...);
CREATE TABLE sessions (...);
CREATE TABLE pending_users (...);  -- approval-required new registrations
```

Schema changes use the migration framework in
`internal/store/migrate.go`. Numbered SQL files under
`internal/store/migrations/` are embedded via `embed.FS` and applied
transactionally on server start. A `schema_migrations` table records
which versions have been applied; the runner is idempotent so subsequent
boots are no-ops, and a failure rolls the transaction back and aborts
startup so handler code never sees a half-applied schema.

The runner is invoked from `NewUserStore` (which owns the DB connection
lifecycle) before any other store code touches the database.

For policy on adding new migrations — file naming, transaction
semantics, the forward-only rule — see [RELEASING.md](../RELEASING.md)
"Schema migrations".

### `SetFindings` is a fingerprint-merge

The single most important store method. Called at the end of every
analysis. It does NOT replace findings wholesale — it merges by
fingerprint (currently a hash of `type + src_ip + dst_ip + dst_port +
source_file`).

On a fingerprint match, the existing row's analyst-state fields are
preserved:
- `Status`
- `Analyst`
- `Notes`
- `AnalystNote`
- `StatusTS`

These are NOT preserved (they refresh from the new run):
- `Score`, `Severity`, `Detail`, `Timestamp`

This is intentional. Scores evolve as more activity accumulates;
analyst work doesn't get destroyed by a re-analysis.

The flag `IsNew` is set for fingerprint-fresh findings — TI
cross-annotation and notification-firing both gate on this.

After the merge persists, `SetFindings` also writes one row per
Beaconing / HTTP Beaconing finding to `beacon_history`, keyed by
`(Finding.BeaconHistoryKey(), today_UTC)` with the four sub-axis
scores. The composite PRIMARY KEY + `INSERT … ON CONFLICT DO
UPDATE` means a single daily row carries both the max score
observed across every analyze pass that ran that day and the
most recent reading. Under sub-daily watch cadence (or
admin-triggered re-analysis), a noon spike followed by an evening
fallback is captured as `max_score=88, last_score=50` rather
than silently dropped — the v0.16.0 `DO NOTHING` shape was
corrected in v0.16.1 NEW-76. Retention is 30 days, swept on the
watch's first-tick-of-UTC-day branch via
`Store.PurgeBeaconHistory()`.

### `BeaconHistoryKey` vs `Fingerprint`

Two identity functions on `model.Finding` with deliberately
different granularity:

- `Fingerprint()` is `{Type, SrcIP, DstIP, DstPort}` — what
  SetFindings uses to preserve analyst state. Intentionally
  coarse: one note per src→dst beacon family is what an analyst
  wants regardless of how many (host, uri) variants share the
  destination.
- `BeaconHistoryKey()` adds `Hostname` and `URI` and joins with
  ASCII Unit Separator (`\x1f`, never appears in URLs / hostnames
  / IPs). Used by `beacon_history` to keep separate trend lines
  for two HTTP beacons sharing a destination but going to
  different `(host, uri)` — without that wider key, the chart
  would mix signal on CDN-fronted destinations.

The canonical-string form (not sha256-hashed) is deliberate —
`beacon_history` rows can outlive their source finding by the
retention window, so the table needs to be SQLite-CLI inspectable
on its own without joining back to `findings`.

---

## SSE event catalog

The SSE broker (`internal/server/sse_broker.go`) fans events to all
subscribers connected to `/events`. Every event has a `type` and a JSON
`data` payload.

| Event | Producer | Payload | Notes |
|-------|----------|---------|-------|
| `progress` | analyzer | `{"pct":0-100,"step":"Phase 1: conn"}` | Pipeline progress. |
| `status` | analyzer, watch | `{"msg":"..."}` | Free-text status line surfaced as a transient toast. |
| `done` | analyzer, watch | `{"count":N,"new_count":N,"cancelled":bool,"incremental":bool}` | Run complete. UI reloads findings. `incremental:true` for non-full watch ticks. |
| `notification` | analyzer, watch | full `Finding` row | Critical/TI/IOC findings fire the bell. `Host Risk Score` is suppressed. |
| `ti_result` | escalation handler | `{"finding_id":N,"source":"vt","detail":"...","hit":bool,"informative":bool}` | Per-service TI lookup outcome during escalation. |
| `ti_done` | escalation handler | `{"finding_id":N,"hits":N}` | All TI lookups for this escalation have settled. Triggers consolidated note write. |
| `sensor_enrolled` | quiver enroll handler | full `Sensor` row | Drives the in-flight enrollment dialog's confirmation tick. |
| `unauthorized_attempt` | quiver checkin handler | full `UnauthorizedAttempt` row | Surfaces in the Sensors modal's "Unauthorized" tab. |

Events are best-effort — a slow subscriber doesn't block the producer.
The broker uses bounded buffered channels per subscriber and drops
events on overflow.

---

## HTTP route surface

All routes are registered in `internal/server.routes()` (server.go).
The role-aware middleware helpers wrap handlers:

| Helper | What it requires |
|--------|-----------------|
| `any(h)`   | Authenticated, any role (analyst, admin, viewer) |
| `write(h)` | Authenticated, analyst or admin |
| `admin(h)` | Authenticated, admin only |

Three special unauthenticated endpoints:

- `/login`, `/register`, `/logout` — auth surface itself.
- `/api/version` — diagnostic build identifier.
- `/quiver/install.sh`, `/api/quiver/enroll`, `/api/quiver/checkin` —
  served on the TLS listener, authenticated by single-use tokens (HTTPS)
  or per-sensor SSH keys (rsync).
- `/static/*` — JS/CSS/images.

For the full endpoint catalog with request/response shapes, see the
"API Reference" section of [README.md](../README.md).

---

## Auth and roles

Sessions are server-side, stored in the `sessions` table with a
random-token cookie (`SameSite=Lax`, `HttpOnly`, `Secure` when on
HTTPS). Login validates against `users`; failed login attempts are
rate-limited per email.

Three roles:

| Role | Can read | Can write | Can administer |
|------|----------|-----------|----------------|
| viewer | findings, exports, lists | nothing | nothing |
| analyst | everything | findings (status/notes), allowlist, IOC, suppressions, analysis, archive run | nothing |
| admin | everything | everything analyst can | users, config, watch settings, archive policy, sensor management, factory reset |

New registrations are admin-approved by default — they land in
`pending_users` until an admin clicks Approve in the Users dialog. The
Users-button badge surfaces the pending count for admins.

---

## Quiver sensor channel

The sensor side is at `internal/server/quiver_assets/` — three Bash
scripts (`install.sh`, `quiver.sh`, `quiver-uninstall.sh`) embedded in
the Go binary via `embed.FS` and served verbatim from
`/quiver/install.sh`.

Server-side endpoints (`internal/server/handlers_quiver.go`):

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /quiver/install.sh` | none (TLS) | Renders install bash with the requesting host's TLS fingerprint, hostname, and ports baked in. |
| `POST /api/quiver/enroll` | enrollment token | Body `{token, name, host, pubkey}`. Validates token, creates `/logs/<name>/`, writes per-sensor `authorized_keys` line forcing `command="rrsync -wo /logs/<name>/"`, persists the sensor row. |
| `POST /api/quiver/checkin` | sensor SSH key (transitively) | Body `{name}`. Returns `enrolled` / `disenrolled` / `unknown`. Unknown checkins create `unauthorized_attempts` rows. |

The protocol contract — what fields the sensor sends, the rsync layout
on disk, the ports, the sshd `command="..."` jail — is versioned via
`internal/server/quiver_protocol.go`. Both enrollment and checkin
payloads carry a `protocol_version` integer; the server validates
against `supportedQuiverProtocols` and rejects mismatches with a
structured error. The current version is `1` (see `QuiverProtocolVersion`
in `quiver_protocol.go`). Bumping rules and the deprecation cycle are
documented in [QUIVER.md](QUIVER.md) under "Protocol versioning."

For sensor-side operational details, see [QUIVER.md](QUIVER.md).

---

## The watch worker

`internal/server/watch.go` runs as a single goroutine launched from
`server.New`. It sleeps until the next configured tick, then calls
`triggerWatchAnalysis()`.

The cadence is configurable: `1`, `4`, `6`, `12`, or `24` hours, with
an anchor minute-of-hour. Timezone-aware (operator-supplied IANA name
via Settings).

Two-tier decision (`triggerWatchAnalysis`):

```go
if config.WatchAlwaysFull {
    refreshFeedsBeforeFullPass()           // synchronous, 2-min cap
    return launchAnalysisWithOptions(...)  // every tick is a full analysis
}
now := time.Now().UTC()
needFull := lastFull.IsZero() ||
            lastFull.Year()    != now.Year() ||
            lastFull.YearDay() != now.YearDay()
if needFull {
    refreshFeedsBeforeFullPass()           // synchronous, 2-min cap
    return launchAnalysisWithOptions(...)  // sets LastFullAnalysisUnix + LastAnalysisUnix
}
// Otherwise: incremental. Filter files by mtime > LastAnalysisUnix - 5min,
// run AnalyzeTIOnly with FeedProvider set so MISP/OpenCTI cached
// indicators participate (no fetch). Updates LastAnalysisUnix only.
return launchIncrementalAnalysis(filteredFiles)
```

`refreshFeedsBeforeFullPass` is the only path that fetches MISP /
OpenCTI feeds — every enabled feed is refreshed in parallel under a
two-minute cap, status updates per-feed, failures log without
blocking analysis. The auto-cadence feed worker is intentionally
disabled (see `server.go`'s `New` comment) and there is no manual
refresh endpoint, so a full pass is the *only* way to bring feed
indicators current. Incremental ticks consult whatever's already in
`feed_indicators`.

Manual "Discard findings & re-analyze" runs as a full pass and resets
both timestamps so the cycle restarts cleanly.

---

## Build and version metadata

Single-binary build via `go build`. CGO disabled (`CGO_ENABLED=0`)
because the SQLite driver is `modernc.org/sqlite` (pure Go). Final
binary is ~14 MB; the Docker image is ~30 MB.

Version metadata is injected at build time:

```bash
go build -ldflags="-s -w \
  -X github.com/BushidoCyb3r/Archer/internal/version.Version=$VERSION \
  -X github.com/BushidoCyb3r/Archer/internal/version.Commit=$COMMIT \
  -X github.com/BushidoCyb3r/Archer/internal/version.BuildTime=$BUILD_TIME" \
  -o /archer ./cmd/archer
```

`start.sh` derives `VERSION` from `git describe --tags --always
--dirty` and passes the values through `docker compose` build args.

The `internal/version` package's `Version`, `Commit`, and `BuildTime`
default to baked-in literals so an air-gap tarball build (no git
history) still reports a sensible value.

The values surface at:
- `GET /api/version` (programmatic, unauthenticated)
- The version pill in the analyst-UI status bar (clickable for the
  About dialog)
- `docker inspect archer` OCI labels
  (`org.opencontainers.image.version`, `.revision`, `.title`, `.source`)
- JSON exports as the `archer_version` field

---

## Testing

Limited at the moment — `go test ./...` runs:

- `internal/server/archive_test.go` — archive-worker dry-run logic.
- `internal/server/authorized_keys_test.go` — `authorized_keys` rewrite.
- `internal/store/store_test.go` — fingerprint-merge invariants.

There's no analyzer test suite yet. Phase 4 of the maturation plan adds
golden-file tests for detection semantics — a checked-in synthetic Zeek
corpus + expected-findings JSON, with a test that re-analyzes the
fixture and diffs against expected. That's how detection drift becomes
detectable.

CI is also pending (Phase 5) — currently `go vet`, `go test`, and
`go build` are run by hand.

---

*Last updated: 2026-05 alongside the v0.1.0 versioning work. Update
this doc whenever the dataflow, schema, SSE catalog, or process model
materially changes.*
