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
- **Logs at `/logs/<sensor>/YYYY-MM-DD/...`** are read-only to the
  analyzer, writable to the archive worker. The top-level sensor dir is
  `archer:archer 02775` (setgid so new subdirs inherit the `archer`
  group); `entrypoint.sh` chowns date-tree subdirs to `archer:archer
  0775` at startup because rsync creates them as the sensor push user
  (`quiver`, uid 1000).
- **Archive at `/data/archive/<sensor>/YYYY-MM-DD/...`** holds aged-out
  logs. The worker determines file age from the `YYYY-MM-DD` path segment
  (not mtime, which rsync may not preserve across the `/logs` bind-mount
  → `/data` volume boundary).

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
| Signal handler (graceful shutdown) | `main.go` | program lifetime |

`tini` (PID 1) reaps zombies and forwards signals so sshd dies cleanly
when archer exits. `entrypoint.sh` is the supervised process: it starts
sshd, chowns `/data` (non-recursively) and `/data/tls` (recursive — a
handful of cert files) to `archer:archer`, chowns the `/logs` top-level
and sensor-level directories, then drops to uid 1001 via `su-exec archer`
to start the archer binary. The `/data/archive` tree is intentionally not
recursively chowned — archive files are already owned by `archer` when the
archive worker moves them, and a full recursive chown is O(n) in archive
file count. sshd continues running as root to handle Quiver rsync-over-SSH
on port 2222.

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
   the file list through the seven phases (see below). Findings are
   collected via `a.add(finding)` into a slice, with a mutex guard.
4. **Findings get persisted.** When `Analyze` returns, the server calls
   `store.SetFindings(findings)`. This is a fingerprint-merge — see
   the [Storage](#storage) section.
5. **TI cross-annotation runs.** `crossAnnotateNewTIHits` walks new TI
   hits and adds analyst notes to sibling findings on the same IP.
6. **Notifications fire.** New findings with `score >= 95` emit
   `notification` SSE events. Finding notifications surface in the
   bell panel; sensor/feed alarms surface as badges on their nav
   buttons. `Host Risk Score` is suppressed (it's a roll-up).
7. **`done` SSE event fires.** UI re-fetches `/api/findings` and
   re-renders. Watch ticks include `incremental: true` so the UI
   distinguishes them from full passes. The UI then calls
   `/api/findings/unseen` and pops the new-findings modal only if the
   logged-in analyst has findings detected since their session's
   new-findings boundary (anchored at login) — a per-user count that
   accumulates across passes, not the run's `new_count`, and the same
   cutoff the `delta` "New only" filter uses. The call runs at login and
   on each `done`; the modal pops only when the count exceeds the session's
   `ModalHighWater` (a server-side per-session guard, raised via
   `POST /api/findings/modal-ack` when shown), so a page refresh — which
   reuses the session — doesn't re-announce; it re-pops only when the count
   grows, and resets on a fresh login.
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
| 2.5 | SNI/JA3/JA4 enrichment for conn Beaconing — deferred here so `sslUIDIndex` is fully populated before the lookup. `analyzeSSL` also builds a per-fingerprint prevalence map over all `ssl.log` (conns, distinct src hosts, distinct dsts); the server pushes it to the store after the pass (`SetFingerprintPrevalence`) and the **TLS-fingerprint rarity + cross-host-cluster** concern (`fp_concern`/`fp_detail`, enrichment only, no score change) is derived from it at read time, not stamped here. Then DGA hostname augmentation: sweep over Beaconing / HTTP Beaconing findings; bumps score (+15) and severity when the destination Hostname's SLD looks algorithmically generated (high entropy + low English bigram log-likelihood). | `analyzer.go: enrichBeaconSNI`, `store.go: FingerprintConcern`, `dga.go: applyDGAScoring` |
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
    status       TEXT,         -- ''/'acknowledged'/'escalated'/'dismissed'
    analyst      TEXT,         -- email of analyst who set status
    analyst_note TEXT,         -- free-text note
    status_ts    TEXT,         -- when status was set
    ioc_match    INTEGER DEFAULT 0,  -- 0/1 matches the IOC list
    is_new       INTEGER DEFAULT 0,  -- 0/1 fresh from this run (overwritten every run)
    detected_at  INTEGER NOT NULL DEFAULT 0,  -- migration 0029: epoch the fingerprint first
                                              -- entered the store; carried forward unchanged on
                                              -- merge (unlike is_new). Anchors the per-session
                                              -- "new since you last looked" surfaces: the modal,
                                              -- the "New only" filter, and the table's new dot /
                                              -- detail badge (via the transient is_new_to_me).
    sensor       TEXT,         -- formerly 'dataset'; renamed in-place
    intervals    TEXT,         -- JSON, beacon-chart raw intervals
    ts_data      TEXT,         -- JSON, beacon-chart raw timestamps
    notes        TEXT,         -- JSON array of operator notes (escalation, TI cross-notes)
    correlations TEXT,         -- JSON []int of sibling finding IDs (Correlated Activity participants)
    ts_score        REAL NOT NULL DEFAULT 0,  -- migration 0018: per-axis beacon sub-scores
    ds_score        REAL NOT NULL DEFAULT 0,  -- (NEW-89 closure). DNS Beaconing leaves
    hist_score      REAL NOT NULL DEFAULT 0,  -- ds_score zero — no data-size axis.
    dur_score       REAL NOT NULL DEFAULT 0,
    mean_interval   REAL NOT NULL DEFAULT 0,  -- triage-header timing summary; persisted
    median_interval REAL NOT NULL DEFAULT 0,  -- so it survives restart + carry-forward
    jitter          REAL NOT NULL DEFAULT 0,  -- interval coefficient of variation
    sample_size     INTEGER NOT NULL DEFAULT 0,
    ja3             TEXT NOT NULL DEFAULT '',  -- migration 0019: TLS client fingerprint of
    ja4             TEXT NOT NULL DEFAULT '',  -- the conn-level Beaconing seed connection
    top_uris        TEXT NOT NULL DEFAULT ''   -- migration 0020: JSON []{uri,count} HTTP-beacon
                                               -- path footprint, aggregated pre-dedup
);

CREATE TABLE beacon_history (
    fingerprint    TEXT NOT NULL,        -- BeaconHistoryKey: canonical-string identity
                                         -- (Type|SrcIP|DstIP|DstPort|Host|URI joined by \x1f)
    day_utc        TEXT NOT NULL,        -- YYYY-MM-DD
    finding_type   TEXT NOT NULL,        -- 'Beaconing', 'HTTP Beaconing', or 'DNS Beaconing'
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

-- v0.17.1 NEW-98 / migration 0014. Notifications persist across server
-- restart so a finding that rang the bell at T isn't lost if Archer
-- restarts at T+5 minutes. Kind controls where the alert surfaces:
--   'finding' carries FindingID + SrcIP/DstIP/DstPort; surfaces in
--     the bell panel; Jump scrolls to the row in the findings table.
--   'sensor' carries Target=sensor name; surfaces as a badge on the
--     Sensors nav button; opening the modal clears the badge.
--   'feed'   carries Target=feed name; surfaces as a badge on the
--     Feeds nav button; opening the modal clears the badge.
-- Empty Kind reads as 'finding' (pre-v0.17.0 persisted rows).
-- Dismissed is a soft delete — the row stays for forensic purposes
-- but the bell and button badges ignore dismissed=1.
CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY,
    kind       TEXT DEFAULT '',         -- 'finding'/'sensor'/'feed' or empty
    target     TEXT DEFAULT '',         -- sensor or feed name (non-finding)
    detail     TEXT DEFAULT '',         -- human-readable description
    finding_id INTEGER DEFAULT 0,       -- 0 for non-finding rows
    severity   TEXT NOT NULL,
    type       TEXT NOT NULL,
    src_ip     TEXT DEFAULT '',
    dst_ip     TEXT DEFAULT '',
    dst_port   TEXT DEFAULT '',
    dismissed  INTEGER DEFAULT 0
);

-- v0.17.0 / migration 0013. Per-feed reliability tracking — see
-- internal/server/feed_health.go. UpdateFeedRefreshState toggles
-- this column via SQL CASE on the refresh status so concurrent
-- refresh ticks can't race the read-modify-write counter. The
-- feed-reliability alarm fires at >=3 consecutive failures OR
-- >24h since the last successful refresh.
-- (column added to existing feeds table)
ALTER TABLE feeds ADD COLUMN consecutive_failures INTEGER DEFAULT 0;

-- v0.18.5 / migration 0015. Per-feed opt-out of the NEW-18 SSRF
-- guard. Default 0 (deny). Setting to 1 lets validateFeedRequest
-- accept a feed URL targeting internal address space, and lets the
-- per-feed httpClientWithTLS CheckRedirect follow internal hops.
-- See docs/FEEDS.md "Internal address bypass" for the operator
-- guidance. feed_create / feed_update audit rows carry the flag.
ALTER TABLE feeds ADD COLUMN allow_internal INTEGER NOT NULL DEFAULT 0;

-- v0.22.0 / migration 0016. Indicator-aging visibility. How many
-- indicators the most recent full refresh aged out. Refresh-owned
-- like last_indicator_count (NEW-22 ownership): written only by the
-- prune step via the targeted SetFeedPrunedCount, never by an admin
-- UpdateFeed. last_indicator_count is the post-prune survivor count,
-- so pre-prune population = last_pruned_count + last_indicator_count;
-- the Feeds dialog renders the ratio as a per-feed "% aged out".
-- See docs/FEEDS.md "Calibrating the window".
ALTER TABLE feeds ADD COLUMN last_pruned_count INTEGER NOT NULL DEFAULT 0;

-- v0.24.0 / migration 0017. Pair allowlist — tuple-scoped permanent
-- view filter (UI: the Allowlist modal's "Relationships" tab as of
-- v0.25.0). Pure view filter: consulted in findings_filter +
-- bell-suppression only, never at emit time, so it never deletes a
-- finding from the store.
CREATE TABLE pair_allowlist (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    src          TEXT NOT NULL,
    dst          TEXT NOT NULL,
    port         TEXT NOT NULL DEFAULT '',
    finding_type TEXT NOT NULL DEFAULT '',   -- '' = every type on the tuple
    sensor       TEXT NOT NULL DEFAULT '',   -- '' = every sensor on the tuple
    detail       TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
);  -- UNIQUE(src, dst, port, finding_type, sensor) — migration 0027

-- v0.38.0 / migration 0027. sensor column on pair_allowlist + unique-index
-- rebuild to include sensor. sensor='' is a wildcard that matches all
-- sensors (existing rules upgrade with sensor='', preserving behavior).
-- A non-empty sensor scopes the rule to one collector so allowlisting
-- sensorA's known-good pair doesn't suppress sensorB's view of the same
-- tuple. The unique index is dropped and recreated because SQLite does
-- not support ADD CONSTRAINT on existing indexes.

-- v0.38.0 / migration 0028. sensor column on notifications. Carrying
-- the finding's sensor into the notification lets the retroactive
-- bell-dismiss (dismissHiddenFindingNotificationsLocked) respect the
-- sensor scope of a newly added pair rule. Existing notification rows
-- get sensor='' which matches only wildcard (sensor='') rules — correct
-- for pre-v0.38.0 rows that were emitted without sensor context.

-- v0.25.0 / migration 0018. Eight beacon-detail columns on findings
-- (shown inline above): the four per-axis sub-scores + the
-- mean/median/jitter/sample_size triage-summary fields. Closes NEW-89
-- — they were in-memory only and zeroed on every restart and on the
-- preserve-historical carry-forward; now durable.

-- v0.27.0 / migrations 0019 + 0020. ja3/ja4 (the conn-level Beaconing
-- seed connection's TLS client fingerprint, lifted from sslUIDIndex at
-- emit) and top_uris (the HTTP-beacon path footprint, JSON []{uri,
-- count} aggregated over the pre-dedup (sensor,src,dst,host) keys).
-- Same restart/carry-forward durability reason as 0018. Additive,
-- DEFAULT '' — not a detection-semantics change (no score, threshold,
-- finding type, or Fingerprint() touched; golden corpus unchanged).

-- v0.28.0 / migration 0021. query_filter_json on feeds. TEXT NOT NULL
-- DEFAULT '' — stores a feed-specific indicator-filter expression so
-- different MISP/OpenCTI feeds can scope their indicator pull independently.

-- v0.30.0 / migration 0022. service_tokens table — machine-to-machine
-- tokens for endpoints that cannot use a browser session (Prometheus,
-- Nagios, shell scripts). Raw token never stored; SHA-256 hash only.
CREATE TABLE service_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT    NOT NULL,
    token_hash  TEXT    NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    created_by  TEXT    NOT NULL DEFAULT ''
);

-- v0.30.0 / migration 0023. spectral_rescued and spectral_period on
-- beacon_history. spectral_rescued=1 when Lomb-Scargle rescued the
-- beacon that day; spectral_period is the dominant period in seconds.
-- Both update alongside peak-characterisation columns (severity, sub-axis
-- scores). DEFAULT 0 — pre-0023 rows and non-spectral beacons read as
-- "not rescued." The evolution chart marks rescued days with a distinct
-- indicator.
ALTER TABLE beacon_history ADD COLUMN spectral_rescued INTEGER NOT NULL DEFAULT 0;
ALTER TABLE beacon_history ADD COLUMN spectral_period  REAL    NOT NULL DEFAULT 0;

-- Users live in a separate file (/data/users.db, sometimes co-located):
CREATE TABLE users (...);
-- migration 0029 adds users.findings_seen_at (INTEGER): epoch of the start
-- of this analyst's most recent session. Each login freezes the PREVIOUS
-- value as that session's new-findings boundary (held in the in-memory
-- session), then advances this column to now. Paired with
-- findings.detected_at to compute the per-session "new since you last logged
-- in" count (detected_at > boundary) for both the modal and the "New only"
-- filter. Seeded to account-creation time so new users start caught-up.
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

There are two public entry points sharing one implementation
(`setFindingsImpl`):

- **`SetFindings(findings)`** — full-pass path. Purges historical
  roll-up findings (Correlated Activity, Host Risk Score) whose
  fingerprints aren't in the fresh emission set. Full analyses re-run
  `correlateFindings` and `aggregateRisk`, so absence = "no longer
  valid."
- **`SetFindingsIncremental(findings)`** — incremental TI-only path.
  Preserves roll-ups untouched. Incrementals don't run correlate or
  aggregate, so absence means "not re-evaluated this pass" — purging
  would drop every CA / HRS the next-most-recent full pass had
  emitted. v0.21.0 added this split after the prior `SetFindings`-only
  behavior was found to be silently dropping rollups across the five
  incremental ticks between UTC-midnight full passes.

A defensive in-batch fingerprint dedup runs at the top of
`setFindingsImpl` (also v0.21.0): when two findings emitted in the
same batch share the same `Fingerprint()`, the highest-scored row wins
and the duplicate is dropped before ID assignment. Without this guard, a multi-source TI Hit emit would
hand two findings the same carry-forward `old.ID`, the second
`INSERT` would collide on the UNIQUE primary key, and the entire
`saveFindings` transaction would roll back — losing every finding,
rollup, and analyst-state change from that run while the in-memory
`s.findings` still reflected the new state. See
`DETECTION_METHODS.md` §12.4 for the original (now-resolved) emit
shape.

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

The notification-emit block consults the allowlist and active
suppression set via `isHiddenLocked(srcIP, dstIP)` and
`isPairAllowedLocked(src, dst, port, type, sensor)` before adding to
`s.notifications`. The same exclusion check `filterFindings` applies
at read time runs here too, so the bell never rings for a finding
whose row would be invisible in the table. NEW-111 (v0.18.1) — the
matching cleanup pass `dismissHiddenFindingNotificationsLocked` runs
from `SetAllowlist`, `AddSuppression`, and `AddPairAllow` to mark
already-emitted finding notifications dismissed when their src/dst is
now hidden or their pair is now allowlisted. `Notification.Sensor`
(migration 0028) carries the finding's sensor so the pair-allow
dismiss correctly respects sensor-scoped rules. Sensor and feed alarms
have no src/dst IPs and pass through unchanged (they surface on their
nav buttons, not the bell).

After the merge persists, `SetFindings` also writes one row per
Beaconing / HTTP Beaconing / DNS Beaconing finding to `beacon_history`, keyed by
`(Finding.BeaconHistoryKey(), today_UTC)` with the four sub-axis
scores. The composite PRIMARY KEY + `INSERT … ON CONFLICT DO
UPDATE` means a single daily row carries both the max score
observed across every analyze pass that ran that day and the
most recent reading. Under sub-daily watch cadence (or
admin-triggered re-analysis), a noon spike followed by an evening
fallback is captured as `max_score=88, last_score=50` rather
than silently dropped — the v0.16.0 `DO NOTHING` shape was
corrected in v0.16.1 NEW-76. `max_score` / `max_score_at` stay
strict-greater, but the `severity` and four sub-axis columns also
update on a score *tie* when the new pass is strictly more severe
(v0.26.0 NEW-84 — a DGA High→Critical bump at an unchanged sub-80
score must not stay recorded as the earlier non-DGA pass's lower
severity; severity rank is an explicit CASE since the column is
TEXT). Retention is 30 days, swept on the watch's
first-tick-of-UTC-day branch via `Store.PurgeBeaconHistory()`.

### `BeaconHistoryKey` vs `Fingerprint`

Two identity functions on `model.Finding` with deliberately
different granularity:

- `Fingerprint()` is `{Type, SrcIP, DstIP, DstPort, Sensor}` for
  all beacon types. For `HTTP Beaconing` it additionally includes
  `Hostname` and `URI`, because two HTTP beacons to different hosts
  or paths on the same (src, dst, port, sensor) are genuinely
  distinct detections with independent analyst state — without this,
  only the highest-scored (host, uri) pair would survive the in-batch
  dedup and be written to the DB.
- `BeaconHistoryKey()` is `{Type, SrcIP, DstIP, DstPort, Hostname, URI, Sensor}`
  joined with ASCII Unit Separator (`\x1f`, never appears in URLs /
  hostnames / IPs). Used by `beacon_history` to keep separate trend
  lines for two HTTP beacons sharing a destination but going to
  different `(host, uri)` — without that wider key, the chart would
  mix signal on CDN-fronted destinations. Includes `Sensor` so two
  Quiver collectors observing the same beacon pair maintain
  independent history rows.

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
| `notification` | analyzer, watch, sensor heartbeat, feed health | `Notification` row | Bell entry. `kind` disambiguates: `finding` (score ≥ 95), `sensor` (heartbeat alarm), `feed` (reliability alarm). `Host Risk Score` is suppressed. |
| `ti_result` | escalation handler | `{"finding_id":N,"source":"vt","detail":"...","hit":bool,"informative":bool}` | Per-service TI lookup outcome during escalation. |
| `ti_done` | escalation handler | `{"finding_id":N,"hits":N}` | All TI lookups for this escalation have settled. Triggers consolidated note write. |
| `sensor_enrolled` | quiver enroll handler | full `Sensor` row | Drives the in-flight enrollment dialog's confirmation tick. |
| `unauthorized_attempt` | quiver checkin handler | full `UnauthorizedAttempt` row | Surfaces in the Sensors modal's "Unauthorized" tab. |
| `watch.heartbeat` | server | `{}` | Unconditional 60s tick — proves the SSE pipeline is alive. UI flips a top-bar dot red after 180s without one. |

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

**Response security headers.** Every response — every route, every
status code — passes through `Server.ServeHTTP`, which sets
`X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors
'none'`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy:
no-referrer` before delegating to the mux (v0.26.0, closes an
external-scan clickjacking finding). HSTS is **deliberately not
set**: the self-signed cert regenerates on a TLS/volume reset, so
an HSTS pin would turn a post-regen cert mismatch into a
non-bypassable browser error and lock analysts out — rationale is
recorded at the header block in `server.go`.

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
structured error. The current version is `2` (see `QuiverProtocolVersion`
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
    refreshFeedsBeforeFullPass()           // synchronous, 10-min cap
    return launchAnalysisWithOptions(...)  // every tick is a full analysis
}
now := time.Now().UTC()
needFull := lastFull.IsZero() ||
            lastFull.Year()    != now.Year() ||
            lastFull.YearDay() != now.YearDay()
if needFull {
    refreshFeedsBeforeFullPass()           // synchronous, 10-min cap
    return launchAnalysisWithOptions(...)  // sets LastFullAnalysisUnix + LastAnalysisUnix
}
// Otherwise: incremental. Filter files by mtime > LastAnalysisUnix - 5min,
// run AnalyzeTIOnly with FeedProvider set so MISP/OpenCTI cached
// indicators participate (no fetch). Updates LastAnalysisUnix only.
// NOTE: LastAnalysisUnix is set to the analysis START time, not the
// completion time. Any file rsynced during a long analysis run still
// has an mtime inside the next tick's [startedAt-5min, ∞) window.
return launchIncrementalAnalysis(filteredFiles)
```

`refreshFeedsBeforeFullPass` is the **steady-state** path that fetches
MISP / OpenCTI feeds — every enabled feed is refreshed in parallel
under a 10-minute cap, status updates per-feed, failures log without
blocking analysis. The auto-cadence feed worker (`internal/feeds/worker.go`)
exists but is not wired into `server.New` — the watch tick drives refresh
instead. Admins can also trigger an on-demand single-feed fetch via
`POST /api/feeds/{id}/refresh` (10-minute hard cap, detached from the
request context so a browser disconnect doesn't cancel an in-flight pull
— v0.19.0). Incremental ticks consult whatever's already in
`feed_indicators` without re-fetching.

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

*Last updated: 2026-05 alongside the v0.19.0 release. Update
this doc whenever the dataflow, schema, SSE catalog, or process model
materially changes.*
