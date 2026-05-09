# Archer HTTP API reference

This document is the contract for Archer's HTTP/SSE surface. It enumerates
every endpoint registered in `internal/server/server.go`'s `routes()`,
their authentication/role requirements, request shapes, and response
shapes. **Pre-1.0:** any field documented here may break between minor
versions, but a breaking change is announced explicitly in CHANGELOG —
see *Breaking-change surfaces* and *Deprecation policy* below.

> Phase 6 deliverable. Phase 7 (TI feed integration) shipped in
> v0.5.0 and added the CRUD endpoints under `/api/feeds/*`; their
> shapes and roles are documented in `docs/FEEDS.md`. There is no
> manual-fetch endpoint — feed refreshes are driven by the watch
> scheduler's pre-full-pass refresh.

---

## Conventions

### Listeners and ports

Archer runs two listeners:

- **HTTPS on `:8443`** — primary surface. TLS cert auto-generated at
  `/data/tls/server.{crt,key}`. Sensors pin the cert by SHA-256
  fingerprint (`/api/sensors/info` exposes the fingerprint).
- **HTTP on `:8080`** — diagnostic only. Same routes, no TLS. Useful
  inside the container for `curl localhost:8080/api/version`. Don't
  expose externally.

### Authentication

Every route except the explicitly-public ones below requires a session
cookie set by `POST /login`. The cookie is `HttpOnly`, `SameSite=Lax`,
and (over HTTPS) `Secure`. Sessions are persisted in
`/data/users.db`'s `sessions` table.

**Public (no session)**:
- `GET /api/version`
- `POST /login`, `POST /register`, `POST /logout`
- `GET /quiver/install.sh`
- `POST /api/quiver/enroll`, `POST /api/quiver/checkin`
- `GET /static/*`

All other routes return `401 Unauthorized` for unauthenticated
requests.

### Roles

Authenticated requests are authorized against three roles:

| Role | Permissions |
|------|-------------|
| `admin` | Everything: config, user management, sensor enroll/disenroll, watch/archive control. |
| `analyst` | Read+write: triage findings, manage allowlist/IOC, run analysis, escalate, import/export. |
| `viewer` | Read-only: list findings, read config, view watch/archive state. |

Role enforcement is layered:
- `requireAuth` middleware (`auth.go`) validates the session.
- `requireRole(...)` middleware (`middleware.go`) gates routes
  declared as `write(...)` or `admin(...)` in `routes()`.
- Per-handler checks use `userFromCtx(r).Role` for routes that mix
  read-as-any with write-as-admin (e.g., `/api/config`, `/api/watch`).

A request that authenticates but lacks the required role gets
`403 Forbidden` with body `{"error": "forbidden"}`.

### Response format

All `/api/*` endpoints return JSON unless noted (the export endpoints
emit `application/json` or `text/csv`; SSE emits `text/event-stream`).

Successful reads return the resource shape directly.
Successful writes typically return `{"ok": true}`.

### Error format

Errors are JSON: `{"error": "message"}` with the appropriate HTTP
status. Common codes:

- `400 Bad Request` — malformed JSON, missing required field, invalid
  query parameter.
- `401 Unauthorized` — no session or expired session.
- `403 Forbidden` — authenticated but role insufficient.
- `404 Not Found` — finding ID doesn't exist, sensor name unknown,
  user ID unknown.
- `405 Method Not Allowed` — HTTP method not supported on this route.
- `409 Conflict` — duplicate (e.g., sensor name already enrolled).
- `500 Internal Server Error` — unexpected; the body is best-effort
  and may be the empty string.

### Time formats

Two formats are accepted and emitted:

- **`YYYY-MM-DD HH:MM:SS` (UTC)** — the default in finding
  `Timestamp` strings and in the `from`/`to` query params on
  `/api/findings`.
- **RFC 3339** (e.g., `2026-05-08T18:30:00Z`) — accepted as an
  alternate input on `from`/`to`.

Internal Unix-second timestamps appear as integers in fields suffixed
`_unix` or `_at` (e.g., `last_full_analysis_unix`,
`archive_last_run_at`). The `/api/version`'s `build_time` is RFC 3339.

### Server-Sent Events

`GET /events` streams pub/sub events. The connection holds open; events
arrive as `data: {...}\n\n` frames. Reconnect on close — the broker
doesn't replay missed events. Event types are listed in
`internal/server/sse_broker.go`; the principal ones are `progress`,
`status`, `done`, `notification`, `ti_result`, `ti_done`,
`sensor_enrolled`, and `unauthorized_attempt`.

---

## Breaking-change surfaces

Per `CHANGELOG.md`'s **Versioning** section, four surfaces require a
`### Breaking` entry on change pre-1.0 (and a major bump post-1.0):

1. **HTTP / SSE API contract** — anything in this document. Renaming
   or removing a field, changing a status code's meaning, changing
   the SSE event shape.
2. **DB schema** — column adds/renames/removes, table changes. Lives
   under `internal/store/migrations/`.
3. **Quiver sensor protocol** — `QuiverProtocolVersion` constant in
   `internal/server/quiver_protocol.go`. Bump when enrollment/checkin
   payload shape changes incompatibly.
4. **Detection semantics** — score formulas, thresholds, finding
   types, feed-matching logic. Goes under `### Detection changes`
   in CHANGELOG; golden-file tests under
   `internal/analysis/testdata/zeek/` catch unintended drift.

Field *additions* are non-breaking and don't require a Breaking
entry. Removals and rename-with-no-alias do.

---

## Deprecation policy

When an API field, query parameter, or endpoint is removed, the
removal happens over a one-minor-version-cycle warning window:

1. **Cycle N — deprecation announced.**
   - The field is documented as deprecated in CHANGELOG under a
     `### Deprecated` section, with a clear pointer to the
     replacement (if any) and the target removal version.
   - The server keeps responding with the field but adds an HTTP
     `Warning: 299 - "<field> deprecated, removed in vX.Y.Z. Use
     <replacement>."` header (RFC 7234 §5.5).
   - Clients can grep response headers for `Warning:` to detect
     which calls touch deprecated surface.
2. **Cycle N+1 — removal.**
   - The field disappears from responses; query params / request
     fields are silently ignored or rejected with a clear error.
   - The CHANGELOG entry moves from `### Deprecated` to
     `### Breaking` with a back-reference to the deprecation
     announcement.
   - A note in `RELEASING.md` cross-references both entries so the
     same operator who announced the deprecation knows when to
     remove it.

A removal that *can't* go through the cycle (security fix, urgent
spec break) ships immediately under `### Breaking` and explains why
the cycle was skipped.

Endpoint *removal* follows the same pattern: the route returns its
current response with a `Warning` header for one cycle, then
returns `410 Gone` in the next minor.

---

## Endpoint reference

Tables below show every route. Detailed shapes follow for the
high-traffic endpoints. For less-used endpoints the implementation is
the contract — pointers are given.

### Auth

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `POST` | `/login` | (public) | Sets session cookie. Body: `{"email","password"}`. |
| `POST` | `/register` | (public) | First user becomes admin; subsequent users land in `pending` state. Body: `{"email","first_name","last_name","password"}`. |
| `POST` | `/logout` | any | Invalidates current session. |

See `internal/server/auth.go` for the exact bcrypt cost, session TTL,
and rate-limit details.

### Diagnostic

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/version` | (public) | Build identity. |

**Response** (`200 OK`):
```json
{
  "version":    "v0.4.0",
  "commit":     "2b61c7a",
  "build_time": "2026-05-08T18:30:00Z"
}
```

The fields are all strings. `commit` and `build_time` are `"unknown"`
when the binary was built without `-ldflags -X` (e.g., air-gap tarball
install where the build host had no git history).

### Findings

The most-used surface. Findings are detector outputs, persisted in
`/data/archer.db`'s `findings` table.

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/findings` | any | List with filters + pagination. Returns array of (projected) Finding. Sets `X-Total-Count` and `X-Has-More` response headers. |
| `GET` | `/api/findings/counts` | any | `{open, ack, esc, ioc, total}` aggregate counts honoring the active filter set (`status` and `ioc_only` are stripped — the counts span all status buckets). Drives the dashboard's info-line counters without forcing a full-set scan from the client. |
| `GET` | `/api/findings/facets` | any | `{types, sensors}` — distinct values across the filter set. `status`, `ioc_only`, `delta`, `type`, `sensor`, `limit`, `offset` are stripped so the dropdowns reflect every available type/sensor regardless of what's currently selected. Powers the Type and Sensor filter dropdowns. |
| `GET` | `/api/findings/{id}` | any | Single finding (full shape including `ts_data`/`intervals`/`notes`). |
| `PUT` | `/api/findings/{id}` | analyst+ | Update status/analyst-note. |
| `POST` | `/api/findings/{id}/escalate` | analyst+ | Run TI escalation; emits `ti_result` SSE events. |
| `POST` | `/api/findings/{id}/notes` | analyst+ | Append a note to the finding. |
| `GET` | `/api/findings/{id}/raw` | any | Raw-log pivot — the Zeek lines that produced this finding. |

**Finding shape** (`model.Finding`, `internal/model/finding.go:23`):

```json
{
  "id":           42,
  "type":         "Beaconing",
  "severity":     "HIGH",
  "score":        85,
  "src_ip":       "192.168.1.5",
  "dst_ip":       "203.0.113.10",
  "dst_port":     "443",
  "detail":       "Connections: 30 | Mean interval: 60.0s | …",
  "timestamp":    "2024-01-15 12:00:00",
  "source_file":  "/logs/sensor1/conn.log",
  "status":       "",
  "analyst":      "",
  "analyst_note": "",
  "status_ts":    "",
  "ioc_match":    false,
  "is_new":       true,
  "sensor":       "sensor1",
  "intervals":    [60.0, 60.0, 60.0],
  "ts_data":      [[1705320000, 500, 2000], …],
  "notes":        []
}
```

- `severity` is one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `status` is `""` (open), `acknowledged`, or `escalated`.
- `intervals`, `ts_data`, `notes`, `sensor` are `omitempty` —
  expect their absence on findings that don't carry that data.
- `ts_data` rows are `[ts_unix, orig_bytes, resp_bytes]` triples used
  for the beacon chart on the analyst UI.
- **`GET /api/findings` returns a projected list** that drops
  `ts_data`, `intervals`, and `notes` regardless of whether they're
  populated — those fields balloon to hundreds of KB per row on
  beacon-rich findings and aren't consulted on the list view. To get
  the full shape, fetch the single-finding endpoint
  (`/api/findings/{id}`). `/api/export/json` similarly strips
  chart-data on the way out (separate code path; same intent).

**`GET /api/findings` query parameters** (all optional):

| Param | Shape | Effect |
|-------|-------|--------|
| `search` | string | Case-insensitive substring match on `type`/`detail`/`src_ip`/`dst_ip`. |
| `type` | string | Exact-match on `type`. |
| `severity` | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` | Exact-match. |
| `min_score` | int 0–100 | Lower bound (inclusive). |
| `delta` | `true` | Only `is_new=true` findings (drift since last analysis). |
| `src_ip` | IP or CIDR | Source matcher. CIDR uses standard notation (`10.0.0.0/8`). |
| `dst_ip` | IP or CIDR | Destination matcher. |
| `dst_port` | int or comma-list | Port set. e.g., `443` or `80,443,8080`. |
| `sensor` | string | Sensor name (matches the per-sensor authorized_keys directory). |
| `from`, `to` | timestamp | Time range. Both `YYYY-MM-DD HH:MM:SS` (UTC) and RFC 3339 accepted. |
| `status` | `open`/`acknowledged`/`escalated` | Status filter. |
| `ioc_only` | `true` | Only findings whose `src_ip` or `dst_ip` is in the IOC list. |
| `sort` | `score`/`severity`/`type`/`src_ip`/`dst_ip`/`timestamp` | Sort key (default `score`). |
| `dir` | `asc`/`desc` | Sort direction (default `desc`). |
| `limit` | int 1–50000 | Max rows in the response. Default `1000`. |
| `offset` | int ≥ 0 | Skip the first N rows of the filtered+sorted set. Default `0`. |

Multiple filters compose freely (AND).

**Pagination response headers** (`GET /api/findings`):

| Header | Value |
|---|---|
| `X-Total-Count` | Total rows matching the filter set (before `limit`/`offset`). |
| `X-Has-More` | `true` if `offset + len(returned) < total`, else `false`. |
| `Access-Control-Expose-Headers` | Lists the two headers above so JS clients in CORS contexts can read them. |

The dashboard uses these to drive the per-tab first / previous / next
/ last navigation buttons and the "Showing X–Y of Z · Page N of M"
footer. Findings, Acknowledged, Escalated, and IOC tabs paginate
server-side via this endpoint; Campaigns and Hosts paginate client-
side over a separate full-set fetch.

**`PUT /api/findings/{id}` body**:

```json
{
  "status":       "acknowledged",
  "analyst_note": "Confirmed legit — internal monitoring tool."
}
```

Either field optional. The handler stamps `analyst` and `status_ts`
from the session.

**`POST /api/findings/{id}/escalate` body**:

```json
{
  "services": ["vt", "otx", "abuseipdb", "greynoise", "censys", "crowdsec"]
}
```

Returns `202 Accepted` and streams results over SSE as `ti_result`
events terminated by a `ti_done`. Service availability depends on
configured API keys (see `/api/ti/services`).

### Configuration

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/config` | any | Returns the full `Config` struct (`internal/config/config.go`). |
| `PUT` | `/api/config` | admin | Replaces the config. Send the full struct (partial updates not supported). |

Config field names are documented in `internal/config/config.go`'s
struct tags. The four most operator-touched fields:

| Field | Purpose |
|-------|---------|
| `timezone` | IANA name, e.g. `America/New_York`. Empty = UTC. Used by watch scheduler and off-hours detector. |
| `off_hours_start` / `off_hours_end` | Hour-of-day bounds for off-hours detection, interpreted in `timezone`. |
| `watch_enabled`, `watch_time`, `watch_interval_hours` | See `/api/watch` for the dedicated endpoint that wraps these. |
| `archive_enabled`, `archive_after_days` | Log archive policy. |

### Lists

Operator-curated allow/deny/IOC slices. Stored in `/data/archer.db`,
preserve insertion order, support `# comment` lines.

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/allowlist` | any | Returns `{"entries": ["1.2.3.4", "# infrastructure", "10.0.0.0/8", …]}`. |
| `PUT` | `/api/allowlist` | analyst+ | Body `{"entries": [...]}`. Replaces the full list. |
| `GET` | `/api/ioc` | any | Same shape as allowlist. |
| `PUT` | `/api/ioc` | analyst+ | Same shape. |
| `GET` | `/api/suppressions` | any | List active suppressions (per-finding-fingerprint mutes). |
| `POST` | `/api/suppressions` | analyst+ | Suppress a finding fingerprint. |
| `DELETE` | `/api/suppressions/{id}` | analyst+ | Lift a suppression. |

`#` lines are preserved verbatim through the round-trip. Inline
`value # tail` comments have their tail stripped. See
`internal/store/store.go`'s `sanitizeListEntries` for the exact
behavior.

### Operations

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/watch` | any | Watch state + computed `next_run`/`next_full_run` previews. |
| `POST` | `/api/watch` | admin | Update watch schedule. Body: `{"time","enabled","timezone","interval_hours"}`. |
| `GET` | `/api/archive` | any | Archive policy + last-run telemetry. |
| `POST` | `/api/archive` | admin | Update archive policy. |
| `POST` | `/api/archive/run` | admin | Run archive synchronously. |
| `POST` | `/api/archive/scan` | admin | Re-scan `/data/archive` against current IOC list + TI feeds. |
| `GET` | `/api/disk-usage` | any | `/logs` + `/data/archive` sizes, free space. 5-minute server-side cache. |
| `GET` | `/api/notifications` | any | List + dismiss UI notifications. |

**`GET /api/watch`** sample response:

```json
{
  "time":           "02:00",
  "enabled":        true,
  "timezone":       "America/New_York",
  "interval_hours": 4,
  "timezone_abbr":  "EST",
  "next_run":       "Today 02:00",
  "next_run_kind":  "incremental",
  "next_full_run":  "Tomorrow 02:00"
}
```

`timezone_abbr`, `next_run`, `next_run_kind`, `next_full_run` are only
present when `enabled=true` and `time` is set.

`interval_hours` accepts `0` / `1` / `4` / `6` / `12` / `24`. `0` and
`24` both mean "once daily at `time`". Values outside that set are
silently clamped to `0`.

### Analysis pipeline

Manual control over the analyzer (separate from watch-mode auto-runs).

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `POST` | `/api/analyze` | analyst+ | Kick off a full analysis pass. |
| `GET` | `/api/analyze/status` | any | Current pipeline state: `idle` / `running` / `paused` + progress %. |
| `POST` | `/api/analyze/cancel` | analyst+ | Stop the running pipeline. |
| `POST` | `/api/analyze/pause` | analyst+ | Pause; resume with the next call. |
| `POST` | `/api/analyze/resume` | analyst+ | Resume a paused pipeline. |
| `POST` | `/api/analyze/reset` | admin | Discard findings and re-analyze (full pass). |

Progress events stream over SSE as `progress` events with
`{step, pct}` payloads.

### Files

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/files` | any | List files in `/logs` (size, mtime, sensor). |
| `GET` | `/api/logs/scan` | any | Trigger a re-scan of `/logs` (no analysis). |
| `POST` | `/api/files/clear` | analyst+ | Remove processed files. |

### Users

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/me` | any | Current session user (id, email, role, status). |
| `GET` | `/api/users` | any | List users. Non-admin sees only public fields. |
| `GET` | `/api/users/{id}` | admin | Full user record. |
| `PUT` | `/api/users/{id}` | admin | Update role, status (activate pending users). |
| `DELETE` | `/api/users/{id}` | admin | Remove user. |

### Threat intel

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/ti/services` | any | Which third-party services are configured. Returns `{vt: bool, otx: bool, abuseipdb: bool, greynoise: bool, censys: bool, crowdsec: bool}`. UI uses this to show/hide service checkboxes on the escalate dialog. |

### Threat-intel feeds (MISP / OpenCTI)

CRUD over operator-curated MISP / OpenCTI feed configurations. Read
is open to any authenticated user; mutation is admin-only and
enforced inside each handler. There is intentionally no manual-fetch
endpoint — refreshes are driven by the watch scheduler's pre-full-pass
refresh (`refreshFeedsBeforeFullPass` in `internal/server/watch.go`).

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/feeds` | any | List configured feeds. `api_key` is redacted; the response carries a `has_api_key` boolean instead. Each row also carries `last_fetch_truncated` (bool) — `true` when the most recent fetch hit the adapter's page-walk cap (10k × 100 pages on MISP, 1k × 100 pages on OpenCTI) with the upstream still indicating more data. |
| `POST` | `/api/feeds` | admin | Create a feed. Required body fields: `source_type` (`misp`/`opencti`), `name`, `url` (with scheme), `api_key`, `indicator_aging_days` (≥ 0). Optional: `enabled`, `tls_skip_verify`. |
| `PUT` | `/api/feeds/{id}` | admin | Update a feed. Empty `api_key` keeps the existing value (clearing requires delete + recreate). |
| `DELETE` | `/api/feeds/{id}` | admin | Delete a feed. FK cascade drops its `feed_indicators`. |
| `POST` | `/api/feeds/{id}/refresh` | admin | One-shot fetch + upsert + prune for one feed (60-second cap). Used to verify connectivity right after configuring a feed; backed by the per-row Refresh button in the Feeds dialog. Watch-tick auto-refresh covers the steady-state case. |

Full operator-facing details (architecture, how to wire up MISP /
OpenCTI, what indicator types match, troubleshooting) live in
[`docs/FEEDS.md`](FEEDS.md).

### Sensors (analyst-facing)

These endpoints back the Sensors modal. Read access is `any`; mutation
requires `admin` (enforced inside each handler).

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/sensors` | any | List enrolled sensors + status. |
| `GET` | `/api/sensors/info` | any | Server identity for the install script: TLS fingerprint, hostname, port. |
| `GET` | `/api/sensors/host` | any | Reachable hostname/IP for sensor configuration. |
| `GET` | `/api/sensors/tokens` | any (read) / admin (POST create) | Manage one-time enrollment tokens. |
| `POST` | `/api/sensors/tokens/revoke` | admin | Revoke a token before it's used. |
| `POST` | `/api/sensors/disenroll` | admin | Remove a sensor from `authorized_keys`. |
| `POST` | `/api/sensors/purge` | admin | Disenroll + delete `/logs/<sensor>/`. |
| `POST` | `/api/sensors/schedule` | admin | Set the per-sensor `quiver.sh` cadence (returned to the sensor on next checkin). |
| `GET` | `/api/sensors/unauthorized` | any | List blocked enrollment attempts. |
| `POST` | `/api/sensors/unauthorized/dismiss` | admin | Dismiss an unauthorized-attempt notification. |

### Quiver sensor protocol (sensor-facing)

These three endpoints are the **only** API a Quiver sensor calls. They
do not require a session — sensors are authenticated by the
enrollment token (one-time) and TLS fingerprint pinning thereafter.

The protocol is versioned by the integer constant `QuiverProtocolVersion`
in `internal/server/quiver_protocol.go` (currently `1`). Sensors that
omit `protocol_version` are treated as v1 for one cycle; future minor
bumps may remove that compat.

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/quiver/install.sh` | The Bash installer body. Sensors `curl` this. |
| `POST` | `/api/quiver/enroll` | First-contact enrollment. Body: `{"protocol_version":1, "name":"sensor1", "token":"…", "ssh_pubkey":"…"}`. Response: `{"ok":true, "ssh_port":2222, "tls_fingerprint":"…", "schedule":"…"}`. |
| `POST` | `/api/quiver/checkin` | Periodic check-in (every quiver.sh tick). Body: `{"protocol_version":1, "name":"sensor1"}`. Response: `{"ok":true, "schedule":"…"}` (so cadence changes propagate) or `{"ok":false, "error":"…"}` on rejection. |

**Protocol version mismatch** returns `400 Bad Request` with body:

```json
{
  "error":              "incompatible Quiver protocol version",
  "server_version":     1,
  "supported_versions": [1],
  "client_version":     2
}
```

The structured error lets the sensor self-diagnose. Bumping
`QuiverProtocolVersion` is a breaking change requiring all sensors to
upgrade — flag in CHANGELOG under `### Breaking` and warn operators
to update sensors before the server.

### Export / Import

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/export/json` | any | Full findings dump. Same query params as `/api/findings`. Includes `archer_version` field at the top of the JSON object. |
| `GET` | `/api/export/csv` | any | CSV variant — flattened columns, no `intervals`/`ts_data`/`notes`. |
| `POST` | `/api/import` | analyst+ | Restore from a `/api/export/json` dump. Fingerprint-merges with existing findings: existing-by-fingerprint findings keep their analyst data, new ones land as `is_new=true`. |

### Server-Sent Events

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/events` | any | Long-lived event stream. |

Event types currently published:

| Event | When | Payload |
|-------|------|---------|
| `progress` | During analysis | `{step:"Beaconing", pct:55}` |
| `status` | Worker state changes | `{state:"running"\|"paused"\|"idle"}` |
| `done` | Analysis finishes | `{findings_added:int, duration_ms:int}` |
| `notification` | New CRITICAL/IOC finding | Notification shape (`internal/model/finding.go`). |
| `ti_result` | TI escalation streams a hit | `{finding_id, service, detail, severity}` |
| `ti_done` | TI escalation completes | `{finding_id}` |
| `sensor_enrolled` | New sensor accepts enrollment | `{name, ts}` |
| `unauthorized_attempt` | Bad token / unknown key blocked | `{ip, name_attempted, ts}` |

The SSE broker is at-most-once and does not replay. A reconnecting
client will miss events that fired during the disconnect; for state
that needs to survive reconnect (notifications, watch state), poll
the corresponding REST endpoint after reconnecting.

---

## Where to look in the code

- Route table: `internal/server/server.go` — `routes()` (line ~102).
- Handlers: `internal/server/handlers_api.go`, `handlers_quiver.go`,
  `handlers_sensors.go`, `handlers_sse.go`, `handlers_ui.go`.
- Auth + middleware: `auth.go`, `middleware.go`.
- Model shapes: `internal/model/{finding,user}.go`.
- Config shape: `internal/config/config.go`.
- Quiver protocol constant: `internal/server/quiver_protocol.go`.

Field-level changes show up in `git log -p internal/model/`,
`git log -p internal/config/config.go`, or
`git log -p internal/server/handlers_*.go` depending on which surface
moved.
