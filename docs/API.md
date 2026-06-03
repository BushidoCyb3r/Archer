# Archer HTTP API reference

This document is the contract for Archer's HTTP/SSE surface. It enumerates
every endpoint registered in `internal/server/server.go`'s `routes()`,
their authentication/role requirements, request shapes, and response
shapes. **Pre-1.0:** any field documented here may break between minor
versions, but a breaking change is announced explicitly in CHANGELOG —
see *Breaking-change surfaces* and *Deprecation policy* below.

> Phase 6 deliverable. Phase 7 (TI feed integration) shipped in
> v0.5.0 and added the CRUD endpoints under `/api/feeds/*`; their
> shapes and roles are documented in `docs/FEEDS.md`. The per-feed
> manual-fetch endpoint `POST /api/feeds/{id}/refresh` (10-minute
> hard cap, v0.19.0+) lives alongside the watch-tick pre-full-pass
> refresh so admins can verify a freshly-configured feed without
> waiting for the next watch tick.

---

## Conventions

### Listeners and ports

Archer runs a single TLS listener:

- **HTTPS on `:8443`** — the only listener. UI, analyst API, and
  Quiver sensor surface (`/api/quiver/*`, `/quiver/install.sh`) all
  served here. TLS cert auto-generated at
  `/data/tls/server.{crt,key}`. Sensors pin the cert by SHA-256
  fingerprint (`/api/sensors/info` exposes the fingerprint); browsers
  validate the chain (operator drops in a CA-signed cert per
  OPERATIONS.md for production). v0.14.5 NEW-49 removed the
  pre-existing plaintext `:8080` listener that had been carrying admin
  credentials in cleartext.

### Authentication

Every route except the explicitly-public ones below requires a session
cookie set by `POST /login`. The cookie is `HttpOnly`,
`SameSite=Strict`, and `Secure` (always — v0.14.5). Sessions are
persisted in `/data/users.db`'s `sessions` table.

As a CSRF defense-in-depth layer behind that `SameSite=Strict` cookie
(v0.55.0): an authenticated state-changing request
(`POST`/`PUT`/`PATCH`/`DELETE`) whose `Origin` — or, absent that,
`Referer` — host doesn't match the request host is rejected with
`403 {"error":"cross-origin request blocked"}`. A request carrying
neither header is allowed, so non-browser session clients are
unaffected.

**Public (no session)**:
- `GET /api/version`
- `POST /login`, `POST /register`, `POST /logout`
- `GET /quiver/install.sh`
- `POST /api/quiver/enroll`, `POST /api/quiver/checkin`
- `GET /static/*`

**Machine-to-machine (`X-Archer-Token`)**:
`GET /api/sensors/health` additionally accepts a service-account token
via an `X-Archer-Token: archer_<value>` request header. If the header
is present and the token is invalid, the request is rejected with `401`
immediately (the session path is not attempted). A failed token also
charges the per-IP rate-limit bucket (the same one login/enroll/checkin
use), so a bogus-token flood on this unauthenticated path returns `429`
once the bucket is exhausted; a valid token is never limited (v0.55.0).
Tokens are admin-generated on `/api/service-tokens` and stored only as
their SHA-256 hash. This is the intended path for Prometheus textfile
collector, Nagios checks, and similar scrape tooling.

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
- `403 Forbidden` — authenticated but role insufficient, or a
  cross-origin state-changing request (see Authentication).
- `404 Not Found` — finding ID doesn't exist, sensor name unknown,
  user ID unknown.
- `405 Method Not Allowed` — HTTP method not supported on this route.
- `409 Conflict` — duplicate (e.g., sensor name already enrolled).
- `429 Too Many Requests` — per-IP rate limit exceeded (login,
  register, Quiver enroll/checkin, and failed `X-Archer-Token`).
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
`sensor_enrolled`, `unauthorized_attempt`, and `watch.heartbeat`.

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
| `POST` | `/login` | (public) | Sets session cookie. **Form-encoded** body (the HTML form on `/login` submits this directly): `email`, `password`. Both routes serve `text/html` for `GET` and process the form on `POST`. |
| `POST` | `/register` | (public) | First user becomes admin and is signed in; subsequent users land in `pending` and need admin approval before login works. **Form-encoded** body: `first_name`, `last_name`, `email`, `password`, `confirm`. |
| `POST` | `/logout` | any | Invalidates current session and clears the cookie. |

See `internal/server/auth.go` for the exact bcrypt cost, session TTL,
and rate-limit details.

### Diagnostic

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/version` | (public) | Build identity. |

**Response** (`200 OK`):
```json
{
  "version":    "v0.55.0",
  "commit":     "2b61c7a",
  "build_time": "2026-06-03T18:30:00Z"
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
| `GET` | `/api/findings/unseen` | any | Per-session new-findings count: `{count, total, since, seen_count}`. `count` is findings first detected (`detected_at`) after the analyst's session boundary (`since`, the start of their previous login), roll-ups excluded; `total` is the dataset size; `seen_count` is the session's modal high-water. Drives the login / analysis-complete modal — the client pops it only when `count > seen_count`, so a page refresh doesn't re-announce. Same boundary the `delta=true` "New only" filter uses. |
| `POST` | `/api/findings/modal-ack` | any | Records that the new-findings modal was shown for this session (raises the high-water to the current unseen count, server-recomputed). Suppresses re-pop on refresh until the count climbs higher or a fresh login starts a new session. Returns `{seen_count}`. Leaves the login boundary and "New only" filter untouched. |
| `GET` | `/api/findings/{id}` | any | Single finding (full shape including `ts_data`/`intervals`/`notes`). |
| `PATCH` | `/api/findings/{id}` | analyst+ | Update status / append analyst-attributed note. |
| `POST` | `/api/findings/{id}/escalate` | analyst+ | Run TI escalation; emits `ti_result` SSE events. |
| `POST` | `/api/findings/{id}/notes` | analyst+ | Append a note to the finding. |
| `GET` | `/api/findings/{id}/raw` | any | Raw-log pivot — the Zeek lines that produced this finding. |
| `GET` | `/api/findings/{id}/position` | any | Absolute zero-indexed position of finding `{id}` within `/api/findings` under the same filter + sort query parameters. Returns `{found: bool, offset: N, total: M}` (200) or `{found: false, total: M}` (404) when the finding does not match. The bell-notification **Jump** action uses this to navigate to the page containing the target finding regardless of the analyst's current pagination offset. |
| `GET` | `/api/findings/{id}/history` | any | 30-day beacon score evolution rows for Beacon / HTTP Beacon findings. Returns `[]` (not 404) for other finding types so the SPA can call unconditionally. See `BeaconHistoryRow` shape below. |

**Finding shape** (`model.Finding`, `internal/model/finding.go:23`):

```json
{
  "id":           42,
  "type":         "Beacon",
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
  "detected_at":  1748557200,
  "is_new_to_me": true,
  "sensor":       "sensor1",
  "hostname":     "kx9j3qm2pflw.com",
  "uri":          "/heartbeat",
  "correlations": [57, 91],
  "intervals":    [60.0, 60.0, 60.0],
  "ts_data":      [[1705320000, 500, 2000], …],
  "notes":        [],
  "ts_score":        0.92,
  "ds_score":        0.81,
  "hist_score":      0.75,
  "dur_score":       0.88,
  "mean_interval":   60.0,
  "median_interval": 60.0,
  "jitter":          0.05,
  "sample_size":     312,
  "ja3":             "771,4865-4866-49195",
  "ja4":             "t13d1516h2_8daaf6152771_b0da82dd1658",
  "ja3_sibling_count": 4,
  "fp_concern":        "critical",
  "fp_detail":         "rare — shared by 3 internal hosts · 43 conns, 1 dst(s)",
  "top_uris": [{"uri": "/poll", "count": 312}, {"uri": "/cmd", "count": 18}]
}
```

- `severity` is one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `is_new` is the volatile per-run flag — true only for fingerprints freshly
  emitted by the most recent analysis, reset to false the next run. It is
  still serialized but no UI surface keys off it any more. Don't use it for
  "what's new since I last looked"; that's `is_new_to_me` / `detected_at` +
  the session boundary (see `delta` below and `/api/findings/unseen`).
- `detected_at` (epoch seconds, `omitempty`) is the stable time the
  fingerprint first entered the store. Assigned once on first insert and
  carried forward unchanged on every re-analysis (like the `id`), so it
  survives the hourly watch passes the `is_new` flag does not. Backs the
  new-findings modal, the "New only" filter, and `is_new_to_me` (migration
  0029).
- `is_new_to_me` is a **transient, derived-at-read** bool — `detected_at`
  is after the requesting session's new-findings boundary (the start of the
  analyst's previous login). Computed by both the list and single-finding
  handlers (never persisted), `omitempty`. It is what the table's blue "new"
  dot and the detail pane's "NEW SINCE LAST LOGIN" badge key off, so they
  agree with the "New only" filter and the modal — all four use the same
  boundary. Per-viewer: the same finding can be `is_new_to_me` for one
  analyst and not another.
- `tls_allowlisted` is a **transient, derived-at-read** bool (`omitempty`) —
  true when the finding's `ja3`/`ja4` client fingerprint has been marked
  benign via `/api/fingerprint-allowlist`. A hint only: it drives the table's
  `fp benign` chip; the finding is **not** hidden or dismissed (unlike the
  pair/IP allowlist, which filter the row out). Clears as soon as the benign
  mark is removed.
- `status` is `""` (open), `acknowledged`, `escalated`, or `dismissed`.
  Dismissed is a lightweight reversible view-state bucket — see
  the **Dismissed status** note under **`GET /api/findings`
  query parameters** below.
- `intervals`, `ts_data`, `notes`, `sensor`, `hostname`, `uri`,
  `correlations` are `omitempty` — expect their absence on findings
  that don't carry that data.
- `hostname` is populated for Beacon (from TLS SNI) and HTTP
  Beacon (from the `Host` header). Consumed by the DGA scoring
  pass and surfaced in the finding-detail pane.
- `uri` is populated for HTTP Beacon (the request path that
  participated in the grouping key).
- `correlations` is the list of sibling finding IDs that share this
  finding's `(src_ip, dst_ip)` pair and contributed to a Correlated
  Activity roll-up. The SPA renders a `+N corr` chip when non-empty.
- `ts_data` rows are `[ts_unix, orig_bytes, resp_bytes]` triples used
  for the beacon chart on the analyst UI.
- `ts_score` / `ds_score` / `hist_score` / `dur_score` are the four
  per-axis beacon sub-scores (each `[0,1]`; the total is their sum ×
  25). `mean_interval` / `median_interval` are the inter-arrival mean
  and median in seconds; `jitter` is their coefficient of variation
  (the "± Ns" spread the triage header renders as a percentage);
  `sample_size` is the observation count the score rests on. All eight
  are `omitempty`, populated only for `Beacon`, `HTTP Beacon`,
  and `DNS Beacon` (which leaves `ds_score` zero — DNS has no
  data-size axis). Persisted as columns (migration 0018) so they
  survive a restart and the carry-forward. They are part of the
  **full** single-finding shape only — the projected list endpoint
  does not include them (next bullet).
- `ja3` / `ja4` are the TLS client fingerprints of the connection that
  seeded a conn-level `Beacon` finding, lifted at emit time from
  `sslUIDIndex` (the same lookup that resolves `hostname` from the
  SNI). Empty for non-TLS beacons, HTTP Beacon (cleartext by
  construction), DNS Beacon, and every non-beacon type. `ja4` is
  empty unless the sensor's Zeek emits a `ja4` field (stock `ssl.log`
  is ja3/ja3s — JA4 needs the JA4+ plugin). Persisted as columns
  (migration 0019) so they survive a restart and the carry-forward.
- `ja3_sibling_count` / `ja4_sibling_count` are **transient,
  derived-at-read** fields — the number of *other* beacon findings in
  the current dataset sharing this `ja3` or `ja4` respectively.
  Computed by the single-finding detail handler only (never persisted,
  excluded from the list projection and exports). Both are `omitempty`;
  an absent value reads correctly as "matched 0 other beacons." Filter
  to those siblings with the `ja3` or `ja4` query params respectively.
- `fp_concern` / `fp_detail` are **transient, derived-at-read** fields
  on conn-level `Beacon` findings carrying a `ja3` or `ja4`. The
  single-finding handler resolves the seed fingerprint against the
  corpus-wide TLS prevalence snapshot (`SetFingerprintPrevalence`, pushed
  after each full pass) into a severity-style concern level
  (`critical`/`high`/`medium`/`low`/`none`) and a one-line summary. The
  SPA colours the detail-pane **FP rarity** row by `fp_concern` (the same
  palette as severity: critical→red … low→green, none→white). Unlike the
  sibling counts — emitted-beacon-only — this sees rarity and sub-floor
  siblings across *all* TLS. **Enrichment only — never alters score or
  severity.** Both `omitempty`; absent when no fingerprint resolves or no
  full pass has run this process. Never persisted, excluded from the list
  projection and exports.
- `top_uris` is the HTTP Beacon destination's request-path
  footprint: `[]{uri, count}`, count-descending, capped at 8. The
  `(Type,src,dst,port)` fingerprint dedup keeps one finding per group,
  so this is aggregated pre-dedup over the `(sensor,src,dst,host)`
  beacon keys and stamped identically on every finding in the group —
  whichever survives the dedup carries the whole footprint. Empty for
  every non-HTTP-Beacon type. Persisted as a JSON column (migration
  0020) for the same restart / carry-forward reason.
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
| `q` | query-language string | The Lucene-style findings query language (v0.48.0) — the primary filter surface. Field terms (`id:`, `type:`, `severity:`, `score:`, `src:`/`dst:` IP or CIDR, `dir:` traffic direction (`outbound`/`inbound`/`internal`/`external`, computed from the RFC1918 boundary; alias `direction`), `port:`, `detail:`, `hostname:`, `uri:` (HTTP Beacon request path), `note:` (analyst note; alias `analyst_note`), `analyst:`, `sensor:`, `status:`, `ts:` (event time), `detected:` (first-detected time, from the `detected_at` epoch column; alias `detected_at`), `ioc:`, `spectral:`, `ja3:`/`ja4:`, `file:`, the beacon sub-scores `tscore:`/`dscore:`/`hist:`/`dur:`, and the beacon timing/volume metrics `conns:`/`meanint:`/`medint:`/`jitter:`), boolean `AND`/`OR`/`NOT` with `()` grouping (an explicit operator is required between adjacent terms — `type:Beacon AND severity:high`, not `type:Beacon severity:high`, which is a parse error), leading/trailing `*`/`?` wildcards on string fields, numeric comparisons (`>=` `<=` `>` `<` `=`) and `[lo TO hi]` ranges, date/datetime literals interpreted in the operator timezone, and quoted phrases. A bare term is a case-insensitive substring match over `type`/`src_ip`/`dst_ip`/`dst_port`/`detail`/`timestamp`/`severity` (a bare IP literal matches src or dst exactly). ANDed on top of every other param and the view scoping. A malformed query returns **`400`** with a JSON `{"error"}` body carrying the parse error — never match-all or match-none. Rejected cases include malformed syntax, an unknown field (`dest:` → there's no such field), and an exact `type:` value that isn't a real finding type (`type:Beaon`); the `type:beacons` family selector still matches the beacon family, but a misspelled exact type errors instead of silently matching nothing (v0.51.0). Grammar in `internal/query`; analyst reference in `docs/ANALYST_PLAYBOOK.md`. The legacy single-field params below remain for back-compat and the export flow. |
| `search` | string | Case-insensitive substring match on `type`/`detail`/`src_ip`/`dst_ip`. |
| `type` | string | Exact-match on `type`. The pseudo-value `beacons` matches the whole beacon family (`Beacon` / `HTTP Beacon` / `DNS Beacon`) in one selector — drives the beacon export target and the all-beacons Findings filter. |
| `severity` | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` | Exact-match. |
| `min_score` | int 0–100 | Lower bound (inclusive). |
| `delta` | `true` | Only findings first detected (`detected_at`) since the requesting analyst's session boundary — "new since you last logged in." Same cutoff as `/api/findings/unseen`; user/session-dependent. (Pre-v0.45.0 this filtered `is_new=true` — new since the last run.) |
| `src_ip` | IP or CIDR | Source matcher. CIDR uses standard notation (`10.0.0.0/8`). |
| `dst_ip` | IP or CIDR | Destination matcher. |
| `dst_port` | int or comma-list | Port set. e.g., `443` or `80,443,8080`. |
| `sensor` | string | Sensor name (matches the per-sensor authorized_keys directory). |
| `from`, `to` | timestamp | Time range. Both `YYYY-MM-DD HH:MM:SS` (UTC) and RFC 3339 accepted. |
| `status` | `open`/`acknowledged`/`escalated`/`dismissed` | Status filter. |
| `ioc_only` | `true` | Only findings whose `src_ip` or `dst_ip` is in the IOC list. |
| `include_dismissed` | `true` | Counts-style flag for callers that want dismissed findings included in an otherwise-unscoped result. Has no effect when `status` is explicitly set. Default behavior (omitted or `false`): if no `status` filter is provided, dismissed findings are excluded — the "I don't want to see this again" semantic carries through every non-Dismissed tab. Used internally by `/api/findings/counts` to bucket dismissed separately. |
| `spectral_only` | `true` | Only Beacon findings whose timing score was rescued by the spectral path. Matches on the `Spectral rescued:` substring in the Detail field. Useful during spectral-tuning calibration — see `docs/SPECTRAL_TUNING.md`. |
| `ts_min`/`ts_max`, `ds_min`/`ds_max`, `hist_min`/`hist_max`, `dur_min`/`dur_max` | float `[0,1]` | Inclusive bound on one beacon sub-axis (timing / data-size / hour-coverage / duration). Either bound of a pair may be omitted; a non-numeric value disables that one axis rather than blanking the filter. **Setting any sub-score bound implicitly scopes the result to beacon types** (`Beacon`/`HTTP Beacon`/`DNS Beacon`) — a bare upper bound like `dur_max=0.3` would otherwise surface every non-beacon, whose sub-scores are a structural `0 ≤ 0.3`. Lets a hunter query a beacon *signature* the composite score averages away (e.g. `ts_min=0.8&dur_max=0.3` = short-lived tight-cadence spikes). DNS Beacon leaves `ds_score` a structural zero, so a `ds_min>0` filter correctly excludes it. |
| `ja3` | string | Exact JA3 client-fingerprint match (case-insensitive — stored lowercased at emit). Powers **TLS Pivot** for sensors on stock Zeek (no JA4+ plugin). Filters to every finding carrying that JA3 so one beacon unravels the whole implant family. |
| `ja4` | string | Exact JA4 client-fingerprint match (case-insensitive — stored lowercased at emit). Powers **TLS Pivot** for sensors running the Zeek JA4+ plugin. Independent of `ja3`; both filters may be set simultaneously (AND). |
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

**`PATCH /api/findings/{id}` body**:

```json
{
  "status": "acknowledged",
  "note":   "Confirmed legit — internal monitoring tool."
}
```

Either field optional. The handler stamps `analyst` and `status_ts`
from the session. `status` is validated against the enum — `""`
(open), `acknowledged`, `escalated`, `dismissed` — anything else
gets `400 Bad Request` (v0.14.3 NEW-37).

**`POST /api/findings/{id}/escalate` body**:

```json
{
  "note":     "Suspected C2 to no-reputation IP from finance workstation.",
  "ips":      ["192.0.2.10"],
  "services": ["vt", "otx", "abuseipdb", "greynoise", "censys", "crowdsec"]
}
```

All three fields optional; `services` must be non-empty for any TI
lookup to fire. The handler escalates the finding (status →
`escalated`) regardless of whether services are queried. Each
`service` runs as a background goroutine and streams a `ti_result`
SSE event when done; a final `ti_done` event closes the burst.

Returns `202 Accepted` and streams results over SSE as `ti_result`
events terminated by a `ti_done`. Service availability depends on
configured API keys (see `/api/ti/services`).

**`GET /api/findings/{id}/history` response** — array of
`BeaconHistoryRow`:

```json
[
  {
    "day_utc":           "2026-04-12",
    "max_score":         88,
    "max_score_at":      1712923200,
    "last_score":        62,
    "last_score_at":     1712944800,
    "severity":          "CRITICAL",
    "ts_score":          0.93,
    "ds_score":          0.92,
    "hist_score":        0.30,
    "dur_score":         0.78,
    "spectral_rescued":  1,
    "spectral_period":   3600.0
  },
  {
    "day_utc":           "2026-04-13",
    "max_score":         78,
    "max_score_at":      1713009600,
    "last_score":        78,
    "last_score_at":     1713009600,
    "severity":          "HIGH",
    "ts_score":          0.94,
    "ds_score":          0.92,
    "hist_score":        0.20,
    "dur_score":         0.78,
    "spectral_rescued":  0,
    "spectral_period":   0
  }
]
```

Sorted ascending by `day_utc`. Up to 30 rows per beacon (retention
window).

- `max_score` (0-100) is the highest composite score observed for
  this beacon on that UTC day across every analyze pass that ran.
  `max_score_at` is its Unix-second timestamp. The SPA's evolution
  chart renders `max_score` — the spike is the trajectory-meaningful
  number.
- `last_score` (0-100) is the most recent composite score written
  for this beacon on that UTC day. `last_score_at` is its Unix-second
  timestamp. Exposed for forensic / per-pass detail; not rendered on
  the v1 chart.
- `ts_score / ds_score / hist_score / dur_score` are the four
  per-axis sub-scores (each in `[0, 1]`) that composed the
  *max-score* write — so an analyst inspecting a high-score day
  sees the sub-axis breakdown that drove the high.
- `severity` matches the max-score write.
- `spectral_rescued` is `1` when the Lomb-Scargle periodogram rescued
  this beacon on this day (i.e., the `ts_score` was below the spectral
  rescue threshold on the raw Bowley/MAD path but the periodogram found
  a strong peak). `0` otherwise. Pre-migration-0023 rows and
  non-spectral beacons read back as `0`. The evolution chart marks
  rescued days so analysts can see which days relied on spectral
  detection. Migration 0023.
- `spectral_period` is the dominant period (seconds) the periodogram
  identified on a rescued day. `0` when the period wasn't resolved or
  the day wasn't spectral-rescued. Migration 0023.

Rows are written by `Store.SetFindings` via
`INSERT … ON CONFLICT DO UPDATE`: max_* updates conditionally when
the new score exceeds the existing max; last_* always updates.
This captures mid-day score shifts that pre-v0.16.1's
`DO NOTHING` semantics silently dropped — see CHANGELOG v0.16.1
NEW-76. The endpoint returns `[]` for finding types other than
Beacon / HTTP Beacon.

### Configuration

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/config` | any | Returns the `Config` struct (`internal/config/config.go`). **Admin** gets it verbatim. **Non-admin** (analyst/viewer) gets the credential fields (`otx_api_key`, `abuseipdb_api_key`, `virustotal_api_key`, `crowdsec_api_key`, `greynoise_api_key`, `censys_api_id`, `censys_api_secret`) blanked to `""`, each with a companion `<field>_configured` boolean — same redaction shape as the feeds `has_api_key` pattern. All non-secret fields are identical across roles. |
| `PUT` | `/api/config` | admin | Replaces the config. Send the full struct (partial updates not supported). Admin GET returns real secrets, so the admin Settings dialog round-trips them unchanged. |

Config field names are documented in `internal/config/config.go`'s
struct tags. The four most operator-touched fields:

| Field | Purpose |
|-------|---------|
| `timezone` | IANA name, e.g. `America/New_York`. Empty = UTC. Used by watch scheduler and off-hours detector. |
| `off_hours_start` / `off_hours_end` | Hour-of-day bounds for off-hours detection, interpreted in `timezone`. |
| `watch_enabled`, `watch_time`, `watch_interval_hours` | See `/api/watch` for the dedicated endpoint that wraps these. |
| `archive_enabled`, `archive_after_days` | Log archive policy. |
| `sensor_stale_threshold_hours` | How long a sensor must be silent (no HMAC checkin) before the heartbeat alarm fires. Default `2`. |
| `feed_stale_threshold_hours` | How long since a feed's last successful fetch before the feed-health alarm fires. Default `24`. |
| `rsync_stale_threshold_hours` | How long the gap between `last_seen_at` and `last_log_mtime` must be before the rsync-dead alarm fires. Default `4`. |

### Lists

Operator-curated allow/deny/IOC slices. Stored in `/data/archer.db`,
preserve insertion order, support `# comment` lines.

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/allowlist` | any | Returns a bare JSON array of strings — `["1.2.3.4", "# infrastructure", "10.0.0.0/8", …]`. |
| `PUT` | `/api/allowlist` | analyst+ | Bare JSON array body `["1.2.3.4", ...]`. Replaces the full list. |
| `GET` | `/api/ioc` | any | Same shape as allowlist (bare string array). |
| `PUT` | `/api/ioc` | analyst+ | Same shape (bare string array). |
| `GET` | `/api/suppressions` | any | Returns an array of `{target, expiry, detail}` objects. |
| `POST` | `/api/suppressions` | analyst+ | Add a suppression. Body: `{"target":"<ip/domain/regex>","days":N,"detail":"<reason>"}`. `days` must be in `(0, 365]`. |
| `DELETE` | `/api/suppressions/{target}` | analyst+ | Lift a suppression. The `{target}` segment is the URL-encoded target string from the GET response (host / IP / regex / sensor) — not a numeric id. |
| `GET` | `/api/pair-allowlist` | any | Returns an array of `{id, src, dst, port, finding_type, detail, created_by, created_at}` rules. |
| `POST` | `/api/pair-allowlist` | analyst+ | Add a tuple-scoped permanent finding filter. Body: `{"src","dst","port","finding_type","detail"}`. `src` and `dst` required; empty `finding_type` = every type on the tuple, set = only that type. Idempotent on the `(src,dst,port,finding_type)` tuple (re-adding returns the existing id). Pure view filter — matching findings are hidden from the table and bell, never dropped from the store. |
| `DELETE` | `/api/pair-allowlist/{id}` | analyst+ | Remove a rule by numeric id. Its matching findings reappear on the next `/api/findings` fetch — no re-analysis. |
| `GET` | `/api/pair-allowlist/suggested` | any | Returns beacon pairs that qualify for allowlist suggestion: 14+ distinct UTC days in `beacon_history` AND an acknowledged finding for that pair AND not already covered by a pair\_allowlist rule. Array of `{src_ip, dst_ip, dst_port, finding_type, day_count, first_seen, last_seen, peak_score, acked_by}`. Empty array when no candidates exist. Read-only; applying a suggestion uses `POST /api/pair-allowlist`. |
| `GET` | `/api/fingerprint-allowlist` | any | Returns an array of `{id, kind, fingerprint, note, created_by, created_at}` — TLS client fingerprints (`kind` is `ja3` or `ja4`) marked benign on the TLS Fingerprints wall. |
| `POST` | `/api/fingerprint-allowlist` | analyst+ | Mark a fingerprint benign. Body: `{"kind":"ja3"\|"ja4","fingerprint","note"}`. Idempotent on `(kind, fingerprint)`. Rejects (`400`) a known-bad C2 fingerprint — a confirmed C2 match can't be muted. Pure view filter: the fingerprint drops out of `/api/fingerprints` and matching findings carry `tls_allowlisted:true`, never dropped from the store. |
| `DELETE` | `/api/fingerprint-allowlist/{id}` | analyst+ | Remove a benign mark by numeric id. The fingerprint returns to `/api/fingerprints` and the `tls_allowlisted` flag clears on the next fetch — no re-analysis. |

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
| `POST` | `/api/analyze` | analyst+ | Kick off a full analysis pass over `/logs`. **No body** — pre-v0.14.8 the handler accepted a `{config}` body that silently mutated the analyzer config without going through the admin gate or the audit log; that path was removed in v0.14.8 NEW-60. Config changes go through `PUT /api/config` (admin-only, audited). The pre-v0.7.0 `files` field is also ignored. Returns `{"error":"no logs found in /logs"}` when the tree is empty. |
| `GET` | `/api/analyze/status` | any | Current pipeline state: `idle` / `running` / `paused` + progress %. |
| `POST` | `/api/analyze/cancel` | analyst+ | Stop the running pipeline. |
| `POST` | `/api/analyze/pause` | analyst+ | Pause; resume with the next call. |
| `POST` | `/api/analyze/resume` | analyst+ | Resume a paused pipeline. |
| `POST` | `/api/analyze/reset` | admin | Discard findings and re-analyze (full pass). |

Progress events stream over SSE as `progress` events with
`{step, pct}` payloads.

All five state-mutating endpoints emit an audit row on the success
path (v0.14.9 NEW-65): `analyze_start`, `analyze_cancel`,
`analyze_pause`, `analyze_resume`, `analyze_reset`. Watch-driven
runs call the same internal pipeline but bypass these handlers, so
they remain unattributed by design — the audit row exists to record
operator-initiated invocations, not scheduler ticks.

### Logs

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/logs/tree` | any | Sensor → date roll-up of `/logs`. Returns `{logs_dir, sensors[]}` where each sensor carries `{name, total_files, total_size_bytes, dates[]}` and each date `{date, files, size_bytes, newest_mtime}`. Drives the sidebar logs preview tree. |

### Users

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/me` | any | Current session user — `{id, email, first_name, last_name, role, status}`. |
| `POST` | `/api/me/password` | any | Change your own password. Body: `{"current_password","new_password","confirm"}`. `current_password` is re-verified (403 if wrong); `new_password` must be ≥ 8 chars and match `confirm` (400 otherwise). On success every session for the user is invalidated and a fresh session cookie is set on the response, so other live sessions die but this client stays logged in. |
| `GET` | `/api/users` | any | Admin gets the full user list; any other role gets a one-entry list containing only themselves. |
| `POST` | `/api/users` | admin | Create a user. Body: `{"email","first_name","last_name","password","role"}`. Returns the created user object (`id`, `email`, `first_name`, `last_name`, `role`, `status`). `password` must be ≥ 8 chars; `role` defaults to `analyst` if missing/invalid. The `password_hash` field is not included in any user response. |
| `PATCH` | `/api/users/{id}` | admin | Update role / status (activate pending users), or reset the user's password by sending `{"password":"…"}` (≥ 8 chars). A password reset cannot target your own account (use `/api/me/password`); it drops the target's sessions so they re-authenticate on the new credential. Role/status and password are independent — send whichever fields apply. |
| `DELETE` | `/api/users/{id}` | admin | Remove user. |

### Admin

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/admin/backup` | admin | Streams a consistent `VACUUM INTO` snapshot of `/data/archer.db` as a downloadable file. Response: `Content-Type: application/octet-stream`; `Content-Disposition: attachment; filename="archer-backup-YYYYMMDD-HHMMSS.db"` (UTC). The temp snapshot is removed after the stream completes. Audit-logged as `db_backup` with `size_bytes` and `filename` in Details. v0.18.2+. |
| `GET` | `/api/audit-log` | admin | Cursor-paginated audit-log feed (v0.14.0). Query params: `cursor` (id-exclusive, default `0` = most-recent page) and `count` (default `100`, server-capped at `500`). Response: `{"entries":[…], "total":N, "next":<cursor or 0 if no more>}`. Each entry is one audit row from the `audit_log` table — `id`, `ts`, `actor_id`, `actor_email`, `action`, `target_type`, `target_id`, `target_name`, plus structured `before_value` / `after_value` / `details` JSON blobs. |

### Threat intel

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/ti/services` | any | Which third-party services are configured. Returns `{vt: bool, otx: bool, abuseipdb: bool, greynoise: bool, censys: bool, crowdsec: bool}`. UI uses this to show/hide service checkboxes on the escalate dialog. |

### Threat-intel feeds (MISP / OpenCTI)

CRUD over operator-curated MISP / OpenCTI feed configurations. Read
is open to any authenticated user; mutation and the per-feed manual
refresh are admin-only (enforced inside each handler). Steady-state
refresh is driven by the watch scheduler's pre-full-pass refresh
(`refreshFeedsBeforeFullPass` in `internal/server/watch.go`); the
`POST /api/feeds/{id}/refresh` route is the on-demand verifier
admins use right after configuring a feed.

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/feeds` | any | List configured feeds. `api_key` is redacted; the response carries a `has_api_key` boolean instead. Each row also carries `last_fetch_truncated` (bool) — `true` when the most recent fetch hit the adapter's page-walk cap (10k × 100 pages on MISP, 1k × 100 pages on OpenCTI) with the upstream still indicating more data — and `last_pruned_count` (int) — how many indicators the most recent full refresh aged out. `last_indicator_count` is the post-prune survivor count, so the pre-prune population is `last_pruned_count + last_indicator_count`; the Feeds dialog renders the ratio as a per-feed "% aged out". Stale after an incremental or with aging disabled. |
| `POST` | `/api/feeds` | admin | Create a feed. Required body fields: `source_type` (`misp`/`opencti`), `name`, `url` (with scheme), `api_key`, `indicator_aging_days` (≥ 0). Optional: `enabled`, `tls_skip_verify`, `allow_internal`. `allow_internal=true` (v0.18.5+) opts this feed out of the SSRF guard so URLs targeting loopback / link-local / RFC1918 / IPv6 ULA space are accepted — for internal MISP / OpenCTI deployments. Per-feed scope; other feeds keep the guard. Audit-logged in `feed_create`. |
| `PUT` | `/api/feeds/{id}` | admin | Update a feed. Empty `api_key` keeps the existing value (clearing requires delete + recreate). `allow_internal` is mutable per call and captured in the `feed_update` before/after maps so a later reviewer can prove who opted which feed in. |
| `DELETE` | `/api/feeds/{id}` | admin | Delete a feed. FK cascade drops its `feed_indicators`. |
| `POST` | `/api/feeds/{id}/refresh` | admin | One-shot fetch + upsert + prune for one feed (10-minute hard cap, v0.19.0+). The handler detaches the fetch's context from the inbound HTTP request, so closing the Feeds modal or losing the browser connection mid-fetch doesn't cancel the sync — the goroutine runs to completion and the row's status updates when it's done. Used to verify connectivity right after configuring a feed; backed by the **Refresh** item in the per-row kebab (⋮) menu in the Feeds dialog. Watch-tick auto-refresh covers the steady-state case. |

Full operator-facing details (architecture, how to wire up MISP /
OpenCTI, what indicator types match, troubleshooting) live in
[`docs/FEEDS.md`](FEEDS.md).

### Sensors (analyst-facing)

These endpoints back the Sensors modal. Read of the sensor list +
unauthorized-attempt list + heartbeat state is open to any
authenticated user; everything else (enrollment-token management,
install-script identity, sensor-facing-host override, sensor
mutations) is admin-only (enforced inside each handler).

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/sensors` | any | List sensor rows (any status), most recent enrollment first. Each row carries `protocol_version` — the Quiver wire-protocol version the sensor last reported (enroll or most recent checkin; `0` = unknown, i.e. no checkin since the server was upgraded to record it). |
| `GET` | `/api/sensors/health` | any / `X-Archer-Token` | Per-sensor staleness state: `{sensors:[{name, status, last_seen_at, stale, stale_for_seconds, stale_threshold_sec}]}`. `stale=true` when `last_seen_at` is older than `sensor_stale_threshold_hours` (default 2 h, configurable); `stale_for_seconds` is how far past the threshold. Only enrolled sensors are included. Accepts a session cookie **or** an `X-Archer-Token` header (see *Machine-to-machine* under **Authentication**). |
| `GET` | `/api/sensors/info` | admin | Server identity for the install one-liner — `{tls_fingerprint, sensor_facing_host, effective_host, server_protocol_version, supported_protocol_versions}`. `server_protocol_version` is the Quiver version this server speaks/prefers; `supported_protocol_versions` is the set it still accepts. The Sensors modal compares each enrolled sensor's `protocol_version` against these to render the compatibility matrix. |
| `PUT` | `/api/sensors/host` | admin | Set the sensor-facing host override. Body: `{"host":"<host>"}` (with optional `:port`). |
| `GET` | `/api/sensors/tokens` | admin | List outstanding enrollment tokens. |
| `POST` | `/api/sensors/tokens` | admin | Mint a one-time 24h token. Body: `{"override_name":"<optional>"}`. Returns the full token row including the bearer string. |
| `POST` | `/api/sensors/tokens/revoke` | admin | Revoke a token before it's used. Body: `{"id":N}`. |
| `POST` | `/api/sensors/disenroll` | admin | Flip the sensor row to `disenrolling` and remove its `authorized_keys` line. Body: `{"id":N}`. Sensor self-cleans on next checkin. |
| `POST` | `/api/sensors/purge` | admin | Move `/logs/<sensor>/` to `/_archived/`, retag the sensor's findings, drop the sensor row (only allowed once status is `disenrolled`). Body: `{"id":N}`. |
| `POST` | `/api/sensors/schedule` | admin | Reassign the per-sensor push minute. Body: `{"id":N,"hour":0,"minute":N}`. (Hour is unused under hourly mode but accepted for backward compat.) |
| `GET` | `/api/sensors/unauthorized` | any | List recent unrecognized checkin attempts. |
| `POST` | `/api/sensors/unauthorized/dismiss` | admin | Remove an unauthorized-attempt row. Body: `{"id":N}`. |

### Quiver sensor protocol (sensor-facing)

These three endpoints are the **only** API a Quiver sensor calls. They
do not require a session — sensors are authenticated by the
enrollment token (one-time) and TLS fingerprint pinning thereafter.

The protocol is versioned by the integer constant `QuiverProtocolVersion`
in `internal/server/quiver_protocol.go` (currently `2`). Sensors that
omit `protocol_version` are resolved as v1, which is **no longer
supported** as of v0.12.0 (NEW-16) — the protocol introduced a
per-sensor checkin secret that has no in-band path to retrofit, so
v1 sensors must re-enroll against the v0.12.0+ server to acquire one.

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/quiver/install.sh` | The Bash installer body. Sensors `curl` this; the response embeds the TLS fingerprint, host, ports, and base64-encoded daily + uninstall scripts so the install runs without a second network hop. |
| `POST` | `/api/quiver/enroll` | First-contact enrollment. Body: `{"protocol_version":2, "token":"…", "name":"sensor1", "host":"<fqdn>", "pubkey":"<ssh-ed25519 …>"}`. Response on success: `{"name":"sensor1", "schedule_hour":0, "schedule_minute":N, "protocol_version":2, "checkin_secret":"…"}` — `checkin_secret` is a one-shot value the sensor stores at `/etc/quiver/secret` (mode `0600`) and HMACs into every subsequent checkin; the server never echoes it on any other endpoint (NEW-16). Rate-limited per source IP. |
| `POST` | `/api/quiver/checkin` | Periodic check-in. Body: `{"protocol_version":2, "name":"sensor1"}` plus an **`X-Quiver-Sig`** header carrying `hex(HMAC-SHA256(body, checkin_secret))`. One of four shapes back, each carrying `"protocol_version":2`: `{"status":"enrolled","schedule":{"hour":0,"minute":N}}`, `{"status":"disenrolled"}`, `{"status":"unknown"}`, or `{"status":"protocol_unsupported","sensor_version":N,"server_version":2,"supported_versions":[2]}`. Missing / invalid signatures fall through to the `unknown` bucket and push an SSE `unauthorized_attempt` event. |

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

### Service-account tokens

Admin-only CRUD for machine-to-machine tokens that let external
monitoring tools (Prometheus textfile collector, Nagios, scripts)
authenticate to `GET /api/sensors/health` without a browser session.

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/service-tokens` | admin | List tokens (id, label, created_at, created_by). Raw values are never stored or returned after creation. |
| `POST` | `/api/service-tokens` | admin | Create a token. Body: `{"label":"<name>"}`. Returns `{"id":N, "label":"…", "token":"archer_<base64url>"}` with HTTP 201. The raw token is shown **exactly once** — copy it immediately. |
| `DELETE` | `/api/service-tokens/{id}` | admin | Revoke a token by numeric id. Returns `{"ok":true}` or 404 if not found. |

**`GET /api/service-tokens` response shape** (array):

```json
[
  {
    "id":         1,
    "label":      "nagios-prod",
    "created_at": 1716163200,
    "created_by": "admin@example.com"
  }
]
```

Tokens are 32-byte random values Base64URL-encoded with an `archer_`
prefix, stored only as their SHA-256 hash. Revoking a token takes
effect immediately — the next `GET /api/sensors/health` call using it
returns `401`. Audit-logged as `service_token_create` /
`service_token_revoke`.

### Export / Import

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/api/export/json` | any | Full findings dump. Same query params as `/api/findings`. Includes `archer_version` field at the top of the JSON object. |
| `GET` | `/api/export/csv` | any | CSV variant — flattened columns, no `intervals`/`ts_data`/`notes`. With `type=beacons` the export is scoped to the beacon family and **appends** ten triage columns (`ts_score`…`sample_size`, `ja3`, `ja4`) after the historical 13; appended-not-inserted, so an index-based consumer of the default schema is unaffected. The default (unscoped) export is byte-identical to prior versions. Pair `type=beacons` with the JSON variant for the structured `top_uris` footprint (a nested list doesn't fit a flat CSV cell). |
| `GET` | `/api/export/xlsx` | any | Multi-sheet workbook (xlsx). Six sheets — `Findings` (open), `Acknowledged`, `Escalated`, `IOC Hits`, `Campaigns`, `Hosts` — all driven from the full database, ignoring filters and tab state. Used by the **Export all** button's XLSX option. |
| `POST` | `/api/import` | admin | Restore from a `/api/export/json` dump. Fingerprint-merges with existing findings: existing-by-fingerprint findings keep their analyst data, new ones land as `is_new=true`. Re-assigns IDs in a fresh sequence and translates every `correlations[]` slice through an old→new map so cross-finding references survive the round-trip. |

### Server-Sent Events

| Method | Path | Role | Notes |
|--------|------|------|-------|
| `GET` | `/events` | any | Long-lived event stream. |

Event types currently published:

| Event | When | Payload |
|-------|------|---------|
| `progress` | During analysis | `{step:"Beacon", pct:55}` |
| `status` | Worker state changes | `{state:"running"\|"paused"\|"idle"}` |
| `done` | Analysis finishes | `{findings_added:int, duration_ms:int}` |
| `notification` | New bell alarm — finding (`score >= 95`), sensor (heartbeat), or feed (reliability) | `Notification` shape (`internal/model/finding.go`). Fields: `id`, `kind` (`finding` / `sensor` / `feed`; empty reads as `finding`), `target` (sensor / feed name for non-finding kinds), `detail` (human-readable text for sensor/feed alarms), `finding_id` (finding kind only), `severity`, `type`, `src_ip`, `dst_ip`, `dst_port`, `dismissed`. **Bell-emit gate (v0.18.1+):** finding notifications are skipped when the finding's src or dst matches the allowlist or an active suppression — the bell only rings for rows that will appear in the table. Existing finding notifications are dismissed in-place when an admin updates the allowlist or adds a suppression that covers their src/dst. NEW-111. Bell threshold for findings was tightened to `score >= 95` at v0.17.1 (was 99 in v0.17.0, over-corrected). |
| `ti_result` | TI escalation streams a hit | `{finding_id, service, detail, severity}` |
| `ti_done` | TI escalation completes | `{finding_id}` |
| `sensor_enrolled` | New sensor accepts enrollment | `{name, ts}` |
| `unauthorized_attempt` | Bad token / unknown key blocked | `{ip, name_attempted, ts}` |
| `watch.heartbeat` | Every 60s, unconditional | `{}` — empty object; presence is the signal. UI flips a top-bar dot red after 180s without a tick. |

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
