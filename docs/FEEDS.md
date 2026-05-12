# Threat-Intel Feeds — MISP and OpenCTI

Archer's feed subsystem ingests indicators from MISP or OpenCTI on a
watch-driven schedule and consults them during analysis to produce
`TI Hit (IP)`, `TI Hit (Domain)`, `TI Hit (Hash)`, and `Suspicious URL`
findings with per-feed provenance. Configuration is operator-curated
through the **Feeds** admin dialog; no SQL required.

This doc covers what the feed pipeline does, how to wire up a feed, which
indicator types actually match (and which don't), and the operational
gotchas teams hit when pointing Archer at internal MISP / OpenCTI
deployments.

---

## Architecture

```
                  ┌──────────────────── Archer host ────────────────────┐
                  │                                                     │
 [admin browser]──HTTP──►  /api/feeds  (CRUD)                           │
                          /api/feeds/{id}/refresh  (admin one-shot)     │
                                       │                                │
                                       ▼                                │
                  ┌─────────── feeds (sqlite) ───────────┐              │
                  │  one row per configured upstream     │              │
                  │  source_type, url, api_key,          │              │
                  │  aging, tls_skip_verify, status      │              │
                  └──────┬───────────────────────────────┘              │
                         │                                              │
                         ▼                                              │
                  ┌─── watch full-pass tick ───┐                        │
                  │  fires the pre-analysis    │                        │
                  │  refresh once per UTC day  │                        │
                  │  (refreshFeedsBeforeFull)  │                        │
                  └──────┬─────────────────────┘                        │
                         │                                              │
       ┌─── HTTPS ───────┴────────────┐                                 │
       │                              │                                 │
       ▼                              ▼                                 │
 [MISP /attributes/restSearch]  [OpenCTI /graphql]                      │
       │                              │                                 │
       └──────────┬───────────────────┘                                 │
                  │                                                     │
                  ▼                                                     │
        normalized []Indicator    ──►  feed_indicators (sqlite)         │
        (ip / cidr / domain / hash)    one row per (feed_id, indicator) │
                                       │                                │
                                       ▼                                │
                                analyzer's phase-0 prefetch              │
                                       │                                │
                                       ▼                                │
                              checkTI / checkSuspiciousURLs /          │
                              checkFileHashes emit                      │
                              TI Hit (IP/Domain/Hash) / Suspicious URL  │
                              with SourceFile = "feed:<name>"           │
                  │                                                     │
                  └─────────────────────────────────────────────────────┘
```

Three independent stages, loosely coupled through SQLite:

1. **Operator config** writes rows to `feeds`.
2. **Refresh** has two paths, both feeding the same upsert/prune body:
   - **Watch full-pass refresh** is the steady-state path. The first
     watch tick of each UTC calendar day (or every tick if
     `WatchAlwaysFull` is on) calls `refreshFeedsBeforeFullPass`
     synchronously before launching analysis: every enabled feed is
     fetched in parallel under a 2-minute cap, indicators are upserted
     into `feed_indicators`, and stale rows are aged out. Failures log
     but do not block the analysis.
   - **Per-feed manual refresh** (`POST /api/feeds/{id}/refresh`,
     admin-only, 60-second cap) is the on-demand path admins use right
     after configuring or editing a feed to verify connectivity. The
     **Refresh** button on each row of the Feeds dialog calls this.
     The dashboard sidebar's all-feeds button is intentionally absent
     — operators who want "refresh everything now" trigger a full
     analysis instead.
3. **Analyzer** reads `feed_indicators` once per analysis run during
   phase-0 prefetch, snapshots indicators into typed buckets per feed,
   and tests dst-IP / DNS-query / HTTP-host candidates against them.
   Both full-pass and incremental ticks consult the cached indicator
   set; only full-pass ticks trigger the upstream fetch above.

The fetch and analyze paths never block on each other — a slow upstream
fetch in stage 2 only delays the analysis it precedes; subsequent
incremental ticks within the same UTC day match against whatever's
already in `feed_indicators`.

---

## Operator workflow

### 1. Add a feed

Click the **Feeds** topbar button (admin role required) → **Add feed**.

| Field | Notes |
|---|---|
| Source type | `MISP` or `OpenCTI` |
| Name | Human label. Surfaces in finding details as `feed:<name>`. |
| URL | Base URL of the upstream. MISP: `https://misp.example/`. OpenCTI: `https://opencti.example/`. No trailing path. |
| API key | MISP: per-user authkey. OpenCTI: bearer token. **Stored in the DB; redacted on subsequent reads.** |
| Indicator aging (days) | Indicators not seen in a fetch for this many days drop out of the matcher. 30 is a sane default; 0 disables aging entirely. |
| Skip TLS certificate verification | Off by default. Tick only for internal MISP / OpenCTI deployments running self-signed or internal-CA certs. |

Save. The new feed's indicators load on the next watch full-pass tick.
If you've just added a feed and want it to participate immediately,
trigger a full pass — either flip on `WatchAlwaysFull` in
Settings → Watch Mode, or run **Discard findings & re-analyze** which
runs as a full pass (with the pre-flight feed refresh) and resets the
two-tier timestamps. Feed status flips through `idle → fetching → ok`
(or `error` on failure, with the upstream error in the feed row's
`last_error`).

### 2. Edit a feed

Click **Edit** on the row. The API-key field is intentionally blank on
edit (the stored key is never echoed back); leave it blank to keep the
existing key, or paste a new one to replace it. Saving a config with the
field blank does **not** clear the key.

### 3. When refresh runs

Feed fetching runs in two paths, both producing identical
fetch/upsert/prune cycles:

**Automatic** — watch full-pass tick. The first watch tick of each UTC
calendar day (or every tick if `WatchAlwaysFull` is on) calls
`refreshFeedsBeforeFullPass` before launching analysis. Every enabled
feed is fetched in parallel under a 2-minute global cap; per-feed
status flips through `idle → fetching → ok`/`error` and the
`last_refresh_at` timestamp updates so the dialog reflects what
happened. This is the steady-state path — the indicator set stays
current without any manual operator action.

**Manual per-feed** — `POST /api/feeds/{id}/refresh`, admin-only,
60-second cap, reachable through the **Refresh** button on each row of
the Feeds dialog. Use this right after configuring or editing a feed
to verify connectivity without waiting for the next watch tick. The
button reports the indicator add / refresh count inline (e.g.
`+147 / ~98253`) and rolls back the label after a few seconds.

There is intentionally no all-feeds dashboard button. If you want to
force a refresh of every configured feed at once, the supported
paths are:

- Flip on **Settings → Watch Mode → Always run full scan on every
  watch tick** for the duration of an active hunt — every subsequent
  tick (down to hourly) becomes a full pass and fetches feeds first.
- Trigger **Discard findings & re-analyze** from the analyst dashboard
  — it runs as a full pass with the pre-flight feed refresh, and
  resets the two-tier timestamps so the cycle restarts cleanly.

### 4. Disable vs. delete

| | |
|---|---|
| Disable | Keeps the feed row and its indicators; just stops the watch scheduler from refreshing it and stops the analyzer from consulting it. The next analysis after disable produces zero matches from this feed. Re-enable to resume. |
| Delete | Drops the feed row and (via FK cascade) its indicators. Forward-only; no undo. |

---

## What the analyzer does with feed indicators

During phase-0 prefetch, the analyzer snapshots each enabled feed's
indicators into typed buckets:

```
feedSources []SourcedFeedIndicators {
  Source  string              // "feed:Home MISP"
  IPs     map[string]bool     // exact IP-string match
  CIDRs   []*net.IPNet        // CIDR containment
  Domains map[string]bool     // exact domain match (lowercased)
  Tags    map[string][]string // upstream-supplied per-indicator labels
}
```

Three analyzer paths consume them:

### `checkTI` (covers conn.log, dns.log, http.log)

For each external dst-IP seen on the wire today:

- if the IP is in any feed's `IPs`, or contained in any feed's CIDRs →
  emit `TI Hit (IP)`
- score 90, severity HIGH (lower than URLhaus's 96-97 / CRITICAL because
  feed indicators are unverified relative to URLhaus's curated focus)
- detail: `<feed-name> indicator match: <ip> — tags: <upstream-tags>`

For each external domain seen on the wire today (DNS query or HTTP host):

- if the domain (lowercased) is in any feed's `Domains` →
  emit `TI Hit (Domain)`
- same scoring as the IP path

### `checkSuspiciousURLs` (covers http.log)

For each `(src, host)` pair in HTTP requests:

- if the host is in any feed's `Domains` →
  emit `Suspicious URL` (different finding type because URI context
  is captured: detail includes the path)
- score 90, severity HIGH

### `checkFileHashes` (covers files.log)

For each file row that carries one or more hash columns
(`md5` / `sha1` / `sha256`):

- if any of the row's hash hex values (lowercased) is in any feed's
  `Hashes` bucket → emit `TI Hit (Hash)`
- score 90, severity HIGH
- detail: `<feed-name> file-hash match: <algo> <hex> | File: <name> | MIME: <type>` (tags inline when present)
- fingerprint dedup is `(downloader-IP, hash-hex)` — a file whose md5
  AND sha256 BOTH match the feed only fires once
- `SrcIP` is set to the downloader (`rx_hosts`), matching the
  `Suspicious File Download` convention so host-risk roll-up
  attributes correctly

**Coverage caveat:** Zeek only populates `md5` / `sha1` / `sha256` in
`files.log` when (a) the file traverses an unencrypted protocol Zeek
can reassemble (HTTP, SMB, FTP, SMTP, IRC), (b) a hashing analyzer is
loaded — `MD5` is default-on for matched MIME types, `sha1` and
`sha256` need `@load policy/frameworks/files/hash-all-files` in
`local.zeek`, and (c) the file completes its transfer. HTTPS, SSH,
encrypted SMB3, and most modern cloud-storage flows produce zero
hashes. In a TLS-everywhere environment, hash matching primarily
fires on internal SMB / SMTP / plain-HTTP traffic — high-value but
narrow. A taps-behind-a-decrypting-proxy deployment broadens this
significantly. Sanity-check what's reachable on a live install:

```
zcat /data/logs/<sensor>/<date>/files.*.log.gz | jq 'select(.md5 != null) | .source' | sort -u
```

### Provenance

Every analyzer-emitted finding from a feed match carries:

```
SourceFile: "feed:<name>"
Detail:     "<name> indicator match: <indicator> — tags: <tag-list>"
```

The findings filter on `/api/findings` also annotates the finding's
`IOCSource` field with the feed source so the UI can render a "matched by"
badge separately from the SourceFile.

### What does NOT match (yet)

- **Hashes.** MISP/OpenCTI hash indicators are persisted to
  `feed_indicators` correctly, but no analyzer field today carries a hash
  candidate — `analyzeFiles` extracts MIME and filename from `files.log`,
  not the hash. This is a logged Phase 7 follow-up.
- **URL paths.** MISP/OpenCTI export hostnames; URL-path indicators
  aren't part of the standard export shape. The `Suspicious URL` finding
  matches on host, with the URI as Detail context.
- **Indicators in disabled feeds.** Disabling a feed removes it from the
  prefetch snapshot immediately on the next analysis.

---

## Aging

Each feed has its own `indicator_aging_days`. After every successful
fetch, the worker calls `RemoveStaleIndicators(feed_id, now − aging·86400)`
to drop indicators not seen in the latest snapshot for longer than the
window. Aging matters because:

- Operators frequently subscribe to feeds that prune entries themselves
  upstream (e.g., URLhaus drops malware-distribution URLs after takedown).
  Without aging, Archer would keep flagging long-dead infrastructure.
- A misconfigured fetch can spike indicator counts; aging provides
  natural cleanup once the misconfiguration is fixed.

Set aging to `0` to disable — every indicator that's ever been fetched
stays forever. Useful only if you're treating MISP as a permanent IOC
archive rather than a current-state snapshot.

---

## TLS-verify bypass

The **Skip TLS certificate verification** checkbox disables certificate
verification on the upstream HTTPS request for one specific feed. Default
off. Tick when pointing Archer at:

- A lab MISP with a self-signed cert
- An internal MISP fronted by a corporate CA the Archer container's
  trust bundle doesn't include
- An OpenCTI behind an internal load balancer terminating with a private
  cert

The setting is per-feed, not global — turning it on for one trusted
internal feed doesn't weaken verification for any other feed. Operators
should still prefer fixing the cert chain when feasible (mount the
internal CA into the container, regenerate the cert with proper SANs,
etc.) and reach for the bypass only when those options are impractical.

---

## Internal address bypass (allow_internal)

Archer ships an SSRF guard on the feed surface (NEW-18). Feed URLs
whose host is a literal IP in loopback (`127.0.0.0/8`, `::1`),
link-local (`169.254.0.0/16` covering AWS metadata; `fe80::/10`),
RFC1918 private (`10/8`, `172.16/12`, `192.168/16`), or IPv6
unique-local (`fc00::/7`) space are refused at config time. A
matching CheckRedirect refuses any redirect-time hop that resolves
into those ranges. The guard exists so a hostile (or careless) admin
can't configure a feed at `http://169.254.169.254/...` or
`http://10.0.0.5/internal-api` and have the feed worker exfiltrate
adjacent internal services using whatever credentials are attached
to the feed.

The **Allow internal address (skip SSRF guard for this feed)**
checkbox is the per-feed opt-out (v0.18.5+). Tick when pointing
Archer at:

- An internal MISP at e.g. `https://10.0.0.17/` — the
  most common case in real deployments where the MISP is on the
  same internal network as Archer rather than on the public
  internet
- An OpenCTI instance reachable only via a private address
- A lab MISP on the same host (`http://172.16.0.5:8080/`)

The setting is per-feed, not global — turning it on for one
specific internal feed leaves the SSRF guard active for every other
feed. A typo that lands a non-internal feed's URL at
`http://169.254.169.254/` still gets refused.

Both guards (config-time `rejectInternalFeedURL` and fetch-time
`CheckRedirect`) honor the flag for the same feed. With
`allow_internal=true`, an internal MISP's normal redirect flow
(e.g. unauthenticated `GET /attributes/restSearch` → `302 /login`
internally) doesn't break the fetch.

Each toggle of the flag is captured in the audit log
(`feed_create` / `feed_update` rows carry `allow_internal` in their
before/after maps) so a later reviewer can prove who opted which
feed in.

The flag is independent of TLS-verify bypass — an internal MISP
with a self-signed cert needs both ticked (it's at an internal
address AND uses a cert Archer doesn't trust); an internal MISP
fronted by a corporate CA Archer trusts only needs allow_internal.

---

## MISP setup tips

### Generate the API key

Top-right username dropdown → **My Profile** → **List My Auth Keys** →
**Add authentication key**. After creation MISP shows the key exactly
once — copy it then; you can't retrieve it later, only revoke and
regenerate.

If your role can't see the auth-keys page at all, the user doesn't
have API access. An admin needs to grant the role API access or
generate a key under a different user.

### Common 403 responses from `/attributes/restSearch`

| Response body | Cause | Fix |
|---|---|---|
| `Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.` | Header missing or malformed | Verify the `Authorization` header format is exactly `Authorization: <key>` (no `Bearer`, no colon-omission) |
| Same body, key looks correct | User's role doesn't have REST access | Grant the role API access in MISP admin → Role permissions |
| Same body, role has access | Key was rotated upstream | Regenerate, paste new key into Archer |

### TLS verification errors

If the worker logs `tls: failed to verify certificate: x509: cannot validate
certificate for <ip> because it doesn't contain any IP SANs`, regenerate
the MISP cert with proper subjectAltNames including both the IP and any
DNS names operators use to reach it.

If the worker logs `tls: failed to verify certificate: x509: certificate
signed by unknown authority`, your MISP cert isn't signed by a CA in
Archer's trust bundle. Either install the CA into the container's trust
store or tick the per-feed bypass.

---

## OpenCTI setup tips

### Get a bearer token

Top-right user menu → **Profile** → scroll to API access → copy the API
token. Tokens don't expire by default but can be revoked.

### What the adapter queries

OpenCTI's GraphQL `indicators` query, walking the cursor up to 100 pages
× 1000 indicators per page = 100k indicators per fetch. Indicators with
unrecognized `x_opencti_main_observable_type` (anything outside
`IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Hostname`, `StixFile`) are
silently skipped — they don't break the fetch, they just don't produce
matchable indicators in Archer.

### STIX pattern parsing

The adapter extracts the indicator value from the STIX pattern's right-
hand side of the `=` operator, which handles the quoted-property-path
case correctly (e.g. `file:hashes.'SHA-256' = '<hash>'`). Patterns
without a `=` (compound expressions, IN-clauses) are skipped.

---

## Companion deployment

Archer doesn't ship MISP or OpenCTI alongside its container — they're
separate services with their own data lifecycle. The recommended pattern
is to run them on the same Docker host as Archer but in separate
compose files / volumes, so a `reset.sh` of Archer doesn't touch the TI
state.

### MISP companion (sketch)

```yaml
services:
  misp-db:
    image: mariadb:10.11
    environment:
      MYSQL_ROOT_PASSWORD: <secret>
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: <secret>
    volumes:
      - misp-db:/var/lib/mysql

  misp:
    image: coolacid/misp-docker:core-latest
    depends_on: [misp-db]
    ports:
      - "8443:443"  # adjust if Archer also wants 8443
    environment:
      MYSQL_HOST: misp-db
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: <secret>
      HOSTNAME: https://misp.local
    volumes:
      - misp-config:/var/www/MISP/app/Config
      - misp-files:/var/www/MISP/app/files
      - misp-tls:/etc/nginx/certs

volumes:
  misp-db:
  misp-config:
  misp-files:
  misp-tls:
```

Then point Archer's feed at `https://<host>:8443/` (or wherever you
exposed it) and use the per-feed TLS-verify bypass for the lab cert.

### OpenCTI companion

OpenCTI's official compose at https://github.com/OpenCTI-Platform/docker
is the canonical source — it pulls in Redis, Elasticsearch, MinIO, and
RabbitMQ alongside the OpenCTI server, so it's heavier than MISP. Worth
running on a separate host if resource margin is tight.

---

## Troubleshooting

### Feed status is `error`

Click the row to see the full error in the tooltip. Common cases:

- **Auth failures (403/401):** rotate the key in MISP/OpenCTI, re-edit
  the feed in Archer.
- **TLS errors:** see the MISP setup section above.
- **Connection refused / timeout:** firewall between Archer and the TI
  service, or the service is down.

### Feed status is `ok` but no findings appear

Check whether the indicators actually overlap with what's on the wire.
The fastest way:

```bash
docker cp archer:/data/archer.db /tmp/a.db

# what indicators do you have?
sqlite3 /tmp/a.db "SELECT indicator_type, COUNT(*) FROM feed_indicators GROUP BY indicator_type"

# what queries does Zeek see?
docker exec archer sh -c "zcat /logs/<sensor>/$(date -u +%Y-%m-%d)/dns*.log.gz" \
  | grep -oE '"query":"[^"]+' | sort -u | wc -l

# any overlap?
docker exec archer sh -c "zcat /logs/<sensor>/$(date -u +%Y-%m-%d)/dns*.log.gz" \
  | grep -oE '"query":"[^"]+' | sed 's/"query":"//' | sort -u > /tmp/q.txt
sqlite3 /tmp/a.db "SELECT indicator FROM feed_indicators WHERE indicator_type='domain'" | sort -u > /tmp/i.txt
comm -12 /tmp/q.txt /tmp/i.txt | head
```

If `comm` returns rows, the overlap exists and the next analysis pass
will surface findings. If it's empty, the test traffic isn't reaching
your sensor's span port — verify which network the sensor monitors and
generate test traffic from a host on that network.

### Indicator count looks capped, "⚠ truncated" badge shown

The MISP adapter walks pages of 10000 up to 100 pages (1M attributes)
as of v0.7.0; OpenCTI walks cursor pages of 1000 up to 100 pages
(100k). When the cap is hit AND the upstream still indicates more
data, the feed row's `last_fetch_truncated` flag is set and the
Feeds dialog renders a yellow `⚠ truncated` badge next to the
indicator count.

To resolve: narrow the MISP search (more specific tag filter, single
campaign instead of "all attributes") or scale up by raising the
adapter's `PageLimit` constant in source if the deployment can
afford the memory + bandwidth (default cap protects against runaway
fetches). For OpenCTI, same playbook — narrow the indicator query
or raise the limit.

---

## Sensor-facing endpoints

The feed endpoints are admin-facing only — there's no Quiver-side
equivalent. Sensors don't need feed visibility; the Archer server
matches feeds against the logs centrally.

| Endpoint | Method | Role | Purpose |
|---|---|---|---|
| `/api/feeds` | GET | any auth | List configured feeds (api_key redacted) |
| `/api/feeds` | POST | admin | Create a feed |
| `/api/feeds/{id}` | PUT | admin | Update a feed (empty api_key keeps existing) |
| `/api/feeds/{id}` | DELETE | admin | Delete a feed (cascades to indicators) |
| `/api/feeds/{id}/refresh` | POST | admin | One-shot fetch + upsert + prune for one feed (60-second cap). |

Full request/response shapes are in `docs/API.md`.
