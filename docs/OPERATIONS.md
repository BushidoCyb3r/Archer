# OPERATIONS.md

Operator-facing runbook for Archer. Audience: the engineer or SOC
analyst responsible for keeping a deployment alive, applying upgrades,
restoring from backup, and answering compliance questions about who
did what.

This document is the counterpart to `README.md` (features + install)
and `docs/ARCHITECTURE.md` (dataflow + internals). When the answer to
"how do I X?" is procedural, it lives here. When it's structural
("why does this work this way?"), it lives in ARCHITECTURE.md.

If you're triaging a deployment in a hurry and don't have time to
read this whole document, start with **`docs/QUICKSTART_OPS.md`**
— it's the 5-minute "deploy + restore + three things to know"
companion. Come back here when the questions get deeper.

Everything below is current as of **v0.30.0**.

---

## Table of contents

1. [Threat model](#threat-model)
2. [Deployment hardening checklist](#deployment-hardening-checklist)
3. [Upgrade procedure](#upgrade-procedure)
4. [Backup and restore](#backup-and-restore)
5. [Sensor lifecycle](#sensor-lifecycle)
6. [Health monitoring](#health-monitoring)
7. [Audit log](#audit-log)
8. [TLS certificate rotation](#tls-certificate-rotation)
9. [Disaster recovery](#disaster-recovery)
10. [Scope decisions](#scope-decisions)

---

## Threat model

Archer assumes the following deployment posture. Calibrate your
hardening choices against deviations from this baseline.

**In scope (Archer defends against):**

- Hostile sensor-network traffic — the whole point. Any malicious
  payload in a Zeek log gets parsed, detected, and surfaced.
- Forged sensor heartbeats — closed by per-sensor HMAC in Quiver
  protocol v2 (v0.12.0).
- Stored XSS via feed-injected indicators — closed by ingest-side
  shape validation (NEW-28) + SPA-side escaping (NEW-26, NEW-27).
- Analyst-fabricated findings via `/api/import` — closed by
  admin-only gate + per-finding validation (NEW-14).
- CSV/XLSX formula injection in exports — closed by leading-char
  quoting (NEW-17).
- Feed-URL SSRF — closed by config-time literal-IP refusal + fetch-
  time CheckRedirect (NEW-18).
- Compromised analyst session — analyst can mark findings, add
  notes, edit allowlists/IOC lists; cannot import findings,
  manage users, manage sensors, manage feeds, or change config.
- Compromised viewer session — read-only; cannot mutate state.

**Out of scope (Archer does not defend against):**

- Compromised admin session — admin actions are logged (see
  [Audit log](#audit-log)) but not gated by anything beyond the
  session cookie. Anyone with an admin session can do anything
  an admin can do.
- Physical access to the host filesystem — anyone with read access
  to `/data/server.key` can impersonate the server's TLS;
  anyone with read access to `/data/archer.db` sees every
  finding and every feed API key. Encrypt the volume at rest if
  this matters.
- Privileged compromise of the sensor host — Quiver's chrooted
  rrsync limits the blast radius to the sensor's own log
  directory, but a root-compromised sensor can still ship
  fabricated logs.
- Resource exhaustion DoS from a high-volume sensor — `GOMEMLIMIT`
  caps Go-heap use and `start.sh` budgets container resources at
  70% RAM / 80% CPU, but a sensor pushing 10 GB/hour will degrade
  analysis cadence.
- Network-level attacks against the SSH port (2222) or HTTPS port
  (8443) — handled by your network's existing controls. Archer
  does no rate-limiting and no IP allowlist at the app layer.

**Trust boundaries Archer assumes hold:**

- The container's filesystem permissions (mode 0600 on
  `/data/server.key`, `/etc/quiver/secret`).
- The container's network isolation — Archer's listening ports are
  exposed by docker-compose, and access to them is the operator's
  network problem to solve.
- The SQLite database's atomicity — WAL mode + single-writer
  config rely on the underlying filesystem honoring fsync.
- The Linux kernel — Archer's user-space defenses don't survive a
  kernel exploit on the host.

---

## Deployment hardening checklist

Run through this before exposing Archer to a multi-user team.

### TLS

- [ ] **Single TLS listener for every role.** As of v0.14.5 the
      pre-existing plaintext `:8080` listener is gone (NEW-49); the
      `:8443` HTTPS listener serves the UI, the analyst API, AND
      the Quiver sensor surface. Admin credentials, analyst session
      cookies, and viewer access are all on TLS by design.
- [ ] **Generate a CA-signed cert from your internal PKI before
      go-live.** REQUIRED for any deployment with more than one
      user. The auto-generated self-signed cert works (sensors pin
      the public key, browsers throw a one-time "Not Secure"
      warning the operator can click through) but a CA-signed cert
      eliminates the warning and matches the discipline every
      compliance framework expects. Drop the cert + key into
      `/data/tls/server.crt` and `/data/tls/server.key` (both mode
      0600). Restart the container; the operator path validates
      expiry, parseability, and key/cert match at startup. A
      startup error names the file so a wrong cert is loudly
      visible.
- [ ] **Sensor pinning still works after a CA cert swap.**
      Pinning checks the public key (SubjectPublicKeyInfo), not
      the chain — so the same cert satisfies both browser chain
      validation and `curl --pinnedpubkey` simultaneously. Just
      make sure to back up `/data/tls/` before rotating, since the
      pinned fingerprint changes with any key regeneration (see
      Backup and restore → cert continuity).
- [ ] **Don't share the auto-gen cert across hosts.** The
      `--pinnedpubkey` fingerprint is host-specific; deploying
      Archer to two hosts means two independent CAs (or two
      independent self-signed certs).

### Network

- [ ] Expose port 8443 (HTTPS) to the admin AND sensor networks.
      Same port carries both. A reverse proxy in front (if you
      use one) can still split by path — `/api/quiver/*` to the
      sensor allowlist, everything else to the admin allowlist —
      but the underlying listener is unified.
- [ ] Expose port 2222 (sshd for log rsync) only to sensor
      networks. The chrooted rrsync limits damage from a
      compromised sensor, but the SSH attack surface itself is
      best minimised at the network layer.
- [ ] **There is no plaintext HTTP listener.** Pre-v0.14.5 Archer
      ran a `:8080` plaintext listener for the analyst UI; that
      listener carried passwords and session cookies in cleartext
      and was removed in NEW-49. The flag does not exist any
      more — `--addr` is gone, `--tls-addr` is the only listener
      configuration knob.
- [ ] Egress from the Archer host to feed URLs (MISP, OpenCTI)
      should pass through your standard outbound proxy /
      monitoring. Feed URLs are admin-configurable; the SSRF
      guards (NEW-18) refuse internal addresses by default but
      a per-feed **Allow internal address** opt-out is available
      (v0.18.5+) for the common case of pointing Archer at an
      internal MISP/OpenCTI. The flag is captured in
      `feed_create` / `feed_update` audit rows so a later
      reviewer can prove who opted which feed in — keep the
      audit log under retention to preserve that trail.

### Secrets

- [ ] **`/data/` volume contains sensitive material.** server.key
      (TLS private key), archer.db (feed API keys, user
      password hashes, sensor HMAC secrets). Treat the volume
      as a secrets store.
- [ ] **Don't commit `.env` or any file from `/data/`** to source
      control. `.env` carries the operator-derived resource
      caps but no secrets directly; `/data/` carries everything.
- [ ] **Sensor secrets live at `/etc/quiver/secret`** (mode 0600,
      owned by the `quiver` user) on each sensor. The same
      secrecy posture as a private SSH key applies.

### Log retention

- [ ] **Findings persist until explicitly pruned.** The
      `archive_after_days` setting (Settings → Operations → Log Archive)
      moves `/logs/<sensor>/<date>/` trees into
      `/data/archive/<sensor>/<date>/` after N days. Pruning
      findings older than the archive cutoff is opt-in
      (destructive toggle).
- [ ] **The audit log is unbounded.** v0.14.0 doesn't prune the
      `audit_log` table. If your compliance regime requires a
      retention cap, periodically `DELETE FROM audit_log WHERE
      ts < strftime('%s', 'now', '-N days');`. (No UI for this
      yet — file under [Scope decisions](#scope-decisions).)
- [ ] **Sensor archived logs persist until manually purged.**
      Disenrolling a sensor moves its logs aside; purging
      deletes them. The two-step flow exists so an admin can
      retain the trail of a recently-removed sensor.

### Auth posture

- [ ] **First registered user becomes admin automatically.** Make
      sure the first registration is from a trusted address.
- [ ] **Passwords are bcrypt-hashed.** Cost factor is Go default
      (10). No password complexity rules — the operator is
      expected to enforce these at registration time via
      whatever onboarding flow they use. (Not a Scope decision
      — just an opt-in we haven't bolted on yet.)
- [ ] **Sessions are in-memory only.** A container restart logs
      everyone out. This is intentional — sessions are
      ephemeral by design.
- [ ] **Session validity is re-checked every request.** Demoting
      a user from active → pending takes effect immediately
      (NEW-8). Admin demotes propagate within one request
      cycle.

---

## Upgrade procedure

### Standard (non-breaking) release

1. Pull the new tag in a checkout: `git fetch && git checkout v0.X.Y`.
2. `./start.sh` rebuilds the image and recreates the container.
3. Migrations run automatically at startup. A clean exit means
   schema is up-to-date. Check `docker compose logs archer` for
   the `applied schema migration` lines if you want explicit
   confirmation.
4. UI version pill (top-right) should show the new version.
5. `/api/version` returns the same value programmatically.

### Releases with `### Breaking` notes in CHANGELOG

Read the release notes first. The known breaking-change categories
(per CLAUDE.md) are:

- **HTTP/SSE API contract** — external scripts may need updates.
- **DB schema** — migrations apply automatically; no manual step.
- **Quiver sensor protocol** — sensors may need re-enrollment
  (v0.12.0 dropped v1; every sensor had to re-run the install
  one-liner).
- **Detection semantics** — score formulas / thresholds /
  finding-type names changed; re-baseline downstream alerting.

For Quiver protocol bumps specifically: the install one-liner from
the Sensors modal always speaks the current server protocol, so
re-running it on each sensor is the canonical upgrade path.

### Downgrade

**Not supported.** Migrations are forward-only; no down migrations
exist. If a release introduces a regression, the recovery path is
to restore from backup and pin to the working release.

---

## Backup and restore

### What to back up

Three pieces, in order of importance:

1. **`/data/archer.db`** — every finding, every feed config, every
   user, every sensor enrollment, every audit-log row, every
   suppression. This is the source of truth. Roughly 10–500 MB
   for a typical deployment depending on finding history.
2. **`/data/tls/server.crt` + `/data/tls/server.key`** — if you
   restore to a new host without these, sensors will need
   re-enrollment because their pinned fingerprint won't match
   the auto-regenerated cert. Tiny (< 2 KB).
3. **`/logs/`** — Zeek logs as they came in. Useful for re-running
   analysis with new detector tuning. Sizes from GB to TB.
   Often the operator's existing log-retention infrastructure
   covers this; if not, back it up here.

Skip:

- `/data/archive/` — derived from `/logs/`; can be re-created.
- `/data/sshd/` — sshd host keys auto-regenerate on container
  start.

### Backup procedure

**Script path (recommended for rotation / cron).** `./backup.sh`
authenticates as an admin, hits the backup endpoint (which runs
`VACUUM INTO` inside the live process), and writes a timestamped
`archer-backup-YYYYMMDD-HHMMSS.db` to `./backups/` (or `$1` /
`BACKUP_DIR`). It verifies the downloaded file's SQLite magic before
keeping it, so a stale session or error page never lands as a
"backup". Credentials come from `ARCHER_BACKUP_USER` /
`ARCHER_BACKUP_PASS` (prompted on a TTY if unset; required for cron).

```sh
./backup.sh                                  # → ./backups/archer-backup-*.db
BACKUP_RETAIN=14 ./backup.sh /srv/archer-bk  # keep newest 14
BACKUP_RSYNC_DEST=archive:/srv/archer/ \
  BACKUP_RSYNC_SSH="ssh -i ~/.ssh/bk -p 2222" ./backup.sh
```

The snapshot is consistent (includes un-checkpointed WAL data) and
never blocks analysis. The download is audit-logged server-side as
`db_backup` with size + filename, so an exfil-via-backup attempt
leaves a row in `audit_log`.

**UI path (v0.18.2+, good for ad-hoc).** Sign in as an admin, open
Settings → Admin → Backup → **Download DB backup**. Same `VACUUM INTO`
snapshot, streamed to the browser with the same timestamped filename
and the same audit row. Works while analysis is running.

Both paths back up **the database only**. The DB file contains every
credential hash, sensor secret, and audit row — handle it with the
same care as the live DB.

**TLS + logs (full set).** The container ships no `sqlite3` CLI, so
the DB must come via one of the paths above. TLS material and logs
are plain files — copy them directly:

```sh
docker compose cp archer:/data/tls/ ./backup-tls-$(date -u +%Y%m%dT%H%M%SZ)/
tar czf ./backup-logs-$(date -u +%Y%m%dT%H%M%SZ).tgz ./logs
```

(`./logs` is a host bind-mount, not a Docker volume — back it up
where it lives. TLS material is tiny but is what preserves sensor
pinning across a different-host restore; see below.)

### Restore procedure

**Script path (same-host DB restore — the rotation case).**
`./restore.sh <snapshot.db>` validates the snapshot's SQLite magic,
prompts for confirmation, stops the container, swaps the file into
the `archer-data` volume (clearing any stale WAL/SHM sidecars), and
restarts. TLS material and all other volumes are left untouched, so
sensor pinning survives in place. Schema migrations run idempotently
on startup, so a snapshot from an older build migrates forward when
the newer binary opens it.

```sh
./restore.sh ./backups/archer-backup-20260516-031500.db
```

**Manual restore on a fresh host (DB + TLS):**

1. Stop any running container: `docker compose down`.
2. Wipe the data volume: `docker volume rm archer_archer-data`.
3. Recreate the container without starting Archer:
   `docker compose up --no-start`.
4. Copy backed-up files into the volume:
   ```sh
   docker compose cp ./backups/archer-backup-*.db archer:/data/archer.db
   docker compose cp ./backup-tls-*/ archer:/data/tls/
   ```
5. Start the container: `docker compose start archer`.
6. **Verify** the UI loads and the version pill matches the build.
   (The container has no `sqlite3` to query `schema_migrations`
   directly; startup migrations bring an older snapshot forward
   and the version pill is the externally observable check.)
7. **Verify** sensor checkins succeed — wait for the next hourly
   tick, then check `/api/sensors` for fresh `last_seen_at`.

**Cert continuity preserves sensor pinning.** As long as you
restore the `/data/tls/` directory from backup, the server's
cert fingerprint on the restored host matches the one every
enrolled sensor pinned. Sensors don't notice the host swap — no
re-enrollment is required, and the existing rsync + checkin
channels continue to work uninterrupted. This is the whole reason
TLS material is in the back-up set; tested-restore-on-different-host
is the validation that the recovery story actually works.

Bringing up on a fresh cert (no TLS backup) means every enrolled
sensor's pinned fingerprint is stale and they'll fail to connect.
Recovery: re-run the install one-liner on each sensor. There is
no in-band re-issue path; this is by design (pinning is what
makes the sensor channel resistant to MITM in the first place).

### Schedule recommendation

- Database: daily.
- TLS material: on every cert rotation.
- Logs: per your existing log-retention policy.
- **Tested restore: quarterly, on a *different host*.** A backup
  you've never restored is not a backup. A backup you've only
  restored on the original host doesn't prove the TLS material is
  in the bundle — restore to a fresh VM and verify sensors
  continue pushing logs without re-enrollment. If they don't, the
  TLS files didn't make it into the backup.

---

## Sensor lifecycle

### Enrollment (initial install)

1. Admin clicks Sensors → New token. Optionally sets an override
   name (locks the sensor to a chosen name regardless of what its
   hostname is).
2. Admin copies the one-liner to the sensor host and runs it as
   root.
3. Sensor generates a fresh ed25519 SSH keypair, POSTs to
   `/api/quiver/enroll` with token + name + pubkey + protocol
   version (v2 as of v0.12.0).
4. Server returns the schedule slot, the protocol version, and
   the per-sensor HMAC secret. The sensor persists the secret at
   `/etc/quiver/secret` (mode 0600).
5. Sensor's `quiver.sh` cron entry fires at the assigned
   minute-of-hour and posts a signed checkin. Logs follow via
   rsync.

**On the `-k --pinnedpubkey` combination in the install script
and `quiver.sh`.** A security reviewer scanning the sensor-side
shell will see `curl -k --pinnedpubkey sha256//<fp> ...` and
flag the `-k`. The combination is correct and intentional:

- `-k` (a.k.a. `--insecure`) turns off CA chain validation.
  Necessary because the default Archer cert is self-signed and
  has no CA chain to validate against — the operator workflow
  doesn't require deploying a system trust anchor on every
  sensor host.
- `--pinnedpubkey sha256//<fp>` enforces public-key pinning
  against the SubjectPublicKeyInfo of the cert the server
  presents. Curl applies BOTH checks (it doesn't OR them);
  `-k` removes the chain layer, `--pinnedpubkey` provides the
  integrity layer. Tampering with the cert changes the SPKI,
  changes the hash, fails the pin, the connection drops.

The construct is the documented Curl idiom for pin-only
verification. It works the same way regardless of whether the
operator has swapped in a CA-signed cert: the chain becomes
valid but pinning still enforces the public key, so a future
CA-bundle-trust-store-poisoning attack against the sensor's
host doesn't help an attacker substitute a different
Archer-public-key cert. Don't remove `-k` "because we have a
CA cert now" — that couples sensor behaviour to deployment
posture in a way that breaks the "swap in your cert, sensors
keep pinning" promise. v0.14.7 NEW-59.

### Disenrollment (clean removal)

1. Admin opens the row's kebab (⋮) in the Sensors modal and picks
   **Disenroll**.
2. Server marks the row `disenrolling`, removes the
   authorized_keys entry, rotates the sensor's logs to
   `/_archived/<name>/<stamp>/`, retags the sensor's findings
   (`<name>:disenrolled-<stamp>`), marks the row `disenrolled`.
3. Sensor's next checkin gets `status=disenrolled` back; quiver.sh
   self-cleans by running quiver-uninstall.sh.

If step 2 crashes midway, the row sits in `disenrolling`. v0.12.0
made the admin handler resumable — reopening the kebab and picking
Disenroll again re-runs the (idempotent) steps from where it
stopped.

### Purge (irreversible)

Once a row is in `disenrolled` state, the kebab menu surfaces
**Purge data** (red). It wipes the sensor's archived logs and
findings. Run it only after you're sure the operational history
can be discarded.

### Re-enrollment (cert rotation, secret loss, sensor host reinstall)

Re-run the install one-liner from the Sensors modal. The sensor
gets a fresh HMAC secret. Old findings tagged with the previous
enrollment stay attributed to the previous instance (suffixed
`:disenrolled-<stamp>`).

**Re-enrolling under the same name? Clear the old log directory
first.** If a sensor is re-enrolled under a name that previously
existed (the operator wiped the DB but didn't clean `/data/logs/`,
or chose the same override name as a prior decommissioned sensor),
the sensor heartbeat alarm reads `lastLogMTime` from the directory
on first scan. The directory's mtime is whatever the last write
was — often months stale. With the freshly-enrolled sensor's
`last_seen_at=0`, `max(0, stale_mtime) = stale_mtime`, which is
older than the `sensor_stale_threshold_hours` threshold (default 2h). A false-positive
"sensor offline" alarm fires (appearing on the Sensors button badge) at the first 5-min tick after enrollment.
NEW-104 in the twenty-third audit round. Mitigation is a single
command before the re-enrollment install runs:

```
docker compose exec archer rm -rf /data/logs/<sensor-name>
```

Or, equivalently, use the **Purge** admin action in the Sensors
modal *before* the re-enrollment — Purge deletes
`/data/logs/<name>/` as part of its cleanup. Plain Disenroll does
not (Disenroll preserves logs for forensic continuity).

---

## User offboarding

When a team member leaves the org, run this sequence. The goal is
to make the cookie they're holding stop working immediately, while
preserving the audit trail of what they did.

1. **Sign in as an admin** (a different account from the
   departing user — admins cannot demote or delete their own
   account; the API rejects self-targets to prevent
   lock-yourself-out).
2. **Open the Users dialog** (admin → Users).
3. **Delete the user row.** This:
   - Removes the row from the `users` table.
   - Calls `DeleteSessionsForUser`, which removes every live
     session token for that user from the in-memory session map.
     The session cookie they hold becomes a 401 on the next
     request — no waiting for TTL expiry.
   - Emits a `user_delete` audit-log row with the deleted user's
     email captured as `actor_email`/`target_name` (denormalised
     at write time so the audit row survives the row deletion).
   - The audit history of everything that user did before
     offboarding stays intact. `actor_id` becomes a dangling
     reference (no FK constraint), but `actor_email` was
     denormalised at write time so the trail is readable.
4. **Verify in the audit log** (admin → Audit) that the
   `user_delete` row landed.

**Demote rather than delete** if you want to retain the account
shape (for re-onboarding, for audit-trail completeness without
the dangling actor_id). Demote viewer → no admin actions
possible. The `user_role_change` audit row captures the
transition.

**What this does NOT do:** revoke any export bundles, raw-log
downloads, or other artefacts the user already pulled out of the
system. Treat those as gone-once-they-leave-the-host. Out-of-band
data-disposition belongs to your team's normal departure
process — Archer can't recall data it already served.

**SLA shape:** sessions auto-invalidate within one request
cycle (single-digit milliseconds in practice — the auth
middleware re-checks the session map every request, by design,
NEW-8). There is no "TTL until logout" window to wait out.

### Password reset and rotation

Two paths, by who is acting (v0.23.0):

- **Self-service.** Any user rotates their own password from the
  account menu (click the display name in the top bar → **Change
  password**). The current password is re-verified, so a hijacked
  session that can't prove knowledge of the credential can't
  silently change it. On success every session for that account is
  dropped and a fresh cookie is issued to the client that made the
  change — the operator's other devices/sessions log out, but they
  are not locked out of the browser they changed it from. Emits
  `user_password_change`.
- **Admin reset.** For a locked-out or suspected-compromised
  account, an admin opens **Users**, clicks **Reset PW** on the
  row, and sets a new password. No knowledge of the old password is
  needed (the admin is the authority). The target's sessions are
  dropped immediately (same `DeleteSessionsForUser` path as
  offboarding) so any cookie they hold dies on the next request and
  they must sign in with the new credential. Emits
  `user_password_reset`. The admin cannot reset their *own*
  password this way — the API refuses self-targets; use
  self-service.

Neither path writes password material to the audit log
(before/after/details are empty for both actions). For a
suspected-compromise response, admin-reset is the fast lever: it
both rotates the credential and kills live sessions in one action.
There are no password-complexity rules beyond the 8-character
minimum — see the scope note in the hardening section.

---

## Health monitoring

v0.17.0 added three operational health surfaces. They share the same
SSE pipe as detection findings; the `kind` field on each `Notification`
row tells the UI (and any external consumer of `/api/notifications`)
what the alarm is about and where it surfaces.

### Bell (in-UI) — finding alarms only

`kind=finding`. Fires on new findings with `score >= 95`. Before
v0.17.0 the gate was "CRITICAL severity or any TI type, regardless of
score" — that fired often enough that operators learned to ignore the
bell. v0.17.0 first cut the threshold at `>= 99`, but that
over-corrected — discrete-tier detectors that score below 99 by design
(URLhaus 96, Malicious JA3 95) stayed silent. v0.17.1 NEW-99 lowered
the floor to 95 so high-confidence TI hits ring through. v0.18.1
NEW-111 added an allowlist/suppression gate: notifications whose src or
dst would be hidden from the table at emit time skip the bell entirely,
and dismiss in-place when an admin later adds the matching entry.

The bell's **Jump** button navigates to the finding row (clearing
filters so pagination and delta-mode can't exclude it).

### Sensors button badge — sensor alarms

A count badge on the **Sensors** nav button signals sensor health
issues. Clicking the button opens the Sensors modal and clears the
badge (opening the modal is the acknowledgment).

- **Sensor heartbeat alarm.** `kind=sensor`, `type=Sensor stale`, `target=<sensor name>`.
  Fires when an enrolled sensor's `last_seen_at` is older than
  `sensor_stale_threshold_hours` (default 2h, configurable in Settings).
  One alarm per staleness episode — transition-edge dedup means the badge
  doesn't increment every 5min while the sensor stays silent. Recovery
  (sensor checks in again) clears the dedup flag so a future re-staleness
  fires a fresh alarm. Disenrolled and never-reported sensors are skipped.
- **Rsync-dead alarm.** `kind=sensor`, `type=Sensor rsync stopped`, `target=<sensor name>`.
  Fires when a sensor is actively checking in (fresh `last_seen_at`) but
  its log directory mtime has not advanced in more than
  `rsync_stale_threshold_hours` (default 4h, configurable). Indicates a
  live sensor whose rsync is broken. Same transition-edge dedup as the
  heartbeat alarm.

### Feeds button badge — feed alarms

A count badge on the **Feeds** nav button signals feed health issues.
Clicking the button opens the Feeds modal and clears the badge.

- **Feed reliability alarm.** `kind=feed`, `target=<feed name>`.
  Fires when an enabled feed has either `consecutive_failures >= 3`
  (the refresh worker bumps the counter on every error and resets it on
  every success) or has gone longer than `feed_stale_threshold_hours`
  (default 24h, configurable) since the last successful refresh. Same
  transition-edge dedup as the sensor alarms.

### Watch heartbeat indicator

A small dot in the top bar (next to the bell) reflects the
`watch.heartbeat` SSE event. The server publishes it every 60s
unconditional of watch config. The UI flips the dot:

- **Green** while a beat arrived in the last 180s
- **Red** after 180s with no beat (3 missed ticks)
- **Grey** (unknown) before the first beat lands at page load

Use it to distinguish "watch is healthy and quiet" from "watch is
dead and quiet." A wedged SSE pipe or a dead server will both
surface within ~3.5 minutes.

### Sensor health endpoint (`/api/sensors/health`)

```
GET /api/sensors/health
```

returns:

```json
{
  "sensors": [
    {
      "name": "lab-1",
      "status": "enrolled",
      "last_seen_at": 1715512345,
      "stale": false,
      "stale_for_seconds": 0,
      "stale_threshold_sec": 7200    ← reflects sensor_stale_threshold_hours (default 2h)
    }
  ]
}
```

Same staleness threshold and signal as the in-UI Sensors button badge alarm, so an
analyst-facing script in the auth boundary (a hunt-team dashboard
tile, an incident-response triage shell helper) sees what the
operator sees. Disenrolled sensors are skipped from the response;
never-reported sensors render with `stale=false` (the clock hasn't
started).

**Auth scope.** The endpoint accepts either a session cookie (analyst /
admin / viewer) or an `X-Archer-Token` service-account token. Service
tokens are admin-generated in Settings → Admin → Service Tokens. Because the
token path requires no browser session, the endpoint is a valid
Prometheus/Nagios scrape target. Token format: `archer_<40-hex-chars>`;
the raw value is shown once at creation. See `GET /api/service-tokens`
in the API reference.

---

## Audit log

Every state-changing admin action since v0.14.0 lands in a
`audit_log` table row. Admins see it via the Audit button in the
top bar.

**What gets logged:**

Action names are snake_case, flat namespace — easier to filter
than a hierarchical scheme and the bounded vocabulary makes
compliance reporting tractable. Add new actions to the same flat
namespace in `internal/server/audit.go` rather than freeform
strings.

| Action | Triggered by |
|---|---|
| `login_success` / `login_failure` / `logout` | `/login` POST / `/logout` |
| `user_register` / `admin_bootstrap` | `/register` POST (v0.14.3) |
| `request_rate_limited` | Unauth flood guard tripped on `/login`, `/register`, or `/api/quiver/checkin` (v0.14.3) |
| `user_create` / `user_role_change` / `user_status_change` / `user_delete` | User mgmt UI |
| `enrollment_token_create` / `enrollment_token_revoke` | Sensors → Tokens |
| `sensor_disenroll` / `sensor_purge` / `sensor_schedule_change` | Sensors modal |
| `sensor_unauthorized_attempt` | `/api/quiver/checkin` for unknown name or bad HMAC (v0.14.1) |
| `feed_create` / `feed_update` / `feed_delete` / `feed_refresh` | Feeds modal |
| `suppression_add` / `suppression_delete` | Suppressions UI |
| `allowlist_edit` / `ioc_edit` | Allowlist / IOC textareas |
| `config_change` / `watch_change` | Settings |
| `finding_status_change` / `finding_escalate` / `finding_note_add` | Findings table + detail (v0.14.1) |
| `finding_import` | `/api/import` |

`finding_*` actions log shape only — never the note body, which can
carry operationally sensitive analyst observations. The note text
itself stays on the finding (preserved in the notes array); the
audit row records `note_length`, escalation IPs/services, and the
status transition. v0.14.1 NEW-32.

`sensor_unauthorized_attempt` lands with `actor_id=NULL` because
sensors aren't users. The `details.reason` field is one of
`unknown_name` (sensor name not in the enrolled-or-disenrolled
set) or `bad_hmac` (name is enrolled but the v2 signature didn't
verify — high-signal: usually means the sensor lost its secret
file or someone has the name list but not the secret). The
`unauthorized_attempts` table remains the live UI surface and is
not displaced — this audit row is for centralised IR queries
alongside admin actions. v0.14.1 NEW-33.

`allowlist_edit` and `ioc_edit` record the *diff* (added/removed
entries, capped at 50 per side with a `diff_truncated` marker for
whole-list replacements) plus a SHA-256 hash of each list state
and the entry counts. Pre-v0.14.2 these audit rows carried the
full pre- and post-edit lists; for teams with large IOC lists
that could mean multi-MB rows blocking the store mutex during
JSON marshaling. The hash makes the audit irrefutable at any
size; the diff makes it human-useful for "who added entry X on
date Y" queries. v0.14.2 NEW-34.

`finding_*` audit rows show TargetName as
`Type src → dst:port` (e.g. `Beacon 10.4.1.7 → 185.99.135.7:443`)
rather than just the finding type — five "Beacon" rows in a
row are otherwise indistinguishable in the audit-log UI. v0.14.2
cosmetic.

`finding_status_change` validates the incoming status against the
finding-status enum (open / acknowledged / escalated). Pre-v0.14.3
the PATCH path accepted any string verbatim, so a buggy automation
client (or a compromised analyst session) could write
`"archived"` and have it persist faithfully — invisible to the
UI's default tab filters but recoverable from the database.
v0.14.3 NEW-37.

`user_register` and `admin_bootstrap` cover the previously-
unaudited `/register` POST path. The bootstrap event (first user
on a fresh deployment, auto-promoted to admin) gets its own
action name because operationally that's the single
highest-privilege account-creation event in the system's
lifetime — worth its own filter. Self-service registrations
land as `user_register` with `actor_id=0` (the user isn't
authenticated to act on their own behalf yet). Both happen *after*
the email-existence timing pad runs, so the existing
enumeration defence is unaffected. v0.14.3 NEW-38.

`logout` lands on every explicit sign-out so session timelines are
reconstructible from the log without inferring end-times from the
absence of subsequent activity. v0.14.3 NEW-44.

**Audit-log flood protection.** The three unauthenticated audit-
emitting paths (`/login`, `/register`, and the unknown-name /
bad-HMAC branches of `/api/quiver/checkin`) are gated behind a
token bucket: 10 requests per minute per source bucket, with
continuous refill (1 token per 6 seconds). The bucket key is the
full IPv4 address; for IPv6, the /64 prefix (NEW-48) so a
residential / cloud attacker rotating through SLAAC privacy
addresses inside their /64 can't bypass the limit. Excess returns
HTTP 429 and emits a `request_rate_limited` audit row **once per
bucket-trip** (NEW-47) — subsequent excess on the same already-
tripped bucket is silently refused. The trip flag clears the next
time the bucket admits a legitimate request, so an attacker who
pauses and resumes audits again on the new trip; an attacker who
sustains their flood audits exactly once.

A legitimate sensor's hourly checkin path **does not consume from
the bucket at all** (v0.14.4 NEW-45). Pre-NEW-45 the rate limit
gated every checkin including successful HMAC-verified ones,
which broke fleets sharing a NAT egress IP — 20 sensors behind
one NAT all consumed from one shared bucket and a mass-restart /
mass-re-enrollment / hourly burst could 429 the 11th-onward
sensor. The asymmetric placement: rate-limit only auth-failure
outcomes, so authenticated successful traffic never touches the
limiter regardless of NAT topology.

Idle buckets are evicted after 10 minutes to bound memory under
long-running distributed floods. v0.14.3 NEW-39 + v0.14.4
NEW-45/47/48.

**IPv6 deployment caveat.** Rate-limit aggregation at the /64
prefix matches the smallest customer allocation unit on most
ISP and cloud networks. An attacker who owns multiple /64s (a
large allocation from a hosting provider, multiple residential
connections) can still rotate buckets — IP-based rate limiting
will always be defeatable by a sufficiently-resourced attacker.
The bucket-trip audit row remains O(1) per /64, so the audit-log
flood path is closed; the open compute-DoS path against bcrypt
is mitigated separately by the timing-pad on the unknown-email
login path (NEW-46) which equalises wall-clock cost across all
failure outcomes.

**Sensors-modal "Unauthorized attempts" surface vs. audit log
under flood.** Two surfaces watch the same event. The
`unauthorized_attempts` table feeds the Sensors-modal UI count;
the audit_log records `sensor_unauthorized_attempt` rows for
incident-response queries. As of v0.14.4 NEW-45 the rate
limiter fires *inside* `recordUnauthorizedCheckin`, so once a
source bucket trips, both the table-row insert and the audit-
log emit are short-circuited until the bucket admits again.
Under a sustained flood the Sensors-modal UI count is bounded
by the first ~10 attempts per bucket cycle while the audit log
shows one `request_rate_limited` row per trip. The audit log
is the authoritative attempt count; the modal UI is for
low-rate "occasional unauthorized attempt" signal. An analyst
reading the UI's count should reconcile against
`audit_log WHERE action IN ('sensor_unauthorized_attempt',
'request_rate_limited') AND source_ip = ?` to see the true
attempt volume. v0.14.5 NEW-54.

**Schema columns** (see migration 0009 for rationale):

- `actor_id` + `actor_email` — actor_email is denormalised at write
  time so the audit row survives the user being deleted. The audit
  trail of a deleted admin's actions stays intact (that's the whole
  point).
- `target_type` + `target_id` + `target_name` — target_name is
  denormalised for the same reason: six months later, "sensor 12"
  is unhelpful; "sensor 12 (edge-fw-east)" is.
- `before_value` + `after_value` (JSON) — for true state
  transitions (role change, feed update, allowlist edit). Empty for
  non-transition events.
- `details` (JSON) — fallback for events without a clean
  before/after shape (login_failure records the reason; feed_refresh
  records the indicator counts; finding_import records the bundle
  sizes).

**Append-only:** the `store` package contains NO UPDATE or DELETE
statements against `audit_log`. This is a code-side invariant, not
a SQLite trigger — a trigger would block the retention-prune query
documented below. Preserve the discipline when adding new
operations.

**What doesn't get logged:**

- Read-only GET endpoints — too noisy.
- Sensor-initiated enrollment — the sensor isn't an admin user.
  (The admin who minted the enrollment token IS logged via
  `enrollment_token_create`, so the trail back to the human is intact.)
- Sensor checkins — logged separately via `last_seen_at`; flooding
  the audit log with checkins would drown out the human actions.
- System-initiated watch ticks — also too noisy.

**Querying directly:**

```sh
docker compose exec archer sqlite3 /data/archer.db '
  SELECT datetime(ts, "unixepoch"), actor_email, action,
         target_type, target_id, target_name, before_value, after_value
  FROM audit_log
  WHERE ts > strftime("%s", "now", "-30 days")
  ORDER BY ts DESC
  LIMIT 100;
'
```

**Incident-response queries:**

```sh
# Everything user X did in the last 7 days (uses idx_audit_log_actor_ts)
docker compose exec archer sqlite3 /data/archer.db '
  SELECT datetime(ts, "unixepoch"), action, target_type, target_name
  FROM audit_log
  WHERE actor_email = "alice@example.com"
    AND ts > strftime("%s", "now", "-7 days")
  ORDER BY ts DESC;
'

# All failed logins in the last 24 hours (uses idx_audit_log_ts_action)
docker compose exec archer sqlite3 /data/archer.db '
  SELECT datetime(ts, "unixepoch"), actor_email, source_ip, details
  FROM audit_log
  WHERE action = "login_failure"
    AND ts > strftime("%s", "now", "-1 day")
  ORDER BY ts DESC;
'
```

**Retention:**

The table is unbounded as of v0.14.0. See
[Deployment hardening](#deployment-hardening-checklist) for the
manual prune query.

---

## TLS certificate rotation

### Auto-generated cert (default)

Cert is valid for 10 years. Rotation isn't a routine concern; if
you must rotate, delete `/data/tls/server.crt` and
`/data/tls/server.key`, restart the container, and re-enroll every
sensor (the pinned fingerprint changes).

### CA-signed cert

1. Generate a new cert + key with your CA. SANs MUST include
   every hostname and IP a sensor might use to reach the server.
2. Stop the container.
3. Replace `/data/tls/server.crt` and `/data/tls/server.key`
   in the volume.
4. Restart the container.
5. Startup validation parses both, verifies expiry, verifies
   key/cert match. A failure surfaces in the container's first
   log lines naming the file.
6. **Sensors using `--pinnedpubkey` will fail until re-enrolled.**
   This is the cost of pinning — when the cert rotates, the
   trust anchor rotates with it. Re-run the install one-liner
   on each sensor. (Future work: a "trust CA bundle" sensor mode
   that lets sensors validate the chain instead of pinning the
   cert. See [Scope decisions](#scope-decisions).)

---

## Disaster recovery

### Symptoms → first step

| Symptom | First check |
|---|---|
| Web UI won't load | `docker compose logs archer` — TLS validation failure on path 1 names the file |
| Sensors all show "stale" simultaneously | Container restart (sessions also dropped) or TLS rotation; check sensor logs for pinning failure |
| One sensor shows "stale" | Check that sensor's `quiver.sh` cron, `/etc/quiver/secret` presence, network reachability |
| Sustained `sensor_unauthorized_attempt` rows with `reason=bad_hmac` for an enrolled sensor name | That sensor's `/etc/quiver/secret` is corrupted or stale. The sensor appears healthy locally (script runs, cron fires) but the HMAC it sends doesn't match what the server stored at enrollment. Fix: re-run the install one-liner from the Sensors modal on the sensor host. v0.14.7 NEW-57. |
| Sustained `sensor_unauthorized_attempt` rows with `reason=unknown_name` from a known-good IP | A sensor whose row was admin-purged is still pushing. Confirm via the Sensors modal that the name isn't in the enrolled list; the sensor host needs `quiver-uninstall.sh` and a fresh install. |
| Findings count dropping | Check archive policy; check if "Discard findings & re-analyze" was triggered |
| Migration error on upgrade | Check `schema_migrations` table state; restore from backup if a partial migration left bad state |
| Audit log empty after upgrade | Migration 0009 didn't run; check `schema_migrations` table |

### Full restore from cold backup

See [Backup and restore](#backup-and-restore) → Restore procedure.

### When in doubt

1. Stop the container.
2. Snapshot the data volume (so anything we touch is recoverable).
3. Read `docker compose logs archer` from the most recent start.
4. Walk the symptom table above.
5. Restore from the most recent verified-good backup if you
   can't resolve in 30 minutes.

---

## Scope decisions

These are *deliberate* non-features. They are documented here so
the team knows what NOT to expect rather than discovering them by
absence.

### Out of scope

- **SSO / OIDC / SAML / cross-deployment identity.** Archer
  authentication is local-only: a per-instance user table, email +
  password, sessions in SQLite. Multi-instance identity is the
  deploying team's problem — there is no shared identity plane and
  there will not be one. If a team runs more than one Archer, each
  is its own user list. If SSO is required, deploy Archer behind an
  authenticating reverse proxy that handles it and pin Archer's
  listener to localhost so the proxy is the only ingress.
- **Multi-tenant separation.** Single-tenant by design. Each
  Archer deployment is one team's view of one network. Use
  separate deployments for separate teams. The audit log is
  per-instance; do not attempt to merge audit logs across
  instances — `actor_id` is local-scope and would collide.
- **Public OSS positioning.** The codebase is on GitHub
  publicly, but the audience for the *product* is internal hunt
  teams. Onboarding docs assume an operator who already knows
  what Zeek is.
- **Hot config reload without restart.** Settings persist
  immediately and take effect on the next analysis tick; for
  changes that affect the running listener (TLS, port), restart
  is the upgrade path.

### Roadmapped (not yet)

- **Metrics endpoint** (`/metrics` Prometheus-style) — see
  MATURATION_PLAN section 11. Monitor Archer with your existing
  monitoring stack rather than via UI screen-scraping.
- **Trust-CA-bundle sensor mode** — alternative to pubkey
  pinning so CA rotation doesn't force fleet-wide re-enrollment.
  See MATURATION_PLAN section 11.
- **Audit-log retention UI** — currently manual SQL. See the
  retention note in [Deployment hardening](#deployment-hardening-checklist).
- **Password complexity / lockout policies** — enforce at the
  onboarding-flow layer for now.

If a team needs one of these and the workaround above doesn't fit,
the right path is to file an issue with the use case rather than
attempt an integration that doesn't match Archer's deployment
model.
