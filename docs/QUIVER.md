# Quiver — Sensor Log Shipping

Quiver is the sensor-side companion to Archer. A Quiver sensor is any Linux host that runs Zeek and ships its rotated logs to the Archer server on a schedule. Archer treats each sensor as its own dataset under `/logs/<sensor-name>/`, so analyzers, campaigns, and the host risk model all keep per-sensor scope without any extra configuration.

Quiver is fully optional — if you're feeding Archer logs by hand or via your own pipeline, the Sensors modal stays empty and nothing changes. Once you enroll a sensor, daily-run + watch-mode analysis automatically picks up the new tree.

---

## Architecture

```
       ┌───────────────────── Archer host ──────────────────────┐
       │                                                         │
 [analyst browser] ──HTTPS────►  :8443  ── Archer (UI + API) ──► /data/archer.db
                                                  │
                                                  ▼
                                       ┌──────────────────────┐
                                       │  /logs/<sensor>/     │  ◄── analyzers
                                       │     YYYY-MM-DD/      │
                                       └──────────────────────┘
                                                  ▲
                                                  │ rsync over ssh
                              ┌───────────────────┴─────────────┐
                              │                                 │
        :8443 (HTTPS, pinned-pubkey)               :22 / mapped to host :2222
        sensor checkin + install.sh                rrsync push, pubkey-only
        (same listener as the UI;                   (separate sshd, not
         pinned by sensors, chain-validated         the HTTP server)
         by browsers)
                              │                                 │
       ┌──────── Sensor host ─┴─────────────────────────────────┴─────────┐
       │  /etc/cron.d/quiver  ──►  /usr/local/bin/quiver.sh               │
       │       │                       │                                  │
       │       └─ runs hourly at        ├─ HTTPS checkin: enrolled?       │
       │          assigned minute       ├─ rsync push of last 24h .gz     │
       │                                └─ self-uninstall on disenroll    │
       └──────────────────────────────────────────────────────────────────┘
```

Two separate channels:

| Channel | Direction | Transport | Auth | Purpose |
|---|---|---|---|---|
| **Pull-control** | sensor → Archer | HTTPS, port 8443 | TLS pubkey-pinned (`curl --pinnedpubkey`) | Enrollment, daily checkin (am-I-still-enrolled, what's my slot) |
| **Log push** | sensor → Archer | rsync over ssh, port 22 (mapped to host 2222) | per-sensor ed25519 keypair, `command="rrsync -wo /logs/<name>/"` in `authorized_keys` | Pushes the last 24 hours of `.gz`'d Zeek logs |

The pull-control channel is what makes disenrollment work without a sensor-side daemon. When an admin disenrolls a sensor, Archer flips the row's status; the next time the sensor's hourly cron fires, its checkin returns `{"status":"disenrolled"}` and the script self-cleans (cron entry, scripts, config, sudoers fragment, SSH key — everything except the `quiver` system user, which is harmless).

---

## Operator workflow

All steps below assume you're an Archer admin (only admins can enroll, disenroll, purge, or reassign slots).

### 1. Enroll a sensor

1. **Sensors modal** → click **+ Enroll new sensor**
2. (Optional) Pre-set the sensor name. Leave blank to use the sensor's hostname; set a value to override (handy if the hostname is generic like `localhost.localdomain`).
3. **Generate token** — Archer mints a single-use token valid for 24 hours and shows the install command. The status row says "Waiting for sensor to run the install command…"
4. Click **Copy** and paste on the sensor as root. Example:
   ```sh
   sudo curl -fsSL -k --pinnedpubkey "sha256//VyoSm6ub..." \
       https://192.0.2.10:8443/quiver/install.sh | sudo bash -s -- TOKEN
   ```
5. The sensor's install runs autonomously (~10–30 seconds): installs missing dependencies, creates the `quiver` system user, generates an ed25519 keypair, enrolls with Archer, drops the daily script and cron entry, and runs a full first-sync of available logs.
6. The dialog flips to "✓ Enrolled as `<name>`" the instant Archer records the enrollment. Close the dialog — the parent Sensors table refreshes and the new row appears.

### 2. Monitor

The Sensors modal has three tables:

Each row carries a kebab (⋮) at the right edge that opens a popover with the row's actions:

- **Enrolled Sensors** — name, host, status, slot, last seen, health (`✓ on time` / `pending` / `⚠ missed` / `never`). Kebab: **Reassign slot**, **Disenroll**, or **Purge data** (after disenroll).
- **Pending Tokens** — outstanding enrollment tokens that haven't been used yet. Used tokens are filtered out automatically (they show up as Enrolled Sensors instead). Kebab on a fresh token: **Show enrollment command** (replays the curl one-liner with the same pulse-dot → green ✓ confirmation flow as the fresh-generate path) and **Revoke**. Expired tokens: just **Revoke**.
- **Unauthorized Attempts** — checkins from sensor names Archer doesn't recognize, with source IP, attempt count, and first/last-seen timestamps. Old rows auto-prune after 30 days unless pinned. Kebab: **Enroll this sensor** (pre-fills the override name in the new-token dialog) or **Dismiss attempt**.

All timestamps in this modal render as UTC `YYYY-MM-DD HH:MM` (full `YYYY-MM-DD HH:MM:SS UTC` on hover), matching the Feeds modal and the rest of the UI's UTC convention (v0.19.0). The **Slot** column is timezone-independent — sensors push every hour at the assigned minute-of-hour, so it shows as `:MM hourly`.

### 3. Reassign a sensor's push minute

Open the row's kebab (⋮) and pick **Reassign slot**, then enter a minute (0–59). Sensors push every hour at the assigned minute-of-hour; randomization at enroll time prevents 20 sensors from synchronizing at HH:00. The new minute takes effect on the sensor's next hourly checkin (it rewrites its own `/etc/cron.d/quiver` from the checkin response).

### 4. Disenroll a sensor

Open the row's kebab (⋮) and pick **Disenroll** (red). Archer:
- Flips the sensor row to `disenrolling`
- Removes the sensor's `authorized_keys` line on the server (push channel closed immediately)
- Leaves the sensor's `/logs/<name>/` tree in place

The sensor itself doesn't know yet. The next time its hourly cron fires, the HTTPS checkin returns `{"status":"disenrolled"}` and the script invokes `quiver-uninstall.sh` to wipe its install footprint.

### 5. Purge

Once a row is in `disenrolled` state, the kebab menu surfaces **Purge data** (red). Purging:
- Moves `/logs/<name>/` to `/logs/_archived/<name>/<timestamp>/` — nested under the sensor name, not hyphen-delimited (v0.12.0 NEW-21 layout: the hyphen-prefix form collided when one sensor's name was a prefix of another's, e.g. `abc` vs `abc-east`). Logs aren't deleted; analysts can still review them.
- Re-tags any existing findings from that sensor's logs to the `_archived` namespace
- Drops the sensor row from the database

---

## Supported sensor distributions

The install script detects the package manager and auto-installs anything missing. No manual prep required for fresh hosts.

| Distro family | Detected via | Installs (if missing) | Cron daemon |
|---|---|---|---|
| Debian / Ubuntu / Kali | `apt-get` | `rsync`, `openssh-client`, `cron`, `sudo`, `util-linux` (`flock`) | `systemctl enable --now cron` |
| RHEL / Oracle / Rocky / Alma 8+ | `dnf` | `rsync`, `openssh-clients`, `cronie`, `sudo` | `systemctl enable --now crond` (+ `restorecon` for SELinux) |
| RHEL / CentOS 7 | `yum` | same as RHEL 8+ | same |
| openSUSE / SLES | `zypper` | `rsync`, `openssh`, `cronie`, `sudo` | `systemctl enable --now cron` |
| Alpine | `apk` | `rsync`, `openssh-client`, `busybox-suid` (provides crond) | `rc-update add crond default` |

Hostname resolution falls back through `hostname -s` → `hostname` → `/etc/hostname` → `uname -n`, so it works even on RHEL 9 minimal where the `hostname` package isn't always installed.

On RHEL/Oracle/Rocky/Alma the install runs `restorecon -F` over every file it drops (`/usr/local/bin/quiver*.sh`, `/etc/cron.d/quiver`, `/etc/sudoers.d/quiver`, `/etc/quiver/*`) so SELinux's enforcing default doesn't block cron from exec'ing the daily script.

---

## Sensor-side artifacts

What `install.sh` drops on a sensor host:

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/usr/local/bin/quiver.sh` | root | 755 | Daily runner: HTTPS checkin → rsync push |
| `/usr/local/bin/quiver-uninstall.sh` | root | 755 | Self-cleanup, called via the sudoers fragment when Archer reports `disenrolled` |
| `/etc/quiver/config` | root | 644 | Server host, ports, TLS fingerprint, sensor name, schedule, key paths |
| `/etc/quiver/secret` | quiver | 600 | Per-sensor `checkin_secret` returned once at enrollment; HMAC-SHA256 key for every checkin (v0.12.0+ protocol v2, NEW-16). |
| `/etc/quiver/keys/id_ed25519` | quiver | 600 | Per-sensor ed25519 keypair generated at enroll |
| `/etc/quiver/known_hosts` | quiver | 644 | Pinned Archer sshd host key |
| `/etc/cron.d/quiver` | root | 644 | `${MINUTE} * * * * quiver /usr/local/bin/quiver.sh` |
| `/etc/sudoers.d/quiver` | root | 440 | Single line: `quiver ALL=(root) NOPASSWD: /usr/local/bin/quiver-uninstall.sh` |
| `/var/lib/quiver/quiver.lock` | quiver | 600 | Single-instance flock lock — chosen over `/var/lock/` so it works on RHEL where `/var/lock` is root-only |
| `quiver` (system user) | — | — | Owns the keypair, runs the cron job, restricted to `/bin/sh` |

The `quiver` user has no password (locked, but enabled for pubkey auth), no shell access from outside, and the only privileged operation it can perform is `sudo /usr/local/bin/quiver-uninstall.sh` — and only via the sudoers fragment that's deleted by that very script.

---

## Schedule and cadence

Sensors push **hourly at a randomized minute-of-hour** (0–59), assigned by the server at enroll time. This is a deliberate change from the original daily cadence — hourly aligns with Zeek's natural log rotation (`current/*.log` → `YYYY-MM-DD/*.log.gz` at the top of each hour), keeps detection latency reasonable for an active hunt team, and surfaces sensor failures within ~2 hours instead of ~25.

Each push:
1. Acquires `/var/lib/quiver/quiver.lock` (no overlapping runs)
2. HTTPS checkin to Archer (`/api/quiver/checkin`)
3. Walks `LOCAL_LOGS_DIR` (default search list: `/nsm/zeek/logs`, `/opt/zeek/logs`, etc.) for `.gz` files modified in the last 24 hours
4. Filters to log types Archer's analyzers consume (`conn|dns|http|ssl|x509|known_certs|capture_loss|notice|stats|weird|files`)
5. rsync push under `nice -n 19 ionice -c 3` and a 7080-second timeout (so the next cron tick can't overlap)

The first push (run during install) is special: `FIRST_SYNC=1` is set in the environment and the install-time backfill window applies instead of the recurring 24-hour mtime filter. Every recurring push after that is the last 24 hours' worth of completed `.gz` files. rsync's `--ignore-existing`-equivalent behavior (size + mtime check) means re-shipping an already-pushed file is a no-op.

**Initial backfill window — admin-controlled at install.** During `install.sh` the operator is prompted for how many days of historical Zeek logs the sensor should ship on its first push. Empty / Enter = ship all available history (the legacy default); any positive integer N means `find -mtime -N` (only files modified within the last N days). The chosen value is persisted to `/etc/quiver/config` as `INITIAL_BACKFILL_DAYS=N` and only affects FIRST_SYNC=1 invocations — recurring cron pushes always use the 24-hour window regardless. For non-interactive deployments (config management, CI), set `INITIAL_BACKFILL_DAYS=N` in the environment before running install.sh and the prompt is skipped. To re-run the install-time backfill manually after install (e.g. you wanted 90 days but answered 7 by mistake), edit `/etc/quiver/config`'s `INITIAL_BACKFILL_DAYS=` line and run `sudo FIRST_SYNC=1 sudo -E -u quiver /usr/local/bin/quiver.sh`.

Why this knob matters: a freshly enrolled sensor with 6 months of local Zeek history would otherwise ship every byte of it on first push — over a slow link or against a busy Archer that's churning through analysis, that's a multi-hour rsync. The backfill cap lets the operator say "I only need the last 30 days from this sensor" and skip the rest.

**rsync copies, never moves.** Quiver invokes `rsync -avRqO --no-perms --timeout=60` with no `--remove-source-files` flag, so every `.gz` Archer ingests is a copy — the original stays in place under the sensor's local Zeek log directory. Whatever retention policy Zeek (or the sensor's filesystem) enforces is unaffected by Quiver. If a sensor disk fills up, that's a sensor-side rotation/retention issue, not an Archer-side one. The only data Archer ever deletes from a sensor is via its own admin-triggered `Purge data` action against `/logs/<name>/` on the Archer host — and even that just moves the tree to `/logs/_archived/<name>/<timestamp>/`, never reaches back to the sensor.

---

## Health monitoring

The Health column in the Enrolled Sensors table classifies each sensor based on `last_seen_at` (set on every HTTPS checkin):

| Badge | Meaning |
|---|---|
| **✓ on time** | Sensor checked in within the last hour. |
| **pending** | Slot just fired; sensor hasn't checked in yet but it's still inside the 30-minute grace window. |
| **⚠ missed** | More than 1h 30m since last checkin. Likely sensor crashed, lost network, or stopped pushing. |
| **never** | Sensor enrolled but has never been seen — the install completed without ever firing a checkin (rare; usually a network/firewall problem). |
| **—** | Disenrolling or disenrolled — health is not meaningful. |

Live updates: when a sensor checks in with an unrecognized name, Archer pushes an SSE `unauthorized_attempt` event so the Sensors modal updates the Unauthorized Attempts table without a manual refresh. When a fresh enrollment completes, an SSE `sensor_enrolled` event refreshes the Enrolled table and flips the in-flight enrollment dialog to its confirmation tick.

---

## Persistence

Everything Archer learns about sensors survives container rebuilds. The named volumes in `docker-compose.yml`:

| Volume | Mount | Contents |
|---|---|---|
| `archer-data` | `/data` | SQLite DB (`archer.db`) — sensors, tokens, unauthorized_attempts; TLS cert + key |
| `archer-sshd` | `/etc/ssh/keys` | sshd host keys — sensors don't see host-key-mismatch warnings after a rebuild |
| `archer-quiver` | `/home/quiver/.ssh` | `authorized_keys` — every enrolled sensor's pinned key line |
| `./logs` (host bind) | `/logs` | Per-sensor log trees |

`./start.sh up` runs `docker compose up -d --build` which rebuilds the image and recreates the container but reattaches all four. The only path to losing state is `docker compose down -v` (note the `-v`); the bundled `start.sh` never passes that flag.

The entrypoint also re-asserts ownership and perms on `/home/quiver/.ssh` on every boot, so even if an old (pre-fix) container left the volume root-owned, the next start corrects it.

---

## Troubleshooting

### `Permission denied (publickey)` from rsync

Two common causes:

1. **`authorized_keys` is root-owned.** sshd's privilege-separated process drops to `quiver` (uid 1000) before reading the file; if the file is mode 0600 owned by root, the read fails. Older Archer builds (before the `matchParentOwner` fix) could leave the file root-owned after a disenroll/re-enroll cycle. Fix: `docker exec archer chown quiver:quiver /home/quiver/.ssh/authorized_keys`. The current build chowns automatically on every write.
2. **Stale sensor row with the same name.** If you re-enroll without disenrolling first, the server sends `409 a sensor with this name is already enrolled`. Disenroll + Purge in the UI, then re-enroll.

### `Connection closed by invalid user quiver`

The `quiver` account in the container has its `/etc/shadow` password set to `!` (locked). Alpine's openssh is built without PAM, so its `allowed_user` check refuses locked accounts even with pubkey-only sshd config. Fix: `docker exec archer sed -i 's/^quiver:!:/quiver:*:/' /etc/shadow`. The current Dockerfile does this at build time; the symptom only appears on very old image builds.

### `FileNotFoundError: '/logs/<sensor>'` from rrsync

The per-sensor log directory wasn't created at enrollment. Older builds didn't pre-create it; the current enrollment handler does. Fix: `docker exec archer sh -c 'mkdir -p /logs/<name> && chown quiver:quiver /logs/<name>'`, or disenroll/purge/re-enroll.

### `exec: 200: not found` in the daily script

Old `quiver.sh` used `exec 200>"$LOCK"` for flock fd setup. Dash (Debian's `/bin/sh`) only accepts single-digit fds in that syntax. Current builds use fd 9. Fix on the sensor: `sudo sed -i 's/exec 200>/exec 9>/; s/flock -n 200/flock -n 9/' /usr/local/bin/quiver.sh` — or just disenroll/re-enroll to pick up the current install template.

### Lock file permission denied

`/var/lock` on RHEL/Oracle is root-owned 0755 — the `quiver` user can't write there. Current builds use `/var/lib/quiver/quiver.lock` which is created at install time. Fix on the sensor: `sudo sed -i 's|/var/lock/quiver.lock|/var/lib/quiver/quiver.lock|' /usr/local/bin/quiver.sh`.

### Archive reports "0 archived" / `permission denied` on source removal

The archive worker runs as the `archer` user (uid 1001). Zeek date-tree
subdirectories (`YYYY-MM-DD/`) are created by rsync running as `quiver`
(uid 1000) and land `quiver:quiver 0755`. `archer` cannot delete files
from those directories; the archive copies every file to `/data/archive`
successfully, then fails `os.Remove(src)` with `permission denied` and
counts every file as skipped.

`entrypoint.sh` fixes this automatically at container startup by chowning
all depth-2 log dirs to `archer:archer 0775`. If you hit this after
upgrading (old container image, new code not yet applied), rebuild:

```bash
docker compose up -d --build
```

If a previous failed archive run left orphaned copies in both `/logs` and
`/data/archive`, clean up the duplicates after rebuilding:

```bash
docker exec archer sh -c '
find /logs -mindepth 3 -type f | while IFS= read -r src; do
    dst="/data/archive/${src#/logs/}"
    [ -f "$dst" ] && rm "$src"
done
'
```

### `quiver: no Zeek log directory found`

Expected on hosts that aren't running Zeek, or where Zeek logs live somewhere unusual. Set `LOCAL_LOGS_DIR=/your/path` in `/etc/quiver/config` and re-run. Or if Zeek is in one of the standard places (Security Onion: `/nsm/zeek/logs`, default Zeek: `/opt/zeek/logs`, `/usr/local/zeek/logs`), the script picks it up automatically.

---

## Sensor-facing endpoints (no session auth)

These are served on the TLS listener (`:8443`) and the rsync sshd (`:22` → host `:2222`). Sensors don't have user sessions; they authenticate via pinned TLS fingerprint (HTTP) and per-sensor ed25519 key (rsync).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/quiver/install.sh` | Renders the install bash for the requesting host. The TLS fingerprint, host, and ports get substituted into the embedded template; the daily and uninstall scripts are inlined as base64 so the install runs without a second network hop. |
| `POST` | `/api/quiver/enroll` | Body `{token, name, host, pubkey, protocol_version}` (current `protocol_version` is `2`). Validates the token (single-use, 24h TTL) and protocol version, writes the `authorized_keys` line, creates `/logs/<name>/`, persists the sensor row, returns `{name, schedule_hour:0, schedule_minute, protocol_version, checkin_secret}`. **`checkin_secret` is returned exactly once at enrollment** — `quiver.sh` persists it at `/etc/quiver/secret` (mode `0600`) and uses it to HMAC-SHA256-sign every subsequent checkin (NEW-16). The server never echoes the secret on any other endpoint. |
| `POST` | `/api/quiver/checkin` | Body `{name, protocol_version}` plus an `X-Quiver-Sig` header carrying the hex-encoded HMAC-SHA256 of the request body keyed by the sensor's `checkin_secret`. Missing or invalid signatures land in the unauthenticated-attempts bucket. Returns `{"status":"enrolled","schedule":{"hour":0,"minute":N},"protocol_version":2}`, `{"status":"disenrolled","protocol_version":2}`, `{"status":"unknown","protocol_version":2}` (and records an `unauthorized_attempts` row, plus pushes an SSE event), or `{"status":"protocol_unsupported","sensor_version":N,"server_version":2,"supported_versions":[2]}` when the sensor's protocol version isn't in the server's supported set. |

`schedule_hour` is always `0` under hourly mode (the cron line uses `*` for the hour); the field is kept on the response for backward compatibility with daily-mode sensors that haven't been re-enrolled yet.

## Protocol versioning

Quiver speaks a versioned wire protocol between the sensor and the Archer server. Every enrollment and checkin carries a `protocol_version` integer; the server validates it against an internal `supportedQuiverProtocols` set and rejects mismatches with a structured error. Without this handshake, an old sensor talking to a newer server would silently rsync to a stale path or fail enrollment with an opaque token error — the version field turns "weird unexplained breakage" into "your sensor is on v1, server requires v2; please reinstall from `<archer>/quiver/install.sh`."

`QuiverProtocolVersion` is currently **`2`** (constant in `internal/server/quiver_protocol.go`). v1 was dropped at v0.12.0 NEW-16 when the per-sensor HMAC checkin-secret was introduced — there's no in-band path to retroactively issue a checkin secret to a v1 sensor, so the operator's upgrade is to re-enroll every sensor against the v0.12.0+ server. A missing `protocol_version` field resolves to v1 (and therefore unsupported), so install scripts must explicitly send `2`.

### Compatibility matrix

The server records the version each sensor reports — written to `sensors.protocol_version` on enrollment and refreshed on **every** checkin (migration 0030), so a row tracks the version of the binary that last checked in, not just its enroll-time value. The Sensors modal reads `protocol_version` from `/api/sensors` and the server's own version from `/api/sensors/info` (`server_protocol_version` + `supported_protocol_versions`) and renders a one-line tally above the enrolled-sensors table: green when the fleet is uniform and current, amber (`N behind`) when any enrolled sensor reports a version older than the one the server prefers. Each sensor row also carries a **Protocol** column flagging a behind sensor with `v<N> ⚠`. Because today's `supportedQuiverProtocols` set is a single version, the matrix is uniform (`all current`) until a future bump makes a mixed fleet reachable — at which point it answers "which fielded sensors still need a re-enroll?" at a glance. A `0`/`unknown` value means a row that no checkin has refreshed since the upgrade that added the column.

### What the current version (`v2`) covers

The protocol contract pinned at v2 is everything the sensor and server agree on out-of-band today. Anything in this list changing in a way old clients can't muddle through is what triggers a v3 bump.

**Wire shapes**

- **Enrollment payload**: `{token, name, host, pubkey, protocol_version}`. Token is single-use; pubkey is an OpenSSH-format ed25519 line.
- **Enrollment response**: `{name, schedule_hour, schedule_minute, protocol_version, checkin_secret}`. `checkin_secret` is returned exactly once and stored at `/etc/quiver/secret` (mode `0600`) on the sensor; the server never echoes it on any other endpoint (audit/export/SSE) per NEW-16.
- **Checkin payload**: `{name, protocol_version}` body **plus** an `X-Quiver-Sig` header carrying `hex(HMAC-SHA256(body, checkin_secret))`. Missing or invalid signatures bucket as unauthorized checkin attempts.
- **Checkin response**: status discriminator (`enrolled` / `disenrolled` / `unknown` / `protocol_unsupported`) plus version echo.

**Identity and crypto**

- **Sensor name regex**: `^[a-z0-9][a-z0-9_-]{0,51}$`. Enforced both client-side (`is_safe()` in `install.sh`) and server-side (`validSensorName` in `handlers_quiver.go`). Filesystem-safe so the name can serve directly as a `/logs/<name>/` directory; capped at 52 chars to leave headroom for path tooling.
- **Pubkey algorithm**: ed25519, generated via `ssh-keygen -t ed25519`. Switching to RSA, ECDSA, ssh certificates, or any other auth model is a v2 concern.
- **TLS pinning**: SHA-256 fingerprint of the server's certificate, baked into the install one-liner and `/etc/quiver/config` as `ARCHER_TLS_FP`. Curl's `--pinnedpubkey "sha256//<fp>"` enforces it on every request. **Fail-closed on an empty pin (v0.55.0)**: if the fingerprint is empty — the server rendered a blank `ARCHER_TLS_FP`, or the config was hand-edited — `install.sh` refuses to enroll and `quiver.sh` refuses to check in, printing an error and exiting non-zero, rather than silently proceeding over an unpinned transport. An empty `--pinnedpubkey "sha256//"` is no pin at all, so the guard closes that gap explicitly.

**Transport**

- **Ports**: HTTPS on 8443, SSH on 22 (mapped host-side to 2222 in the bundled `docker-compose.yml`).
- **Rsync directory layout**: server-side rrsync chroot at `/logs/<sensor-name>/`, forced via `command="rrsync -wo /logs/<name>/"` in `authorized_keys` (the `-w` is write-only, `-o` is read-only metadata). Sensor pushes use `-avRqO --no-perms` so the YYYY-MM-DD/file.log.gz tree is preserved relative to the chroot root; `-O --no-perms` are load-bearing — rrsync runs as `quiver` and doesn't own the target dir, so without them every push fails rc=23 on a `utimes()`/`chmod()` it can't perform.
- **Source-files-never-deleted semantics**: rsync runs *without* `--remove-source-files`. Every `.gz` Archer ingests is a copy; the server never deletes from the sensor. Local rotation/retention is the sensor operator's responsibility. Reversing this is a v2 break — sensors built for v1 assume their files are safe.

**Schedule and content**

- **Schedule contract**: hourly cadence, server-assigned minute-of-hour. The daily-mode `schedule_hour` field is preserved on responses but the cron line uses `*` for the hour. Server can reassign the minute via the checkin response; sensor rewrites `/etc/cron.d/quiver` and `/etc/quiver/config` in place.
- **First-sync semantics**: `FIRST_SYNC=1` (set by `install.sh`'s first invocation only) honors `INITIAL_BACKFILL_DAYS` from `/etc/quiver/config` — empty means "ship the entire local Zeek log tree," an integer N means `-mtime -N`. Recurring cron runs always use `-mtime -1` regardless of `INITIAL_BACKFILL_DAYS`.
- **Accepted Zeek log types**: the regex `(conn|dns|http|ssl|x509|known_certs|capture_loss|notice|stats|weird|files)` in `quiver.sh` filters which `.gz` files are eligible to push. Adding a new analyzer family that needs a different log type (e.g. `tunnel`, `dpd`) requires sensor scripts to be updated — that's a v2 concern even though the wire shape doesn't change. Operators with stale sensor scripts would silently miss the new log type otherwise.

### When to bump

Bump `QuiverProtocolVersion` and add the new version to `supportedQuiverProtocols` whenever any of the above changes in a way the previous version's sensor can't muddle through. Concrete examples:

- Renaming the rsync chroot from `/logs/<name>/` to `/logs/<sensor-id>/`.
- Adding a required field to enrollment (a new field that absence-of breaks the server's flow).
- Changing the schedule contract from hourly to operator-configurable cadence pushed from the server.
- Switching the auth model (e.g. SSH cert auth in place of pinned pubkey).
- Adding a server-pushed config endpoint that sensors are expected to poll.

Cosmetic or backwards-compatible additions don't need a bump — adding an optional field to enrollment that an older sensor can omit is fine.

### Compatibility window

When you bump from v`N` to v`N+1`:

1. Add `N+1` to `supportedQuiverProtocols` and set `QuiverProtocolVersion = N+1`.
2. Keep `N` in the supported set for at least one minor release — that's the deprecation cycle. Document the planned removal in CHANGELOG under `### Deprecated`.
3. Bump `PROTOCOL_VERSION` in `quiver_assets/install.sh` so freshly enrolled sensors use the new version.
4. In the release after that minor, remove `N` from the supported set. Document under `### Breaking`.

This means a sensor in the field has at least one minor-version cycle to be reinstalled before it loses connectivity.

### Backwards compatibility for pre-versioning sensors

Sensors enrolled before protocol versioning landed (Archer < v0.2.0) don't send a `protocol_version` field. The server treats a missing field as `1` for one minor cycle so existing fleets keep enrolling and checking in during the upgrade window. Once every fielded sensor has run the new install one-liner (or pushed at least one checkin from an updated `quiver.sh`), the server can flip missing-field handling to a hard error in a future minor.

### Error surfaces

- **Enrollment with unsupported version**: HTTP 400 with `{error, sensor_version, server_version, supported_versions}`. The install script logs the response body and exits before committing local state, so the operator sees the failure at install time.
- **Checkin with unsupported version**: HTTP 200 with `{status: "protocol_unsupported", sensor_version, server_version, supported_versions}`. The checkin response shape is already a status discriminator; using HTTP 200 means `curl -fsSL` doesn't swallow the body. `quiver.sh` logs the supported-versions list and exits cleanly so cron tries again next tick (still failing) until the operator reinstalls from the current Archer build.
