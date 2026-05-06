# Quiver — Sensor Log Shipping

Quiver is the sensor-side companion to Archer. A Quiver sensor is any Linux host that runs Zeek and ships its rotated logs to the Archer server on a schedule. Archer treats each sensor as its own dataset under `/logs/<sensor-name>/`, so analyzers, campaigns, and the host risk model all keep per-sensor scope without any extra configuration.

Quiver is fully optional — if you're feeding Archer logs by hand or via your own pipeline, the Sensors modal stays empty and nothing changes. Once you enroll a sensor, daily-run + watch-mode analysis automatically picks up the new tree.

---

## Architecture

```
       ┌───────────────────── Archer host ──────────────────────┐
       │                                                         │
 [analyst browser] ──HTTP─────►  :8080  ── Archer (UI + API) ──► /data/archer.db
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

- **Enrolled Sensors** — name, host, status, slot, last seen, health (`✓ on time` / `pending` / `⚠ missed` / `never`), and admin actions (Slot, Disenroll, or Purge after disenroll).
- **Pending Tokens** — outstanding enrollment tokens that haven't been used yet. Used tokens are filtered out automatically (they show up as Enrolled Sensors instead). Click **Revoke** on any row to invalidate a token before it's used.
- **Unauthorized Attempts** — checkins from sensor names Archer doesn't recognize, with source IP, attempt count, and first/last-seen timestamps. Old rows auto-prune after 30 days unless pinned. From here you can **Enroll this** (pre-fills the override name in the new-token dialog) or **Dismiss** the row.

The **Slot** and **Last seen** columns render in whatever timezone you've configured for watch mode (the `Timezone` field in the sidebar's **Watch Mode** section). The timezone field auto-saves on change — no need to enable watch mode for it to stick. Findings timestamps stay in UTC throughout the rest of the UI.

### 3. Reassign a sensor's push minute

Click **Slot** on an enrolled row and pick a minute (0–59). Sensors push every hour at the assigned minute-of-hour; randomization at enroll time prevents 20 sensors from synchronizing at HH:00. The new minute takes effect on the sensor's next hourly checkin (it rewrites its own `/etc/cron.d/quiver` from the checkin response).

### 4. Disenroll a sensor

Click **Disenroll** (red button). Archer:
- Flips the sensor row to `disenrolling`
- Removes the sensor's `authorized_keys` line on the server (push channel closed immediately)
- Leaves the sensor's `/logs/<name>/` tree in place

The sensor itself doesn't know yet. The next time its hourly cron fires, the HTTPS checkin returns `{"status":"disenrolled"}` and the script invokes `quiver-uninstall.sh` to wipe its install footprint.

### 5. Purge

Once a row is in `disenrolled` state, the **Purge data** button appears. Purging:
- Moves `/logs/<name>/` to `/logs/_archived/<name>-<timestamp>/` (logs aren't deleted; analysts can still review them)
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

The first push (run during install) is special: `FIRST_SYNC=1` is set in the environment, the mtime filter is dropped, and the entire log tree is shipped. After that, every recurring push is the last 24 hours' worth of completed `.gz` files. rsync's `--ignore-existing`-equivalent behavior (size + mtime check) means re-shipping an already-pushed file is a no-op.

**rsync copies, never moves.** Quiver invokes `rsync -avRq` with no `--remove-source-files` flag, so every `.gz` Archer ingests is a copy — the original stays in place under the sensor's local Zeek log directory. Whatever retention policy Zeek (or the sensor's filesystem) enforces is unaffected by Quiver. If a sensor disk fills up, that's a sensor-side rotation/retention issue, not an Archer-side one. The only data Archer ever deletes from a sensor is via its own admin-triggered `Purge data` action against `/logs/<name>/` on the Archer host — and even that just moves the tree to `/logs/_archived/<name>-<timestamp>/`, never reaches back to the sensor.

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

### `quiver: no Zeek log directory found`

Expected on hosts that aren't running Zeek, or where Zeek logs live somewhere unusual. Set `LOCAL_LOGS_DIR=/your/path` in `/etc/quiver/config` and re-run. Or if Zeek is in one of the standard places (Security Onion: `/nsm/zeek/logs`, default Zeek: `/opt/zeek/logs`, `/usr/local/zeek/logs`), the script picks it up automatically.

---

## Sensor-facing endpoints (no session auth)

These are served on the TLS listener (`:8443`) and the rsync sshd (`:22` → host `:2222`). Sensors don't have user sessions; they authenticate via pinned TLS fingerprint (HTTP) and per-sensor ed25519 key (rsync).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/quiver/install.sh` | Renders the install bash for the requesting host. The TLS fingerprint, host, and ports get substituted into the embedded template; the daily and uninstall scripts are inlined as base64 so the install runs without a second network hop. |
| `POST` | `/api/quiver/enroll` | Body `{token, name, host, pubkey}`. Validates the token (single-use, 24h TTL), writes the `authorized_keys` line, creates `/logs/<name>/`, persists the sensor row, returns `{name, schedule_hour:0, schedule_minute}`. |
| `POST` | `/api/quiver/checkin` | Body `{name}`. Returns `{"status":"enrolled","schedule":{"hour":0,"minute":N}}` or `{"status":"disenrolled"}` or `{"status":"unknown"}` (and records an `unauthorized_attempts` row, plus pushes an SSE event). |

`schedule_hour` is always `0` under hourly mode (the cron line uses `*` for the hour); the field is kept on the response for backward compatibility with daily-mode sensors that haven't been re-enrolled yet.
