# QUICKSTART_OPS — Archer deployment TL;DR

> Triage doc for the deploying engineer. The full operator runbook
> is `OPERATIONS.md` (~600 lines). This is the 5-minute version:
> what to run, what to test, what to know before you put it in
> front of analysts.
>
> If you have time, read OPERATIONS.md first. If you don't,
> follow this and bookmark OPERATIONS.md for the questions that
> come up later.

---

## Pre-flight (answer these before deploying)

1. **Where will sensors reach the server?** Hostname or IP +
   port 8443 (HTTPS) and port 2222 (rsync over SSH). If the
   admin URL differs from the sensor-facing URL, set the
   override via `PUT /api/sensors/host` (admin-only) — see
   `docs/API.md` for the body shape.
2. **Who registers first?** The first registered user is auto-
   promoted to admin. Register from a trusted browser session.
3. **Is the host backed up?** Backup is a single SQLite file
   plus the TLS material. Make sure your backup story covers
   the volume *before* you have data worth losing. See restore
   commands below.

---

## Deploy (10 commands)

```sh
# 1-4: clone + start
git clone https://github.com/BushidoCyb3r/Archer.git
cd Archer
./start.sh                                      # builds image, derives CPU/RAM, brings up the stack
docker compose ps                               # confirm 'archer' is Up

# 5-7: first login
# Open https://<host>:8443/ in a browser (accept the self-signed cert
# the first time — the fingerprint is what sensors will pin against)
# Register the first user (becomes admin automatically)
# Sign in

# 8-10: enroll one sensor (Sensors modal → + Enroll new sensor)
# Copy the install one-liner shown in the UI
# Run it on the sensor host as root
# Verify: Sensors modal should show the new sensor "fresh" within 60s
```

After this you have a working Archer. Analyze logs lands in the
top toolbar once Zeek logs start arriving in `/logs/<sensor>/`.

---

## Restore (5 commands)

If you're recovering on a fresh host from a database backup +
TLS-material backup:

```sh
# 1-2: stop and wipe the data volume on the new host
docker compose down
docker volume rm archer_archer-data

# 3-4: bring the container up without starting Archer; copy backed-up files in
docker compose up --no-start
docker compose cp ./backup-archer-db.sqlite archer:/data/archer.db
docker compose cp ./backup-tls/ archer:/data/tls/

# 5: start
docker compose start archer
```

**Sensors should reconnect without re-enrollment** because the TLS
fingerprint they pinned came back with the cert files. If sensors
fail to connect after restore: the TLS files didn't make it into
your backup. Re-run the install one-liner on each sensor to
re-pin.

**Tested restore on a *different* host quarterly** is the only way
to prove the TLS material is actually in the backup bundle. See
OPERATIONS.md → Backup and restore.

---

## Three things to know before going live

1. **Local auth only.** Email + password, stored in the local
   SQLite. No SSO/OIDC/SAML and there will not be — Archer is
   single-tenant by design. If you need SSO, deploy Archer behind
   an authenticating reverse proxy and pin its listener to
   localhost. Documented in OPERATIONS.md → Scope decisions.
2. **Sensor pinning means cert rotation = re-enrollment.** The
   auto-generated cert is valid for 10 years. If you ever rotate
   it, every enrolled sensor's pinned fingerprint becomes stale
   and you re-run the install one-liner on each. Plan
   accordingly; for stable deployments leaving the cert alone is
   the right move.
3. **Audit log is admin-only and covers admin actions, login
   events, analyst state changes on findings, and sensor auth
   failures.** Read-only GETs and sensor checkins are not logged
   (would drown out the signal). Query via the Audit dialog in
   the UI; for IR queries past the UI's reach, see OPERATIONS.md
   → Audit log.

---

## When something breaks — first commands

```sh
docker compose logs --tail=200 archer          # most recent server logs
docker compose exec archer ls -la /data        # is the DB there, is the TLS dir populated
docker compose logs archer | grep 'applied schema migration' | tail -1
                                                # highest migration applied this boot, should match the release
curl -sk https://localhost:8443/api/version    # running build (no sqlite3 in the container to query schema_migrations directly)
```

If the UI won't load and the logs show TLS validation failure,
the cert files are missing or unreadable — restore from backup or
delete `/data/tls/` and restart to regenerate (will require sensor
re-enrollment, see point 2 above).

For anything else, go to OPERATIONS.md → Disaster recovery → the
symptom→first-step table.

---

## Where the full doc lives

- **OPERATIONS.md** (~600 lines) — threat model, hardening
  checklist, upgrade procedure, full backup/restore procedure,
  sensor lifecycle, user offboarding, audit log schema, TLS
  rotation, scope decisions.
- **README.md** — feature surface and API reference.
- **docs/ANALYST_PLAYBOOK.md** — how an analyst hunts real-world
  C2 beacons with Archer. Triage workflow, modern tradecraft,
  eight-question checklist, worked examples, FP patterns,
  escalation criteria. Read this with your analyst hat on.
- **docs/ARCHITECTURE.md** — internals, dataflow, store schema.
- **docs/DETECTION_METHODS.md** — analyst-facing description of
  the 12 detector families. The math behind each finding type.
- **docs/QUIVER.md** — Quiver sensor protocol and operations.

Bookmark OPERATIONS.md for the questions that come up after the
first week of running this.
