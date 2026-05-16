#!/usr/bin/env bash
# restore.sh — replace the live SQLite DB with a snapshot from backup.sh.
#
# Destructive: overwrites /data/archer.db in the archer-data volume.
# The container must be down so the live process isn't holding the DB
# open — a swap under an open WAL writer corrupts both. TLS material
# under /data/tls/ and all other volumes are left untouched, so sensor
# pinning survives an in-place restore.
#
# Usage: ./restore.sh <snapshot.db>
#
# A backup.sh snapshot is a single clean file (VACUUM INTO output, no
# WAL). Any stale archer.db-wal / -shm from the previous DB must be
# removed or SQLite will replay them onto the fresh file and corrupt it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
SNAP="${1:-}"

if [ -z "$SNAP" ] || [ ! -f "$SNAP" ]; then
  echo "Usage: $0 <snapshot.db>" >&2
  exit 1
fi
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "ERROR: docker-compose.yml not found next to this script" >&2
  exit 1
fi
# Validate the snapshot before anything destructive — taking the
# container down and then discovering a bad file is the worst outcome.
if [ "$(head -c 16 "$SNAP")" != "SQLite format 3" ]; then
  echo "ERROR: $SNAP is not a SQLite database" >&2
  exit 1
fi

cat <<BANNER
This will REPLACE the live Archer database with:

  $SNAP  ($(du -h "$SNAP" | cut -f1))

The container will be stopped, the DB swapped, and the container
restarted. Findings, notes, users, sensor enrollments, and audit
history will become whatever the snapshot holds. TLS material and
pushed logs are NOT touched.

BANNER
read -r -p "Type RESTORE to continue: " confirm
if [ "$confirm" != "RESTORE" ]; then
  echo "Aborted."
  exit 0
fi

echo "Stopping Archer..."
docker compose -f "$COMPOSE_FILE" down

# Compose prefixes volume names with the project (directory) name. Try
# the canonical archer_<vol> form, then the bare name, then a suffix
# match — same resolution reset.sh uses.
VOL=""
for cand in archer_archer-data archer-data; do
  if docker volume inspect "$cand" >/dev/null 2>&1; then VOL="$cand"; break; fi
done
if [ -z "$VOL" ]; then
  VOL=$(docker volume ls --format '{{.Name}}' | grep -E 'archer-data$' | head -1)
fi
if [ -z "$VOL" ]; then
  echo "ERROR: archer-data volume not found — is this the right host?" >&2
  exit 1
fi

# The container is down, so nothing else has the volume open. Reuse the
# archer image (guaranteed present locally; no pull, air-gap-safe) just
# as a filesystem to land the file and clear stale WAL/SHM sidecars.
echo "Restoring into volume ${VOL}..."
docker run --rm \
  -v "${VOL}:/data" \
  -v "$(cd "$(dirname "$SNAP")" && pwd):/snap:ro" \
  --entrypoint sh archer:latest -c "
    cp /snap/$(basename "$SNAP") /data/archer.db &&
    rm -f /data/archer.db-wal /data/archer.db-shm &&
    echo restored"

echo "Starting Archer..."
docker compose -f "$COMPOSE_FILE" up -d

cat <<DONE

Done. Verify:
  - UI loads and the version pill matches the build
  - Findings / users / sensors reflect the restored snapshot
  - Sensor checkins resume on the next tick (/api/sensors last_seen_at)

Schema migrations run idempotently on startup, so a snapshot from an
older build migrates forward when the newer binary opens it.
DONE
