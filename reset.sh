#!/usr/bin/env bash
# reset.sh — wipe all Archer state and start fresh
#
# Removes:
#   - archer-data   → /data: SQLite DB (findings, users, settings, allowlist,
#                     IOC list, suppressions, notifications, watch schedule,
#                     archive config, sensor records) + /data/tls (auto-issued
#                     TLS material for the 8443 Quiver pull endpoint)
#   - archer-sshd   → /etc/ssh/keys: sshd host keys for the 2222 Quiver SSH
#                     port — wiping these means enrolled sensors will see a
#                     host-key mismatch on their next push and must clear
#                     /etc/quiver/known_hosts (re-enrollment via install.sh
#                     does this automatically)
#   - archer-quiver → /home/quiver/.ssh: authorized_keys with per-sensor
#                     entries — every enrolled sensor must re-enroll
#
# Keeps:
#   - log files in ./logs (sensor pushes + archive layout, not in a volume)
#   - the Docker image itself

set -euo pipefail

COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "ERROR: docker-compose.yml not found next to this script" >&2
  exit 1
fi

cat <<'BANNER'
This will permanently delete ALL Archer state:

  Findings & analysis
    - findings, analyst notes, statuses, status timestamps
    - notifications, suppressions
    - dataset fingerprint (next analysis will not flag IsNew correctly)

  Configuration
    - user accounts (admin, analyst, viewer)
    - settings, API keys, organisation CIDRs
    - allowlist, IOC list
    - watch schedule, archive policy

  Quiver
    - enrolled sensors (every sensor must re-enroll via install.sh)
    - sshd host keys (sensors will see a key mismatch until they clear
      /etc/quiver/known_hosts; install.sh does this automatically)
    - per-sensor authorized_keys
    - auto-issued TLS material for the 8443 pull endpoint

Pushed log files under ./logs are NOT touched.

BANNER
read -r -p "Type YES to continue: " confirm
if [ "$confirm" != "YES" ]; then
  echo "Aborted."
  exit 0
fi

echo ""
echo "Stopping Archer..."
docker compose -f "$COMPOSE_FILE" down

echo "Removing data volumes..."
# Compose prefixes volume names with the project (directory) name. Try the
# canonical "archer_<vol>" form first, then fall back to bare names in case
# the project was started under a different name (e.g. via -p).
for vol in archer-data archer-sshd archer-quiver; do
  if ! docker volume rm "archer_${vol}" 2>/dev/null && \
     ! docker volume rm "${vol}" 2>/dev/null; then
    found=$(docker volume ls --format '{{.Name}}' | grep -E "${vol}\$" | head -1)
    if [ -n "$found" ]; then
      docker volume rm "$found"
    else
      echo "  WARNING: ${vol} not found — already gone or named differently"
    fi
  fi
done

echo "Starting fresh Archer instance..."
docker compose -f "$COMPOSE_FILE" up -d

# Pick the IP a remote analyst (and remote sensors) would use to reach
# this host. `ip route get` returns the kernel's outbound source for an
# external destination — that's the LAN-facing IP, which matters more
# than localhost for any sensor URL the operator copies. Fall back to
# localhost only when no route is detectable (host with no network up).
HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") { print $(i+1); exit }}')
HOST_IP="${HOST_IP:-localhost}"

cat <<DONE

Done. Archer is running:
  - Analyst UI       http://${HOST_IP}:8080
  - Quiver pull TLS  https://${HOST_IP}:8443  (sensor → control channel)
  - Quiver SSH/rsync ssh://quiver@${HOST_IP}:2222  (sensor → log push)

Next steps:
  1. Open the UI and register a new admin account.
  2. To re-enroll sensors, hit the Sensors menu → Enroll, then run the
     printed install.sh one-liner on each sensor.
DONE
