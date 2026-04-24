#!/usr/bin/env bash
# reset.sh — wipe all Archer state and start fresh
# Removes: all findings, users, settings, allowlist, IOC list, suppressions, notifications
# Keeps:   log files in ./logs, the Docker image itself

set -euo pipefail

COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "ERROR: docker-compose.yml not found next to this script" >&2
  exit 1
fi

echo "This will permanently delete ALL Archer data:"
echo "  - findings, analyst notes, statuses"
echo "  - user accounts"
echo "  - settings and API keys"
echo "  - allowlist and IOC list"
echo "  - suppressions and notifications"
echo ""
read -r -p "Type YES to continue: " confirm
if [ "$confirm" != "YES" ]; then
  echo "Aborted."
  exit 0
fi

echo ""
echo "Stopping Archer..."
docker compose -f "$COMPOSE_FILE" down

echo "Removing data volume..."
docker volume rm archer_archer-data 2>/dev/null || docker volume rm archer-data 2>/dev/null || {
  # Fall back: find the volume by inspecting the compose project
  VOL=$(docker volume ls --format '{{.Name}}' | grep -E 'archer.*data|data.*archer' | head -1)
  if [ -n "$VOL" ]; then
    docker volume rm "$VOL"
  else
    echo "WARNING: could not find the data volume — it may already be gone."
  fi
}

echo "Starting fresh Archer instance..."
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "Done. Archer is running at http://localhost:8080"
echo "Register a new admin account to get started."
