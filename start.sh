#!/usr/bin/env bash
# start.sh — launch Archer with resource limits set to 80% of host capacity.
# Usage: ./start.sh [up|down|restart|logs|status]
set -euo pipefail

COMPOSE="sudo docker compose"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ACTION="${1:-up}"

# ── Compute 80% of host CPU and RAM ─────────────────────────────────────────

TOTAL_CPUS=$(nproc)
TOTAL_MEM_MB=$(awk '/MemTotal/ { printf "%.0f", $2 / 1024 }' /proc/meminfo)

ARCHER_CPUS=$(awk "BEGIN { v = $TOTAL_CPUS * 0.8; printf (v < 0.5 ? \"0.5\" : \"%.1f\"), v }")
ARCHER_MEM_MB=$(awk "BEGIN { v = int($TOTAL_MEM_MB * 0.8); print (v < 512 ? 512 : v) }")
ARCHER_MEMORY="${ARCHER_MEM_MB}m"

# Write .env so 'docker compose' picks up the values even without this script
cat > "$ENV_FILE" <<EOF
ARCHER_CPUS=${ARCHER_CPUS}
ARCHER_MEMORY=${ARCHER_MEMORY}
EOF

# ── Print summary ────────────────────────────────────────────────────────────

echo "Host resources:   ${TOTAL_CPUS} CPUs  |  ${TOTAL_MEM_MB} MB RAM"
echo "Archer limits:    ${ARCHER_CPUS} CPUs  |  ${ARCHER_MEMORY} RAM  (80%)"
echo ""

# ── Dispatch ─────────────────────────────────────────────────────────────────

case "$ACTION" in
  up)
    $COMPOSE up -d --build
    echo ""
    echo "Archer is running at http://localhost:8080"
    ;;
  down)
    $COMPOSE down
    ;;
  restart)
    $COMPOSE down
    $COMPOSE up -d
    echo ""
    echo "Archer is running at http://localhost:8080"
    ;;
  logs)
    $COMPOSE logs -f
    ;;
  status)
    $COMPOSE ps
    sudo docker stats archer --no-stream --format \
      "CPU: {{.CPUPerc}}  RAM: {{.MemUsage}} / {{.MemLimit}}"
    ;;
  *)
    echo "Usage: $0 [up|down|restart|logs|status]"
    exit 1
    ;;
esac
