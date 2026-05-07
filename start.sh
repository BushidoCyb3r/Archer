#!/usr/bin/env bash
# start.sh — launch Archer with CPU set to 80% and RAM set to 70% of capacity.
# RAM is the more conservative cap because memory overshoot can OOM-kill the
# container, while CPU spikes only slow analysis down.
# Usage: ./start.sh [up|down|restart|logs|status]
set -euo pipefail

COMPOSE="sudo docker compose"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ACTION="${1:-up}"

# ── Compute resource budget from effective Docker capacity ──────────────────
#
# The host kernel may report more CPUs/RAM than the Docker daemon will grant
# to a container (e.g. Docker Desktop's VM, daemon CPU/memory limits, or
# nested virtualisation). Asking for more than the daemon allows surfaces as
# "range of CPUs is from 0.01 to N.00" at container-create time. Prefer
# Docker's own view when available; fall back to the host view otherwise.

HOST_CPUS=$(nproc)
HOST_MEM_MB=$(awk '/MemTotal/ { printf "%.0f", $2 / 1024 }' /proc/meminfo)

DOCKER_CPUS=$(sudo docker info --format '{{.NCPU}}' 2>/dev/null || echo 0)
DOCKER_MEM_BYTES=$(sudo docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
DOCKER_MEM_MB=$(awk -v b="$DOCKER_MEM_BYTES" 'BEGIN { printf "%.0f", b / 1048576 }')

# Use the lower of (host, docker) for each resource — that's what the daemon
# will actually accept. If docker info failed (returns 0), fall back to host.
TOTAL_CPUS="$HOST_CPUS"
if [[ "$DOCKER_CPUS" =~ ^[0-9]+$ ]] && (( DOCKER_CPUS > 0 && DOCKER_CPUS < HOST_CPUS )); then
  TOTAL_CPUS="$DOCKER_CPUS"
fi
TOTAL_MEM_MB="$HOST_MEM_MB"
if [[ "$DOCKER_MEM_MB" =~ ^[0-9]+$ ]] && (( DOCKER_MEM_MB > 0 && DOCKER_MEM_MB < HOST_MEM_MB )); then
  TOTAL_MEM_MB="$DOCKER_MEM_MB"
fi

# CPU at 80% — burst CPU spikes don't crash the container, the worst case is
# slower analysis. Memory at 70% — overshoot here can OOM-kill the container,
# so leave a wider absorption margin for kernel/journal/docker daemon spikes
# that don't show up in Go's GOMEMLIMIT accounting.
ARCHER_CPUS=$(awk "BEGIN { v = $TOTAL_CPUS * 0.8; printf (v < 0.5 ? \"0.5\" : \"%.1f\"), v }")
ARCHER_MEM_MB=$(awk "BEGIN { v = int($TOTAL_MEM_MB * 0.7); print (v < 512 ? 512 : v) }")
ARCHER_MEMORY="${ARCHER_MEM_MB}m"

# Derive version metadata from the git checkout so the build bakes in the
# right tag/commit/time. `git describe --tags --always` falls back to the
# short commit when no tag exists yet (pre-v0.1.0 checkouts), and we let
# the Dockerfile's defaults take over if git itself isn't available — that
# covers air-gap tarball installs where the repo was extracted, not cloned.
if command -v git >/dev/null 2>&1 && git -C "$SCRIPT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  ARCHER_VERSION="$(git -C "$SCRIPT_DIR" describe --tags --always --dirty 2>/dev/null || echo v0.1.0)"
  ARCHER_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
else
  ARCHER_VERSION="v0.1.0"
  ARCHER_COMMIT="unknown"
fi
ARCHER_BUILD_TIME="$(date -u +%FT%TZ)"

# Write .env so 'docker compose' picks up the values even without this script
cat > "$ENV_FILE" <<EOF
ARCHER_CPUS=${ARCHER_CPUS}
ARCHER_MEMORY=${ARCHER_MEMORY}
ARCHER_VERSION=${ARCHER_VERSION}
ARCHER_COMMIT=${ARCHER_COMMIT}
ARCHER_BUILD_TIME=${ARCHER_BUILD_TIME}
EOF

# ── Print summary ────────────────────────────────────────────────────────────

echo "Host resources:   ${HOST_CPUS} CPUs  |  ${HOST_MEM_MB} MB RAM"
if [[ "$DOCKER_CPUS" =~ ^[0-9]+$ ]] && (( DOCKER_CPUS > 0 )); then
  echo "Docker capacity:  ${DOCKER_CPUS} CPUs  |  ${DOCKER_MEM_MB} MB RAM"
fi
echo "Archer limits:    ${ARCHER_CPUS} CPUs  |  ${ARCHER_MEMORY} RAM  (CPU 80% / RAM 70%)"
echo "Archer version:   ${ARCHER_VERSION}  (commit ${ARCHER_COMMIT}, built ${ARCHER_BUILD_TIME})"
echo ""

# Pick the IP a remote analyst would use to reach this host. `ip route get`
# returns the source address chosen for the default route, which is what
# matters when LAN browsers point at us — falling back to localhost only
# when no route is detectable (host with no network up).
HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") { print $(i+1); exit }}')
HOST_IP="${HOST_IP:-localhost}"

# ── Dispatch ─────────────────────────────────────────────────────────────────

case "$ACTION" in
  up)
    $COMPOSE up -d --build
    echo ""
    echo "Archer is running at http://${HOST_IP}:8080"
    ;;
  down)
    $COMPOSE down
    ;;
  restart)
    $COMPOSE down
    $COMPOSE up -d
    echo ""
    echo "Archer is running at http://${HOST_IP}:8080"
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
