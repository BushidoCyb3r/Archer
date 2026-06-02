#!/usr/bin/env bash
#
# demo.sh — launch a self-contained Archer demo on this machine.
#
# Builds the binary, seeds a throwaway data directory from the sample Zeek
# logs in demo/logs/, registers a demo admin, runs one analysis pass, and
# leaves the workbench running at https://localhost:<port> until Ctrl-C.
#
# Nothing here touches a production deployment: the data dir, logs, and TLS
# cert all live in a temp directory that is removed on exit. Re-run any time.

set -euo pipefail

PORT="${ARCHER_DEMO_PORT:-18443}"
EMAIL="${ARCHER_DEMO_EMAIL:-demo@archer.local}"
PASSWORD="${ARCHER_DEMO_PASSWORD:-archerdemo}"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="$(mktemp -d /tmp/archer-demo.XXXXXX)"
BIN="$RUNTIME/archer"
JAR="$RUNTIME/cookies"
BASE="https://localhost:$PORT"
SRV_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$RUNTIME"
}
trap cleanup EXIT INT TERM

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }

say "Building archer (CGO disabled)…"
VERSION="$(git -C "$REPO" describe --tags --always 2>/dev/null || echo demo)"
( cd "$REPO" && CGO_ENABLED=0 go build \
    -ldflags="-s -w -X github.com/BushidoCyb3r/Archer/internal/version.Version=${VERSION}-demo" \
    -o "$BIN" ./cmd/archer )

say "Seeding sample logs…"
mkdir -p "$RUNTIME/data" "$RUNTIME/logs"
cp -r "$REPO"/demo/logs/. "$RUNTIME/logs/"
touch "$RUNTIME/authorized_keys"
SCEN_COUNT="$(find "$RUNTIME/logs" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"

say "Starting server on $BASE …"
"$BIN" \
  --tls-addr "0.0.0.0:$PORT" \
  --data-dir "$RUNTIME/data" \
  --logs-dir "$RUNTIME/logs" \
  --web-dir "$REPO/web" \
  --authkeys-path "$RUNTIME/authorized_keys" \
  >"$RUNTIME/server.log" 2>&1 &
SRV_PID=$!

# Wait for the HTTPS listener.
for _ in $(seq 1 50); do
  if curl -sk -o /dev/null "$BASE/"; then break; fi
  if ! kill -0 "$SRV_PID" 2>/dev/null; then
    echo "server exited early — log follows:" >&2; cat "$RUNTIME/server.log" >&2; exit 1
  fi
  sleep 0.2
done

say "Registering demo admin ($EMAIL)…"
# First registration on a fresh data dir is auto-approved as admin and the
# response sets the session cookie, so this same jar authenticates the
# analyze call below.
curl -sk -c "$JAR" -o /dev/null \
  --data-urlencode "first_name=Demo" \
  --data-urlencode "last_name=Analyst" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "confirm=$PASSWORD" \
  "$BASE/register"

say "Analyzing $SCEN_COUNT scenarios…"
curl -sk -b "$JAR" -X POST -o /dev/null "$BASE/api/analyze"
sleep 0.5
for _ in $(seq 1 120); do
  if curl -sk -b "$JAR" "$BASE/api/analyze/status" | grep -q '"running":false'; then break; fi
  sleep 0.5
done
COUNT="$(curl -sk -b "$JAR" -D - -o /dev/null "$BASE/api/findings?limit=1" \
          | grep -i '^X-Total-Count:' | tr -dc '0-9')"

cat <<EOF

  ────────────────────────────────────────────────────────────
   Archer demo is live.

     URL:       $BASE
     Email:     $EMAIL
     Password:  $PASSWORD
     Findings:  ${COUNT:-?} across $SCEN_COUNT sample scenarios

   Your browser will warn about the self-signed cert — that is
   expected; proceed past it. Press Ctrl-C here to stop and wipe
   the demo (production deployments are untouched).
  ────────────────────────────────────────────────────────────

EOF

wait "$SRV_PID"
