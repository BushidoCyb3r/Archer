#!/usr/bin/env bash
# backup.sh — pull a consistent SQLite snapshot off a running Archer.
#
# Drives the admin backup endpoint, which runs `VACUUM INTO` inside the
# live process — the only consistent online-backup primitive available
# (the container ships no sqlite3 CLI; the binary is pure-Go no-CGO).
# The snapshot includes any un-checkpointed WAL data and never blocks
# analysis. The download is audit-logged server-side as `db_backup`.
#
# Scope: the database only. TLS material under /data/tls/ is needed for
# sensor-pin continuity on a different-host restore but is not reachable
# over the API — back it up with `docker compose cp archer:/data/tls/`
# (see docs/OPERATIONS.md). Logs follow your own retention.
#
# Config (env, with defaults):
#   ARCHER_URL          base URL          (default https://localhost:8443)
#   ARCHER_BACKUP_USER  admin email       (prompted if unset on a TTY)
#   ARCHER_BACKUP_PASS  admin password    (prompted if unset on a TTY)
#   ARCHER_CACERT       CA bundle for TLS verify (default: skip verify, -k)
#   BACKUP_DIR          local target dir  (default ./backups; or $1)
#   BACKUP_RETAIN       keep newest N     (default: keep all)
#   BACKUP_RSYNC_DEST   rsync target      (e.g. archive:/srv/archer/) — optional
#   BACKUP_RSYNC_SSH    rsync -e value    (e.g. "ssh -i key -p 2222") — optional
set -euo pipefail

ARCHER_URL="${ARCHER_URL:-https://localhost:8443}"
BACKUP_DIR="${1:-${BACKUP_DIR:-./backups}}"
JAR="$(mktemp)"
CREDS="$(mktemp)"
chmod 600 "$CREDS"
trap 'rm -f "$JAR" "$CREDS"' EXIT

CURL_TLS=(-k)
if [ -n "${ARCHER_CACERT:-}" ]; then CURL_TLS=(--cacert "$ARCHER_CACERT"); fi

USER_EMAIL="${ARCHER_BACKUP_USER:-}"
USER_PASS="${ARCHER_BACKUP_PASS:-}"
if [ -z "$USER_EMAIL" ] || [ -z "$USER_PASS" ]; then
  if [ ! -t 0 ]; then
    echo "ERROR: set ARCHER_BACKUP_USER and ARCHER_BACKUP_PASS for non-interactive use" >&2
    exit 1
  fi
  [ -z "$USER_EMAIL" ] && read -r -p "Admin email: " USER_EMAIL
  [ -z "$USER_PASS" ] && { read -r -s -p "Admin password: " USER_PASS; echo; }
fi

mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/archer-backup-${STAMP}.db"

# Write credentials to a tempfile read by curl --config so they don't
# appear in /proc/<pid>/cmdline for the curl process lifetime.
printf 'data-urlencode = "email=%s"\ndata-urlencode = "password=%s"\n' \
  "$USER_EMAIL" "$USER_PASS" > "$CREDS"

# Authenticate. A bad password re-renders the login page with HTTP 200
# and no Set-Cookie, so -f won't catch it — verify the session cookie
# actually landed in the jar.
curl -sf "${CURL_TLS[@]}" -c "$JAR" -o /dev/null -K "$CREDS" \
  "${ARCHER_URL}/login" || true
if ! grep -q 'archer_session' "$JAR"; then
  echo "ERROR: login failed (check credentials and ${ARCHER_URL})" >&2
  exit 1
fi

echo "Snapshotting ${ARCHER_URL} → ${OUT}"
curl -fS "${CURL_TLS[@]}" -b "$JAR" -o "$OUT" "${ARCHER_URL}/api/admin/backup"

# A redirect to /login (session not honoured) or an error page would
# write non-SQLite bytes. Every SQLite file starts with this 16-byte
# magic; reject anything else rather than archive a useless file.
if [ "$(head -c 16 "$OUT")" != "SQLite format 3" ]; then
  echo "ERROR: downloaded file is not a SQLite database — discarding" >&2
  rm -f "$OUT"
  exit 1
fi
echo "OK: $(du -h "$OUT" | cut -f1) — ${OUT}"

if [ -n "${BACKUP_RSYNC_DEST:-}" ]; then
  echo "Replicating → ${BACKUP_RSYNC_DEST}"
  if [ -n "${BACKUP_RSYNC_SSH:-}" ]; then
    rsync -a -e "$BACKUP_RSYNC_SSH" "$OUT" "$BACKUP_RSYNC_DEST"
  else
    rsync -a "$OUT" "$BACKUP_RSYNC_DEST"
  fi
fi

# Timestamped names sort chronologically, so newest-N is a tail of the
# sorted list. Only prune what this script produces.
if [ -n "${BACKUP_RETAIN:-}" ]; then
  mapfile -t all < <(ls -1 "$BACKUP_DIR"/archer-backup-*.db 2>/dev/null | sort)
  if [ "${#all[@]}" -gt "$BACKUP_RETAIN" ]; then
    for old in "${all[@]:0:${#all[@]}-BACKUP_RETAIN}"; do
      echo "Pruning ${old}"
      rm -f "$old"
    done
  fi
fi
