#!/bin/sh
# /usr/local/bin/quiver.sh — recurring Zeek log push to Archer.
#
# Lifecycle (each cron tick):
#   1. Acquire flock on /var/lib/quiver/quiver.lock; bail if a previous
#      run is still going.
#   2. Read /etc/quiver/config for server host/port/fingerprint, sensor
#      name, schedule minute, and SSH key path. Optional LOCAL_LOGS_DIR
#      override; otherwise auto-detect.
#   3. POST {name} to /api/quiver/checkin over pinned-pubkey TLS. The
#      server's response branches:
#        enrolled     → maybe rewrite cron with a new minute, then push
#        disenrolled  → invoke uninstall script, exit
#        unknown/err  → silently exit (admin probably purged the row,
#                       or transient network blip — try again next tick)
#   4. Locate the local Zeek log tree (LOCAL_LOGS_DIR or autodetect
#      across /opt/zeek/logs, /usr/local/zeek/logs, /nsm/zeek/logs,
#      and a few legacy Bro paths).
#   5. Filter to log types Archer's analyzers actually consume. First
#      run after install (FIRST_SYNC=1) honors the admin's install-time
#      backfill window from INITIAL_BACKFILL_DAYS in /etc/quiver/config
#      — empty means ship every .gz, an integer N means -mtime -N.
#      Recurring cron runs always use -mtime -1 regardless.
#   6. rsync over ssh to quiver@archer:.  rrsync chroots us into
#      /logs/<sensor-name>/ on the server side, so the trailing colon
#      means "the root of the chroot." -avR preserves the date-tree
#      directory structure. nice/ionice yield CPU+IO.
#
# Source files are NEVER deleted from this sensor — rsync runs without
# --remove-source-files, so every .gz Archer ingests is a copy. Local
# rotation/retention on the sensor is your problem to manage.
#
# Operator overrides (edit /etc/quiver/config):
#   LOCAL_LOGS_DIR=/path/to/zeek/logs   # bypass the autodetect list
#   ARCHER_SSH_PORT=2222                # if you remap on the server
#   INITIAL_BACKFILL_DAYS=30            # only honored on FIRST_SYNC=1
#                                       # invocations; ignored by cron
#
# Logs land in syslog (cron's stdout/stderr capture varies by distro).
# To debug a tick interactively: sudo -u quiver /usr/local/bin/quiver.sh
set -eu

. /etc/quiver/config

# Single-instance lock — overlapping rsyncs would fight for the same
# files and the same sshd connection slot. Single-digit fd is required;
# dash (Debian/Ubuntu /bin/sh) parses multi-digit fds in `exec N>FILE`
# as a command named N, which fails with "exec: 200: not found".
# /var/lock is root:0755 on RHEL/Oracle — not quiver-writable. Use the
# install-created /var/lib/quiver instead, which is owned by the quiver
# user on every distro.
LOCK=/var/lib/quiver/quiver.lock
exec 9>"$LOCK"
if ! flock -n 9; then
    echo "quiver: another run already in progress" >&2
    exit 0
fi

CHECKIN_URL="https://${ARCHER_HOST}:${ARCHER_HTTPS_PORT}/api/quiver/checkin"

# PROTOCOL_VERSION is sourced from /etc/quiver/config. v0.12.0+ servers
# require v2 (per-sensor HMAC on every checkin); v1 is no longer
# accepted. A v1-vintage sensor that hasn't been re-enrolled will get
# protocol_unsupported back and the operator must re-run the install
# one-liner.
: "${PROTOCOL_VERSION:=2}"

# Read the per-sensor checkin secret. The server returns it once at
# enrollment; install.sh persists it at /etc/quiver/secret with mode
# 0600 owned by the quiver user. A missing or empty file means the
# sensor enrolled under v1 (pre-v0.12.0) and must be re-enrolled —
# checkin will fail with a clear error rather than silently sending
# unsigned requests.
SECRET_FILE=/etc/quiver/secret
if [ ! -s "$SECRET_FILE" ]; then
    echo "quiver: missing checkin secret at ${SECRET_FILE}; re-run the install one-liner from the Archer admin UI to enroll under protocol v2" >&2
    exit 0
fi
CHECKIN_SECRET=$(cat "$SECRET_FILE")

# Sanity-check the secret shape. The server-side enrollment response
# produces 32 random bytes URL-safe-base64-encoded (RawURLEncoding):
# 43 characters, charset [A-Za-z0-9_-], no padding. A partial-disk-write
# during sensor reboot, an FS error, or an accidental operator edit
# corrupts the file and openssl below silently HMACs with the wrong
# key — producing endless bad_hmac unauthorized_attempt rows server-
# side with the sensor appearing healthy locally. Loud warning here
# routes the operator straight to the re-enrollment fix instead of
# the audit-log archaeology path. v0.14.7 NEW-57.
SECRET_LEN=${#CHECKIN_SECRET}
case "$CHECKIN_SECRET" in
    *[!A-Za-z0-9_-]*)
        echo "quiver: ${SECRET_FILE} contains characters outside the expected base64url charset — file is corrupted or hand-edited. Re-run the install one-liner from the Archer admin UI to refresh the secret." >&2
        ;;
esac
if [ "$SECRET_LEN" != 43 ]; then
    echo "quiver: ${SECRET_FILE} is ${SECRET_LEN} chars; expected 43 (32 random bytes URL-safe-base64). File is corrupted or truncated. Re-run the install one-liner from the Archer admin UI to refresh the secret." >&2
fi

# Sign the body. openssl is on every distro that ships curl + cron, so
# no extra dependency. The server re-derives the same digest server-
# side and constant-time-compares against the X-Quiver-Sig header.
BODY="{\"name\":\"${SENSOR_NAME}\",\"protocol_version\":${PROTOCOL_VERSION}}"
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$CHECKIN_SECRET" | sed 's/^.*= *//')

resp=$(curl -fsSL -k --pinnedpubkey "sha256//${ARCHER_TLS_FP}" --max-time 30 \
    -H "Content-Type: application/json" \
    -H "X-Quiver-Sig: ${SIG}" \
    -X POST -d "$BODY" \
    "${CHECKIN_URL}" 2>/dev/null || echo '{"status":"network_error"}')

status=$(echo "$resp" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')

case "$status" in
    enrolled)
        # Honor any minute-of-hour reassignment the admin made via the
        # Sensors modal. Hourly mode: the hour field stays '*' in cron
        # regardless of whatever schedule_hour the server reports.
        new_m=$(echo "$resp" | sed -n 's/.*"minute":\([0-9]\+\).*/\1/p')
        # Validate range before writing to cron — a server returning an
        # out-of-range value would produce a malformed cron entry.
        if [ -n "${new_m:-}" ] && [ "$new_m" -ge 0 ] 2>/dev/null && [ "$new_m" -le 59 ] && [ "$new_m" != "$SCHEDULE_MINUTE" ]; then
            sed -i "s/^SCHEDULE_MINUTE=.*/SCHEDULE_MINUTE=${new_m}/" /etc/quiver/config
            echo "${new_m} * * * * quiver /usr/local/bin/quiver.sh >/dev/null 2>&1" \
                > /etc/cron.d/quiver
            echo "quiver: schedule reassigned to :$(printf '%02d' "$new_m") (every hour)" >&2
            SCHEDULE_MINUTE=$new_m
        fi
        ;;
    disenrolled)
        echo "quiver: server says we're disenrolled, self-cleaning" >&2
        sudo /usr/local/bin/quiver-uninstall.sh
        exit 0
        ;;
    protocol_unsupported)
        # Server rejected our PROTOCOL_VERSION. The sensor isn't broken,
        # but it can't push until quiver.sh is updated to a version the
        # server speaks. Surface what the server supports so the operator
        # can match versions; the row stays enrolled so re-running the
        # install one-liner from a current Archer build will fix it.
        srv_supported=$(echo "$resp" | sed -n 's/.*"supported_versions":\[\([0-9, ]*\)\].*/\1/p')
        echo "quiver: server rejected protocol v${PROTOCOL_VERSION}; supported versions: ${srv_supported:-unknown}" >&2
        echo "quiver: re-run the install one-liner from the Archer admin UI to update this sensor" >&2
        exit 0
        ;;
    unknown|network_error|"")
        # Unknown to the server (admin probably purged the row), a
        # transient network blip, OR — most operationally annoying —
        # the server thinks our HMAC is bad. The server's response is
        # the same "unknown" verdict for unknown-name AND bad-HMAC
        # paths by design (a forger shouldn't be able to distinguish
        # them), so the sensor can't tell from the status alone which
        # case it's in. Tell the operator where to look: the audit
        # log on the server narrows it to one of the two via
        # details.reason. v0.14.7 NEW-57. Either way, push nothing
        # this tick.
        if [ "$status" = "unknown" ]; then
            echo "quiver: server returned 'unknown' for this sensor. Could be an admin-purged sensor row OR a corrupted ${SECRET_FILE} (bad_hmac). Check the Archer audit log: action=sensor_unauthorized_attempt with details.reason narrows it. If reason=bad_hmac, re-run the install one-liner from the Archer admin UI." >&2
        fi
        exit 0
        ;;
esac

# ── Locate the local Zeek log tree ──────────────────────────────────────────

if [ -z "${LOCAL_LOGS_DIR:-}" ]; then
    for d in /opt/zeek/logs /usr/local/zeek/logs /nsm/zeek/logs \
             /var/lib/docker/volumes/var_log_zeek/_data \
             /opt/bro/logs /usr/local/bro/logs /nsm/bro/logs \
             /storage/zeek/logs /storage/bro/logs; do
        if [ -d "$d" ]; then LOCAL_LOGS_DIR="$d"; break; fi
    done
fi
if [ -z "${LOCAL_LOGS_DIR:-}" ] || [ ! -d "$LOCAL_LOGS_DIR" ]; then
    echo "quiver: no Zeek log directory found" >&2
    exit 0
fi

cd "$LOCAL_LOGS_DIR"

# Default subset of log types matches what Archer's analyzers actually
# consume. Unknown rotated logs (e.g. dpd, syslog, tunnel) get filtered
# out so we don't waste bandwidth on logs Archer can't use.
LOG_TYPES_REGEX='(conn|dns|http|ssl|x509|known_certs|capture_loss|notice|stats|weird|files)'

# FIRST_SYNC=1 (set by install.sh's first invocation) honors the
# install-time backfill window — INITIAL_BACKFILL_DAYS=N in the sourced
# config means "ship at most the last N days," empty means "ship the
# entire local log tree." Recurring cron runs always use the 24h
# default regardless of the install-time setting.
if [ "${FIRST_SYNC:-0}" = "1" ]; then
    if [ -n "${INITIAL_BACKFILL_DAYS:-}" ]; then
        MTIME_FILTER="-mtime -${INITIAL_BACKFILL_DAYS}"
    else
        MTIME_FILTER=""
    fi
else
    MTIME_FILTER="-mtime -1"
fi
files=$(find . -type f $MTIME_FILTER -iname '*.gz' \
        | grep -E "$LOG_TYPES_REGEX" \
        | grep -v '/\.' \
        | sort -u)

if [ -z "$files" ]; then
    echo "quiver: no eligible log files in $LOCAL_LOGS_DIR" >&2
    exit 0
fi

# ── rsync push ──────────────────────────────────────────────────────────────

# rrsync on the server side chroots the destination to /logs/<name>/, so
# the trailing colon gives us "the root of the chroot." -avR preserves
# the YYYY-MM-DD/file.log.gz tree structure. nice/ionice yield to
# everything else on the sensor host so Quiver never causes dropped
# packets. timeout caps total runtime under the next cron tick.
SSH_OPTS="-i ${SSH_KEY_PATH} -p ${ARCHER_SSH_PORT} -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${KNOWN_HOSTS_PATH} -o LogLevel=ERROR -o ServerAliveInterval=60"

if command -v ionice >/dev/null 2>&1; then
    NICE_CMD="ionice -c 3 nice -n 19"
else
    NICE_CMD="nice -n 19"
fi

echo "$files" | timeout --kill-after=60 7080 $NICE_CMD \
    rsync -avRqO --no-perms --timeout=60 \
        -e "ssh ${SSH_OPTS}" \
        --files-from=- ./ \
        "quiver@${ARCHER_HOST}:" \
    || { rc=$?; echo "quiver: rsync failed (rc=${rc})" >&2; exit 0; }

echo "quiver: push complete" >&2
