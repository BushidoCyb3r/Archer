#!/bin/sh
# /usr/local/bin/quiver.sh — daily Zeek log push to Archer.
#
# Cron-driven, runs as the quiver user. Each tick checks in with Archer
# over HTTPS first; the response decides whether to push, self-clean,
# or exit silently. Schedule changes from the admin propagate through
# the same checkin response and rewrite cron in place.
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

resp=$(curl -fsSL -k --pinnedpubkey "sha256//${ARCHER_TLS_FP}" --max-time 30 \
    -H "Content-Type: application/json" \
    -X POST -d "{\"name\":\"${SENSOR_NAME}\"}" \
    "${CHECKIN_URL}" 2>/dev/null || echo '{"status":"network_error"}')

status=$(echo "$resp" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')

case "$status" in
    enrolled)
        # Honor any minute-of-hour reassignment the admin made via the
        # Sensors modal. Hourly mode: the hour field stays '*' in cron
        # regardless of whatever schedule_hour the server reports.
        new_m=$(echo "$resp" | sed -n 's/.*"minute":\([0-9]\+\).*/\1/p')
        if [ -n "${new_m:-}" ] && [ "$new_m" != "$SCHEDULE_MINUTE" ]; then
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
    unknown|network_error|"")
        # Unknown to the server (admin probably purged the row) or a
        # transient network blip. Either way, push nothing this tick.
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

# FIRST_SYNC=1 (set by install.sh's first invocation) ships the entire
# log tree. Recurring runs drop everything older than 24 hours so we
# stop re-shipping yesterday's files every tick.
if [ "${FIRST_SYNC:-0}" = "1" ]; then
    MTIME_FILTER=""
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
    rsync -avRq --timeout=60 \
        -e "ssh ${SSH_OPTS}" \
        --files-from=- ./ \
        "quiver@${ARCHER_HOST}:" \
    || { rc=$?; echo "quiver: rsync failed (rc=${rc})" >&2; exit 0; }

echo "quiver: push complete" >&2
