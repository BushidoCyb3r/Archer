#!/bin/sh
# Quiver enrollment bootstrap.
#
# What this does:
#   1. Detects the local package manager and installs missing deps
#      (curl, rsync, openssh-client, util-linux flock, sudo, cron daemon).
#   2. Creates a system user 'quiver' with home /var/lib/quiver.
#   3. Generates a fresh ed25519 SSH keypair under /etc/quiver/keys/.
#   4. POSTs {token, hostname, pubkey} to Archer's /api/quiver/enroll
#      over HTTPS — TLS is pinned to the fingerprint baked into this
#      script, so no CA chain or known_hosts trust is required.
#   5. Writes /etc/quiver/config (server host/ports, sensor name,
#      assigned cron minute, key path) and /etc/quiver/known_hosts.
#   6. Drops /usr/local/bin/quiver.sh (the recurring push script) and
#      /usr/local/bin/quiver-uninstall.sh (self-clean helper).
#   7. Drops /etc/cron.d/quiver — runs hourly at the server-assigned
#      minute, so 20 sensors don't synchronize at HH:00.
#   8. Drops /etc/sudoers.d/quiver — narrowly authorizes the quiver
#      user to invoke ONLY the uninstall script via sudo.
#   9. Restores SELinux contexts on the dropped files (no-op off RHEL).
#  10. Prompts the admin for the initial backfill window — how many days
#      of historical Zeek logs to ship on the first push. Defaults to all
#      available history; can be set non-interactively by exporting
#      INITIAL_BACKFILL_DAYS=N before running this script.
#  11. Runs the first push immediately, honoring that window. FIRST_SYNC=1
#      tells quiver.sh to use the install-time backfill cap; recurring
#      cron runs always use the 24-hour default.
#
# Filesystem footprint left behind:
#   /etc/quiver/                  config, ssh key, known_hosts
#   /var/lib/quiver/              quiver user home + flock file
#   /usr/local/bin/quiver.sh      recurring push script
#   /usr/local/bin/quiver-uninstall.sh
#   /etc/cron.d/quiver
#   /etc/sudoers.d/quiver
#
# Removal: `sudo /usr/local/bin/quiver-uninstall.sh` reverses items 5-8.
# (The 'quiver' user is intentionally preserved — see uninstall script.)
#
# Archer renders this template with deployment-specific values
# substituted at request time. The token is the only runtime argument;
# everything else (host, ports, fingerprint, the recurring script body,
# the uninstall helper) was baked in by the server when this body was
# served.
set -eu

TOKEN="${1:-}"
ARCHER_HOST="{{ARCHER_HOST}}"
HTTPS_PORT="{{HTTPS_PORT}}"
SSH_PORT="{{SSH_PORT}}"
TLS_FP="{{TLS_FP}}"
QUIVER_SH_B64="{{QUIVER_SH_B64}}"
UNINSTALL_SH_B64="{{UNINSTALL_SH_B64}}"

# Quiver wire-protocol version this script speaks. The server validates
# this on enrollment + checkin and rejects mismatches with a structured
# error so the operator sees "your sensor is on vN, server requires v..."
# instead of an opaque rsync failure later. See docs/QUIVER.md "Protocol
# versioning" for what counts as a bump and the compatibility rules.
PROTOCOL_VERSION=1

# ── Preconditions ───────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "quiver: must run as root (use sudo)" >&2
    exit 1
fi
if [ -z "$TOKEN" ]; then
    echo "Usage: sudo bash $0 <enrollment-token>" >&2
    exit 1
fi

# Distro-portable dependency install. Minimal RHEL/Oracle/Rocky/Alma ships
# without rsync and cronie; Debian/Ubuntu containers sometimes lack cron.
# Detect the package manager once, then install whatever's missing rather
# than failing the operator with "missing dependency: rsync."
PM=""
PM_INSTALL=""
PM_REFRESH=""
PKG_SSH_CLIENT=""
PKG_CRON=""
CRON_SVC=""
if   command -v apt-get >/dev/null 2>&1; then
    PM=apt-get
    PM_INSTALL="apt-get install -y --no-install-recommends"
    PM_REFRESH="apt-get update -qq"
    export DEBIAN_FRONTEND=noninteractive
    PKG_SSH_CLIENT=openssh-client
    PKG_CRON=cron
    CRON_SVC=cron
elif command -v dnf >/dev/null 2>&1; then
    PM=dnf
    PM_INSTALL="dnf install -y"
    PKG_SSH_CLIENT=openssh-clients
    PKG_CRON=cronie
    CRON_SVC=crond
elif command -v yum >/dev/null 2>&1; then
    PM=yum
    PM_INSTALL="yum install -y"
    PKG_SSH_CLIENT=openssh-clients
    PKG_CRON=cronie
    CRON_SVC=crond
elif command -v zypper >/dev/null 2>&1; then
    PM=zypper
    PM_INSTALL="zypper --non-interactive install"
    PKG_SSH_CLIENT=openssh
    PKG_CRON=cronie
    CRON_SVC=cron
elif command -v apk >/dev/null 2>&1; then
    PM=apk
    PM_INSTALL="apk add --no-cache"
    PKG_SSH_CLIENT=openssh-client
    PKG_CRON=busybox-suid    # /usr/sbin/crond ships in busybox-suid on Alpine
    CRON_SVC=crond
fi

ensure_cmd() {
    _cmd=$1; _pkg=$2
    if command -v "$_cmd" >/dev/null 2>&1; then return 0; fi
    if [ -z "$PM" ]; then
        echo "quiver: missing '$_cmd' and no supported package manager found" >&2
        return 1
    fi
    if [ -n "$PM_REFRESH" ] && [ -z "${_PM_REFRESHED:-}" ]; then
        $PM_REFRESH >/dev/null 2>&1 || true
        _PM_REFRESHED=1
    fi
    echo "quiver: installing '$_pkg' (provides $_cmd) via $PM..." >&2
    if ! $PM_INSTALL "$_pkg" >/dev/null 2>&1; then
        echo "quiver: failed to install '$_pkg'. Run manually: sudo $PM_INSTALL $_pkg" >&2
        return 1
    fi
    command -v "$_cmd" >/dev/null 2>&1
}

ensure_cmd curl       curl                  || exit 1
ensure_cmd rsync      rsync                 || exit 1
ensure_cmd ssh        "$PKG_SSH_CLIENT"     || exit 1
ensure_cmd ssh-keygen "$PKG_SSH_CLIENT"     || exit 1
ensure_cmd flock      util-linux            || exit 1
ensure_cmd sudo       sudo                  || exit 1
# awk, grep, sed, find, base64, tr are part of every distro's base; skip.

# Make sure the cron daemon is installed and running. /etc/cron.d/quiver
# only fires if there's actually a cron daemon reading it.
if ! pgrep -x crond >/dev/null 2>&1 && ! pgrep -x cron >/dev/null 2>&1; then
    if [ -n "$PM" ] && [ -n "$PKG_CRON" ]; then
        if ! command -v crond >/dev/null 2>&1 && ! command -v cron >/dev/null 2>&1; then
            echo "quiver: installing '$PKG_CRON' via $PM..." >&2
            $PM_INSTALL "$PKG_CRON" >/dev/null 2>&1 || \
                echo "quiver: could not install $PKG_CRON; daily push won't run until a cron daemon exists" >&2
        fi
    fi
fi
if command -v systemctl >/dev/null 2>&1 && [ -n "$CRON_SVC" ]; then
    systemctl enable --now "$CRON_SVC" >/dev/null 2>&1 || true
elif command -v rc-update >/dev/null 2>&1 && [ -n "$CRON_SVC" ]; then
    # OpenRC (Alpine without systemd)
    rc-update add "$CRON_SVC" default >/dev/null 2>&1 || true
    rc-service "$CRON_SVC" start    >/dev/null 2>&1 || true
fi

# ── Sensor name resolution ──────────────────────────────────────────────────

# Try several portable sources. `hostname -s` is GNU-flag specific and
# `hostname` itself is missing on some RHEL 9 minimal images, so fall back
# to /etc/hostname and uname before giving up. Strip trailing domain in
# case the chosen source returned an FQDN.
NAME=$(hostname -s 2>/dev/null || hostname 2>/dev/null \
       || cat /etc/hostname 2>/dev/null || uname -n 2>/dev/null || echo "")
NAME=$(echo "$NAME" | awk -F. '{print $1}')
NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]')

is_safe() {
    # filesystem-safe: lowercase alnum + - _ ; 1-52 chars; first char alnum
    case "$1" in
        ''|[!a-z0-9]*|*[!a-z0-9_-]*) return 1 ;;
    esac
    [ "${#1}" -le 52 ]
}

if ! is_safe "$NAME"; then
    echo "quiver: hostname '$NAME' isn't filesystem-safe" >&2
    while true; do
        printf 'Enter a sensor name (lowercase a-z 0-9 - _ ; max 52 chars): ' >&2
        read NAME </dev/tty
        if is_safe "$NAME"; then break; fi
        echo "quiver: '$NAME' isn't valid, try again" >&2
    done
fi
echo "quiver: enrolling as '$NAME'"

# ── User and directories ────────────────────────────────────────────────────

if ! id quiver >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd -r -s /bin/sh -m -d /var/lib/quiver quiver
    else
        echo "quiver: no useradd available" >&2
        exit 1
    fi
fi

install -d -m 700 -o quiver -g quiver /etc/quiver
install -d -m 700 -o quiver -g quiver /etc/quiver/keys
install -d -m 700 -o quiver -g quiver /var/lib/quiver

# ── SSH keypair (regenerate every enrollment so re-runs aren't bound to
#    a previously-disenrolled keypair on the server) ────────────────────────

KEY=/etc/quiver/keys/id_ed25519
rm -f "$KEY" "$KEY.pub"
sudo -u quiver ssh-keygen -t ed25519 -N '' -f "$KEY" -q -C "quiver-$NAME"
PUB=$(cat "$KEY.pub")

# ── Enroll with the server ──────────────────────────────────────────────────

ENROLL_URL="https://${ARCHER_HOST}:${HTTPS_PORT}/api/quiver/enroll"
HOST_REPORTED=$(hostname -f 2>/dev/null || hostname 2>/dev/null \
               || cat /etc/hostname 2>/dev/null || uname -n 2>/dev/null || echo "$NAME")

# Hostname and pubkey already pass through is_safe / ssh-keygen; the
# token is opaque random bytes from the admin UI; none of those need
# additional escaping for this minimal JSON payload. PROTOCOL_VERSION is
# always a bare integer literal (not user input), so quoting it as a
# number is safe.
PAYLOAD=$(printf '{"token":"%s","name":"%s","host":"%s","pubkey":"%s","protocol_version":%d}' \
    "$TOKEN" "$NAME" "$HOST_REPORTED" "$PUB" "$PROTOCOL_VERSION")

# -fsSL fails the request body on non-2xx, which is exactly what we want
# when the server rejects an unsupported protocol version — the curl
# exit code below trips the error path and the operator sees the failure
# at install time, before any local state is committed. The actual
# rejection message lives in the server's response body, but with -f we
# don't see it. Re-issue without -f on failure to surface it.
if ! RESP=$(curl -fsSL -k --pinnedpubkey "sha256//${TLS_FP}" --max-time 30 \
    -H "Content-Type: application/json" \
    -X POST -d "$PAYLOAD" \
    "$ENROLL_URL"); then
    ERR_BODY=$(curl -sSL -k --pinnedpubkey "sha256//${TLS_FP}" --max-time 30 \
        -H "Content-Type: application/json" \
        -X POST -d "$PAYLOAD" \
        "$ENROLL_URL" 2>/dev/null || echo '')
    echo "quiver: enrollment failed" >&2
    if [ -n "$ERR_BODY" ]; then
        echo "quiver: server response: $ERR_BODY" >&2
    fi
    exit 1
fi

# Hourly mode: only the minute-of-hour matters. We still parse and
# persist H so legacy daily-mode telemetry stays consistent, but the
# cron line below drops it.
H=$(echo "$RESP"  | sed -n 's/.*"schedule_hour":\([0-9]\+\).*/\1/p')
M=$(echo "$RESP"  | sed -n 's/.*"schedule_minute":\([0-9]\+\).*/\1/p')
SRV=$(echo "$RESP" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
SRV=${SRV:-$NAME}
H=${H:-0}
M=${M:-0}
echo "quiver: enrolled as '$SRV', scheduled hourly at :$(printf '%02d' "$M") UTC"

# ── Drop the daily script and the uninstall helper ──────────────────────────

echo "$QUIVER_SH_B64"    | base64 -d > /usr/local/bin/quiver.sh
chmod 755 /usr/local/bin/quiver.sh
chown root:root /usr/local/bin/quiver.sh

echo "$UNINSTALL_SH_B64" | base64 -d > /usr/local/bin/quiver-uninstall.sh
chmod 755 /usr/local/bin/quiver-uninstall.sh
chown root:root /usr/local/bin/quiver-uninstall.sh

# ── Initial backfill window ─────────────────────────────────────────────────
# Admin-controlled cap on how far back the FIRST sync ships. Empty means
# "ship every .gz we can find" (Zeek's full local retention). Honored only
# by the FIRST_SYNC=1 invocation below; recurring cron runs always use the
# 24h mtime window regardless of what's set here.
#
# Resolution order:
#   1. INITIAL_BACKFILL_DAYS env var (set non-interactively, e.g. by config
#      management) wins — no prompt fires.
#   2. Otherwise, prompt on /dev/tty with default = empty (= all history).
#   3. If no /dev/tty (truly headless), fall back to all history.
if [ -z "${INITIAL_BACKFILL_DAYS+x}" ]; then
    if [ -e /dev/tty ]; then
        printf '\nquiver: initial log backfill — how many days of historical Zeek logs should this\n' >&2
        printf '       sensor ship to Archer right now?\n' >&2
        printf '       (press Enter to ship all available history, or enter a number e.g. 7): ' >&2
        IFS= read -r INITIAL_BACKFILL_DAYS </dev/tty 2>/dev/null || INITIAL_BACKFILL_DAYS=""
    else
        INITIAL_BACKFILL_DAYS=""
    fi
fi
# Trim whitespace, then validate: empty (= all) or a positive integer.
INITIAL_BACKFILL_DAYS=$(printf '%s' "${INITIAL_BACKFILL_DAYS:-}" | tr -d '[:space:]')
if [ -n "$INITIAL_BACKFILL_DAYS" ]; then
    case "$INITIAL_BACKFILL_DAYS" in
        ''|*[!0-9]*|0)
            echo "quiver: '$INITIAL_BACKFILL_DAYS' isn't a positive integer — falling back to all available history" >&2
            INITIAL_BACKFILL_DAYS=""
            ;;
    esac
fi

# ── Config and known_hosts ──────────────────────────────────────────────────

cat > /etc/quiver/config <<CONF
ARCHER_HOST=${ARCHER_HOST}
ARCHER_HTTPS_PORT=${HTTPS_PORT}
ARCHER_SSH_PORT=${SSH_PORT}
ARCHER_TLS_FP=${TLS_FP}
SENSOR_NAME=${SRV}
SCHEDULE_HOUR=${H}
SCHEDULE_MINUTE=${M}
SSH_KEY_PATH=${KEY}
KNOWN_HOSTS_PATH=/etc/quiver/known_hosts
LOCAL_LOGS_DIR=
INITIAL_BACKFILL_DAYS=${INITIAL_BACKFILL_DAYS}
PROTOCOL_VERSION=${PROTOCOL_VERSION}
CONF
chmod 644 /etc/quiver/config
chown root:root /etc/quiver/config

touch /etc/quiver/known_hosts
chown quiver:quiver /etc/quiver/known_hosts
chmod 644 /etc/quiver/known_hosts

# ── Sudoers fragment limited to the uninstall script ────────────────────────

cat > /etc/sudoers.d/quiver <<SUDO
quiver ALL=(root) NOPASSWD: /usr/local/bin/quiver-uninstall.sh
SUDO
chmod 440 /etc/sudoers.d/quiver
chown root:root /etc/sudoers.d/quiver

# ── Cron entry — hourly push at the assigned minute-of-hour ─────────────────
# Hour is always '*' under hourly mode; the assigned minute is per-sensor
# random so 20 sensors don't synchronize at HH:00.
cat > /etc/cron.d/quiver <<CRON
${M} * * * * quiver /usr/local/bin/quiver.sh >/dev/null 2>&1
CRON
chmod 644 /etc/cron.d/quiver

# ── SELinux contexts (RHEL/Oracle/Rocky/Alma) ───────────────────────────────
# Files we just dropped land as unlabeled_t/admin_home_t and crond on an
# enforcing system will refuse to exec them. restorecon brings them back
# to bin_t / system_cron_spool_t / etc_t per the system policy. No-op on
# distros without SELinux installed.
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/quiver.sh \
                  /usr/local/bin/quiver-uninstall.sh \
                  /etc/cron.d/quiver \
                  /etc/sudoers.d/quiver \
                  /etc/quiver \
                  /etc/quiver/keys \
                  /etc/quiver/keys/id_ed25519 \
                  /etc/quiver/keys/id_ed25519.pub \
                  /etc/quiver/known_hosts \
                  /etc/quiver/config 2>/dev/null || true
fi

# ── First sync (initial backfill) ───────────────────────────────────────────
# FIRST_SYNC=1 makes quiver.sh apply the install-time backfill window
# (INITIAL_BACKFILL_DAYS in /etc/quiver/config) instead of the 24-hour
# default that recurring cron runs use. Empty backfill window = ship the
# entire local Zeek log tree.
if [ -n "$INITIAL_BACKFILL_DAYS" ]; then
    echo "quiver: running first sync (backfill: last ${INITIAL_BACKFILL_DAYS} day(s))..."
else
    echo "quiver: running first sync (backfill: all available history)..."
fi
FIRST_SYNC=1 sudo -E -u quiver /usr/local/bin/quiver.sh || echo "quiver: first sync had issues — see /var/log for details" >&2

echo ""
echo "quiver: install complete."
echo "       sensor name : ${SRV}"
echo "       hourly slot : :$(printf '%02d' "$M") (every hour)"
echo "       runs as     : user 'quiver'"
echo ""
echo "quiver: where things live on this sensor:"
echo "       config      : /etc/quiver/config       (edit LOCAL_LOGS_DIR= to override Zeek dir auto-detect)"
echo "       ssh key     : /etc/quiver/keys/        (regenerated on every re-enrollment)"
echo "       cron entry  : /etc/cron.d/quiver       (hourly, minute :$(printf '%02d' "$M"))"
echo "       push script : /usr/local/bin/quiver.sh"
echo "       lock file   : /var/lib/quiver/quiver.lock (single-instance guard)"
echo ""
echo "quiver: verify it's working from THIS host:"
echo "       sudo -u quiver /usr/local/bin/quiver.sh   # run a push manually right now"
echo "       grep CRON /var/log/syslog | grep quiver  # confirm cron is firing (path varies by distro)"
echo ""
echo "quiver: verify it's landing on the Archer server:"
echo "       Archer UI → Sensors → look for '${SRV}' with a recent 'last seen' timestamp"
echo "       server-side logs land at /logs/${SRV}/<YYYY-MM-DD>/<file>.log.gz"
echo ""
echo "quiver: removal (also runs automatically if the Archer admin disenrolls this sensor):"
echo "       sudo /usr/local/bin/quiver-uninstall.sh"
