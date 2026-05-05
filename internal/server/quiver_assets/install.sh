#!/bin/sh
# Quiver enrollment bootstrap. Archer renders this template with
# deployment-specific values substituted at request time. The token is
# the only runtime argument; everything else (host, ports, fingerprint,
# the daily script body, the uninstall helper) was baked in by the
# server when this body was served.
set -eu

TOKEN="${1:-}"
ARCHER_HOST="{{ARCHER_HOST}}"
HTTPS_PORT="{{HTTPS_PORT}}"
SSH_PORT="{{SSH_PORT}}"
TLS_FP="{{TLS_FP}}"
QUIVER_SH_B64="{{QUIVER_SH_B64}}"
UNINSTALL_SH_B64="{{UNINSTALL_SH_B64}}"

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
# additional escaping for this minimal JSON payload.
PAYLOAD=$(printf '{"token":"%s","name":"%s","host":"%s","pubkey":"%s"}' \
    "$TOKEN" "$NAME" "$HOST_REPORTED" "$PUB")

RESP=$(curl -fsSL -k --pinnedpubkey "sha256//${TLS_FP}" --max-time 30 \
    -H "Content-Type: application/json" \
    -X POST -d "$PAYLOAD" \
    "$ENROLL_URL") || { echo "quiver: enrollment HTTP request failed" >&2; exit 1; }

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

# ── First sync (full backfill) ──────────────────────────────────────────────
# FIRST_SYNC=1 makes quiver.sh skip its mtime filter and ship the entire
# Zeek log tree. Recurring runs use the default 24-hour window.
echo "quiver: running first sync (full log backfill)..."
FIRST_SYNC=1 sudo -E -u quiver /usr/local/bin/quiver.sh || echo "quiver: first sync had issues — see /var/log for details" >&2

echo ""
echo "quiver: install complete."
echo "       sensor name : ${SRV}"
echo "       hourly slot : :$(printf '%02d' "$M") (every hour)"
echo "       runs as     : user 'quiver'"
