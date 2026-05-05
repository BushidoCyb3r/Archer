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
for cmd in curl rsync ssh ssh-keygen flock awk grep sed find sudo base64 hostname; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "quiver: missing dependency: $cmd" >&2
        exit 1
    fi
done

# ── Sensor name resolution ──────────────────────────────────────────────────

NAME=$(hostname -s 2>/dev/null || hostname)
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
HOST_REPORTED=$(hostname -f 2>/dev/null || hostname)

# Hostname and pubkey already pass through is_safe / ssh-keygen; the
# token is opaque random bytes from the admin UI; none of those need
# additional escaping for this minimal JSON payload.
PAYLOAD=$(printf '{"token":"%s","name":"%s","host":"%s","pubkey":"%s"}' \
    "$TOKEN" "$NAME" "$HOST_REPORTED" "$PUB")

RESP=$(curl -fsSL -k --pinnedpubkey "sha256//${TLS_FP}" --max-time 30 \
    -H "Content-Type: application/json" \
    -X POST -d "$PAYLOAD" \
    "$ENROLL_URL") || { echo "quiver: enrollment HTTP request failed" >&2; exit 1; }

H=$(echo "$RESP"  | sed -n 's/.*"schedule_hour":\([0-9]\+\).*/\1/p')
M=$(echo "$RESP"  | sed -n 's/.*"schedule_minute":\([0-9]\+\).*/\1/p')
SRV=$(echo "$RESP" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
SRV=${SRV:-$NAME}
H=${H:-2}
M=${M:-0}
echo "quiver: enrolled as '$SRV', scheduled at $(printf '%02d:%02d' "$H" "$M") UTC"

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

# ── Cron entry — daily push at the assigned slot ────────────────────────────

cat > /etc/cron.d/quiver <<CRON
${M} ${H} * * * quiver /usr/local/bin/quiver.sh >/dev/null 2>&1
CRON
chmod 644 /etc/cron.d/quiver

# ── First sync (3-day backfill) ─────────────────────────────────────────────

echo "quiver: running first sync (backfill of last 3 days of logs)..."
sudo -u quiver /usr/local/bin/quiver.sh || echo "quiver: first sync had issues — see /var/log for details" >&2

echo ""
echo "quiver: install complete."
echo "       sensor name : ${SRV}"
echo "       daily slot  : $(printf '%02d:%02d' "$H" "$M") UTC"
echo "       runs as     : user 'quiver'"
