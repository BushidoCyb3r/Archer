#!/bin/sh
set -eu

# ── sshd bootstrap ────────────────────────────────────────────────────────
# Host keys live in /etc/ssh/keys (a persistent volume in the docker-compose
# layout) so sensors don't trip host-key-mismatch warnings after a container
# rebuild. ssh-keygen is idempotent on existing keys; the -q quiets the
# "key generated" stdout that would otherwise duplicate every restart.
mkdir -p /etc/ssh/keys
[ -f /etc/ssh/keys/ssh_host_ed25519_key ] || \
    ssh-keygen -t ed25519 -f /etc/ssh/keys/ssh_host_ed25519_key -N '' -q
[ -f /etc/ssh/keys/ssh_host_rsa_key ] || \
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/keys/ssh_host_rsa_key -N '' -q
chmod 600 /etc/ssh/keys/ssh_host_*_key
chmod 644 /etc/ssh/keys/ssh_host_*_key.pub

# /home/quiver/.ssh is a named volume; on first run it shadows whatever the
# image baked in, so re-initialize the authorized_keys file and perms here.
# Idempotent: existing contents are left alone.
mkdir -p /home/quiver/.ssh
[ -f /home/quiver/.ssh/authorized_keys ] || touch /home/quiver/.ssh/authorized_keys
# archer (uid 1001) owns both the directory and the file so it can write
# authorized_keys directly (AppendAuthKey) and atomically via a sibling
# temp file + rename (RemoveAuthKey). sshd_config sets StrictModes no so
# sshd accepts the non-quiver owner; sshd reads the file as root anyway.
chown -R archer:archer /home/quiver/.ssh
chmod 700 /home/quiver/.ssh
chmod 600 /home/quiver/.ssh/authorized_keys

# Start sshd in the foreground of a background subshell. tini (PID 1) reaps
# this when Archer exits, so we don't have to chase signals manually.
/usr/sbin/sshd -D -e &

# ── GOMEMLIMIT ────────────────────────────────────────────────────────────
# Derive GOMEMLIMIT from the cgroup memory cap so Go's GC applies backpressure
# before the kernel OOM-kills us. cgroup v2 first, fall back to v1, then host.
detect_mem_bytes() {
    if [ -r /sys/fs/cgroup/memory.max ]; then
        v=$(cat /sys/fs/cgroup/memory.max)
        if [ "$v" != "max" ]; then echo "$v"; return; fi
    fi
    if [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        v=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
        # cgroup v1 "unlimited" is a huge near-int64-max sentinel
        if [ "$v" -lt 9000000000000000000 ]; then echo "$v"; return; fi
    fi
    awk '/MemTotal/ {printf "%d", $2*1024}' /proc/meminfo
}

if [ -z "${GOMEMLIMIT:-}" ]; then
    total=$(detect_mem_bytes)
    export GOMEMLIMIT="$((total * 9 / 10))B"
    echo "entrypoint: GOMEMLIMIT=${GOMEMLIMIT} (90% of ${total} bytes)"
fi

# Hand /data and /logs to the archer user before dropping privileges.
# On first start after upgrade these dirs are root-owned; this is the
# one-time migration. Idempotent on subsequent starts.
chown -R archer:archer /data /logs

exec su-exec archer /app/archer "$@"
