#!/bin/sh
set -euo pipefail

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
# archer:archer ownership throughout: archer writes, and quiver reads via
# the archer supplementary group (addgroup quiver archer in Dockerfile).
# matchParentOwner in authorized_keys.go re-chowns the file after each
# write; it can only succeed when the target gid is in archer's group set.
chown archer:archer /home/quiver/.ssh /home/quiver/.ssh/authorized_keys
chmod 750 /home/quiver/.ssh
chmod 640 /home/quiver/.ssh/authorized_keys

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

# Hand /data to the archer user before dropping privileges. Only chown
# /data itself plus the tls subdirectory (a handful of cert files) — a
# recursive chown of the full tree is O(n) in archive file count and
# destructive if /data is bind-mounted from a host path with arbitrary
# contents. Archive files are already archer-owned once moved there by
# the archive worker; the DB and WAL at /data root are covered by the
# non-recursive pass.
chown archer:archer /data
find /data -maxdepth 1 -exec chown archer:archer {} \;
chown -R archer:archer /data/tls 2>/dev/null || true
# Only chown the /logs root and sensor-level dirs, not the date-tree
# subdirs inside them. Sensor-level dirs are archer:archer 2775 so
# rrsync (quiver, with archer as supplementary group) can push into them
# and new date subdirs inherit the archer group via the setgid bit.
chown archer:archer /logs
find /logs -maxdepth 1 -mindepth 1 -type d -exec chown archer:archer {} + 2>/dev/null || true
# Date-level subdirs (YYYY-MM-DD) are created by rsync running as the
# sensor's push user (UID 1000 → quiver in this container). chown them
# to archer:archer and ensure group-write so the archive worker can
# delete source files after moving them to /data/archive.
find /logs -mindepth 2 -maxdepth 2 -type d \
    -exec chown archer:archer {} + \
    -exec chmod 775 {} + 2>/dev/null || true

exec su-exec archer /app/archer "$@"
