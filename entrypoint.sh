#!/bin/sh
set -eu

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

exec /app/archer "$@"
