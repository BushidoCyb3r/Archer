FROM golang:1.25-alpine AS builder

ENV GOTOOLCHAIN=local

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /archer ./cmd/archer

# ── Final image ───────────────────────────────────────────────────────────────
FROM alpine:3.20

# tini reaps zombies and forwards signals so that sshd dies cleanly when
# Archer exits. openssh-server + rsync are the sensor-facing transport
# (Quiver sensors push their daily logs over ssh). ca-certificates and
# tzdata are kept from the original image for outbound TLS calls.
RUN apk add --no-cache ca-certificates tzdata openssh-server tini rsync rrsync \
    && adduser -D -h /home/quiver -s /bin/sh quiver \
    && mkdir -p /home/quiver/.ssh /etc/ssh/keys /run/sshd \
    && touch /home/quiver/.ssh/authorized_keys \
    && chown -R quiver:quiver /home/quiver \
    && chmod 700 /home/quiver/.ssh \
    && chmod 600 /home/quiver/.ssh/authorized_keys \
    && chmod 700 /run/sshd

# rrsync ships in Alpine's rsync package but the canonical path varies
# between 3.x point releases (3.18 dropped it under /usr/bin, some prior
# versions used /usr/share/rsync). The per-sensor authorized_keys lines
# bake in `command="rrsync -wo /logs/<name>/"`, so an unresolvable path
# would silently break every sensor's rsync push. Pin /usr/bin/rrsync
# unconditionally and fail the build if the rsync package didn't ship
# rrsync at all — the operator deserves a build-time error, not a
# runtime mystery.
RUN if [ ! -x /usr/bin/rrsync ]; then \
        for cand in /usr/share/rsync/rrsync /usr/lib/rsync/rrsync /usr/local/bin/rrsync; do \
            if [ -x "$cand" ]; then ln -sf "$cand" /usr/bin/rrsync; break; fi; \
        done; \
    fi \
    && test -x /usr/bin/rrsync \
    || { echo "rrsync not found in rsync package — Alpine layout changed?" >&2; exit 1; }

WORKDIR /app
COPY --from=builder /archer ./archer
COPY web/ ./web/
COPY entrypoint.sh /app/entrypoint.sh
COPY sshd_config /etc/ssh/sshd_config
RUN chmod +x /app/entrypoint.sh

# /logs   — per-sensor subdirs land here; analyzer reads from this tree
# /data   — SQLite DB plus auto-generated TLS material under /data/tls
# Persistent shares for sshd state are declared in docker-compose.yml so
# operators can bind-mount them when host-side persistence matters.
VOLUME ["/logs", "/data"]

# 8080 — analyst UI (plain HTTP, LAN-side)
# 8443 — Quiver sensor checkin / install endpoint (TLS, pinned at enrollment)
# 22   — Quiver sensor rsync push (ssh-key auth)
EXPOSE 8080 8443 22

ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
CMD ["--addr=:8080", "--tls-addr=:8443", "--logs-dir=/logs"]
