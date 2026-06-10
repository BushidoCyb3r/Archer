FROM golang:1.25.11-alpine AS builder

ENV GOTOOLCHAIN=local

# Version metadata is baked in at build time via -ldflags. start.sh fills
# these from `git describe --tags --always` and `git rev-parse --short HEAD`
# so each rebuild reports the actual checkout state. Defaults match the
# baked-in values in internal/version/version.go for the air-gap case where
# the build host has no git history (tarball install).
ARG ARCHER_VERSION=v0.1.0
ARG ARCHER_COMMIT=unknown
ARG ARCHER_BUILD_TIME=unknown

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X github.com/BushidoCyb3r/Archer/internal/version.Version=${ARCHER_VERSION} \
      -X github.com/BushidoCyb3r/Archer/internal/version.Commit=${ARCHER_COMMIT} \
      -X github.com/BushidoCyb3r/Archer/internal/version.BuildTime=${ARCHER_BUILD_TIME}" \
    -o /archer ./cmd/archer

# ── Final image ───────────────────────────────────────────────────────────────
FROM alpine:3.23

# tini reaps zombies and forwards signals so that sshd dies cleanly when
# Archer exits. openssh-server + rsync are the sensor-facing transport
# (Quiver sensors push their daily logs over ssh). ca-certificates and
# tzdata are kept from the original image for outbound TLS calls.
RUN apk add --no-cache ca-certificates tzdata openssh-server tini rsync rrsync su-exec \
    && adduser -D -h /home/quiver -s /bin/sh quiver \
    # adduser -D leaves /etc/shadow with `quiver:!:...` which marks the
    # account locked. Alpine's openssh is built without PAM (UsePAM is a
    # no-op), so its allowed_user check refuses locked accounts even with
    # PubkeyAuthentication=yes — sshd logs "invalid user quiver" and the
    # rsync push fails with Permission denied. `*` means "no usable
    # password" without locking the account; PasswordAuthentication=no
    # in sshd_config keeps password auth shut regardless.
    && sed -i 's/^quiver:!:/quiver:*:/' /etc/shadow \
    && mkdir -p /home/quiver/.ssh /etc/ssh/keys /run/sshd \
    && touch /home/quiver/.ssh/authorized_keys \
    && chown -R quiver:quiver /home/quiver \
    && chmod 700 /home/quiver/.ssh \
    && chmod 600 /home/quiver/.ssh/authorized_keys \
    && chmod 700 /run/sshd \
    && adduser -D -u 1001 -H -s /sbin/nologin archer \
    && addgroup quiver archer

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

# Re-declare ARGs in the final stage so OCI image labels can interpolate
# them — ARG values from the builder stage don't carry over by default.
ARG ARCHER_VERSION=v0.1.0
ARG ARCHER_COMMIT=unknown
LABEL org.opencontainers.image.title="Archer"
LABEL org.opencontainers.image.version="${ARCHER_VERSION}"
LABEL org.opencontainers.image.revision="${ARCHER_COMMIT}"
LABEL org.opencontainers.image.source="https://github.com/BushidoCyb3r/Archer"

# 8443 — analyst/admin/viewer UI + API + Quiver sensor checkin / install
#        endpoint, all over TLS. Sensors pin the cert at enrollment;
#        browsers validate against the CA chain (operator drops in
#        their own CA-signed cert per OPERATIONS.md). The pre-v0.14.5
#        plaintext :8080 listener was removed in NEW-49 — admin auth
#        had been transmitted in cleartext, which is unacceptable for
#        a tool whose threat model is "the LAN may be hostile."
# 22   — Quiver sensor rsync push (ssh-key auth, separate sshd)
EXPOSE 8443 22

# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["--tls-addr=:8443", "--logs-dir=/logs"]
