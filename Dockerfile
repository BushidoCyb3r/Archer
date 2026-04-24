FROM golang:1.25-alpine AS builder

ENV GOTOOLCHAIN=local

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /archer ./cmd/archer

# ── Final image ───────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /archer ./archer
COPY web/ ./web/

VOLUME ["/logs", "/data"]

EXPOSE 8080

ENTRYPOINT ["/app/archer"]
CMD ["--addr=:8080", "--logs-dir=/logs"]
