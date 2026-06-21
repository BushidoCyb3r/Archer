#!/usr/bin/env bash
# gate.sh — run the full release-gate set locally, mirroring CI (.github/
# workflows/ci.yml). Run this before declaring a release ready; a clean exit
# here is what the CI lint / test / vuln / js-test jobs check on push.
#
# Gates, in order (fail-fast — stops at the first failure):
#   1. gofmt -l        formatting
#   2. go vet ./...    static analysis
#   3. go test -race   full unit + handler suite under the race detector
#   4. CGO=0 build     the production build shape (pure-Go static binary)
#   5. govulncheck     reachability-based vulnerability scan (pinned to the
#                      CI version; uses an installed binary if present, else
#                      go run so it works on a box without it installed)
#   6. node --test     the dependency-free SPA test harness (web/test/)
#
# Usage: bash gate.sh

set -uo pipefail
cd "$(dirname "$0")"

GOVULN_VERSION="v1.3.0" # keep in sync with .github/workflows/ci.yml

fail() {
    echo
    echo "GATE FAILED: $1" >&2
    exit 1
}

step() { echo; echo "── $1 ──"; }

step "1/6 gofmt -l"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
    echo "$unformatted"
    fail "files need gofmt"
fi
echo "ok"

step "2/6 go vet ./..."
go vet ./... || fail "go vet"
echo "ok"

step "3/6 go test -race ./..."
go test -race ./... || fail "go test -race"

step "4/6 CGO_ENABLED=0 go build ./..."
CGO_ENABLED=0 go build ./... || fail "CGO=0 build"
echo "ok"

step "5/6 govulncheck"
if command -v govulncheck >/dev/null 2>&1; then
    govulncheck ./... || fail "govulncheck"
else
    echo "(govulncheck not installed — running via 'go run ...@${GOVULN_VERSION}')"
    go run "golang.org/x/vuln/cmd/govulncheck@${GOVULN_VERSION}" ./... || fail "govulncheck"
fi

step "6/6 node --test web/test/*.test.js"
if command -v node >/dev/null 2>&1; then
    node --test web/test/*.test.js || fail "js tests"
else
    fail "node not found — install Node.js to run the SPA test harness"
fi

echo
echo "ALL GATES PASSED"
