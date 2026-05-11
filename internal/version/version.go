// Package version exposes the Archer release identifier so handlers, the
// UI, and JSON exports can read a single source of truth instead of
// hardcoding strings. The values are populated at build time via -ldflags
// "-X github.com/BushidoCyb3r/Archer/internal/version.Version=v0.x.y" so
// the same source tree can be tagged any number of times without source
// edits. The bare-checkout defaults below let `go run` and air-gapped
// tarball installs (where the build host has no git history) still report
// a sensible version.
package version

// Version is the release tag this binary was built from. Production
// builds set it via -ldflags from `git describe --tags --always`.
var Version = "v0.15.0"

// Commit is the short git SHA this binary was built from. "unknown" when
// the build host had no git checkout (e.g. air-gap tarball).
var Commit = "unknown"

// BuildTime is the UTC timestamp of the build, ISO-8601. "unknown" for
// builds that didn't pass it via -ldflags.
var BuildTime = "unknown"
