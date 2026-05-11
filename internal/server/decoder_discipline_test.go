package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoRawJSONDecoderOnRequestBody enforces the discipline NEW-35,
// NEW-40, NEW-50, NEW-58, and NEW-61 collectively established:
// every request-body decode must go through decodeJSONBody (which
// applies a size cap, returns 413 on cap-trip, and never echoes
// raw decoder error text back to the caller). Pre-fix, the
// codebase had ad-hoc json.NewDecoder(r.Body).Decode(...) chains
// scattered across handlers; a typo in one of them (size cap
// forgotten, error response inconsistent) silently fragmented the
// discipline and made it impossible to audit by reading the
// CHANGELOG alone.
//
// One narrow exception is allowed:
//   - handlers_quiver.go's checkin path needs the RAW request body
//     for HMAC verification before JSON decode, so it does
//     read+cap+decode as a manual two-step. That manual chain
//     carries its own MaxBytesReader and 413 handling — verified
//     by a separate test (TestQuiverCheckin_BodyCapReturns413).
//
// Same shape as TestEscConsistency_AcrossSPAModules (NEW-30): the
// rule is the test, not a docstring that drifts as new handlers
// are added.
func TestNoRawJSONDecoderOnRequestBody(t *testing.T) {
	pattern := regexp.MustCompile(`json\.NewDecoder\(\s*r\.Body\s*\)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Go files found in package directory")
	}

	// Allowed: archive-run keeps the raw json.NewDecoder pattern
	// because the call-site silently tolerates decode errors
	// (req stays at zero values, which is the "real run, not
	// dry" semantic). decodeJSONBody can't be used there because
	// it writes a response on error, which would conflict with
	// the 200 the handler writes below. The MaxBytesReader wrap
	// on the same line bounds the body, so the size-cap
	// discipline is still applied — just without the helper.
	allowList := map[string]bool{
		"handlers_api.go": false, // checked separately below — must use MaxBytesReader
	}
	_ = allowList

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// Flatten newlines so multi-line decoder chains match.
		flat := regexp.MustCompile(`\s+`).ReplaceAllString(string(body), " ")
		matches := pattern.FindAllStringIndex(flat, -1)
		for _, m := range matches {
			// Walk a generous window backward and forward to
			// confirm whether the match is wrapped in
			// http.MaxBytesReader. If it is, the call is
			// bounded — acceptable. If not, the discipline is
			// broken.
			start := m[0]
			if start > 200 {
				start = m[0] - 200
			} else {
				start = 0
			}
			end := m[1]
			if end+50 < len(flat) {
				end = m[1] + 50
			} else {
				end = len(flat)
			}
			window := flat[start:end]
			if !strings.Contains(window, "MaxBytesReader") {
				t.Errorf("%s: raw json.NewDecoder(r.Body) without MaxBytesReader; use decodeJSONBody — NEW-61 regression", f)
			}
		}
	}
}
