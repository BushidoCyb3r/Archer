package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoRawJSONDecoderOnRequestBody enforces the bounded-decode
// discipline NEW-35, NEW-40, NEW-50, NEW-58, and NEW-61 collectively
// established: no request-body decode may read an UNBOUNDED body. The
// failure mode it guards against is an `json.NewDecoder(r.Body)` chain
// with no size cap, which lets a caller stream an arbitrarily large
// body into memory. Pre-fix such chains were scattered across handlers;
// a typo dropping the cap silently fragmented the discipline.
//
// Two bounded forms are accepted, both safe:
//   - decodeJSONBody(w, r, &dst, cap) — the PREFERRED path. Adds a
//     413 on cap-trip, DisallowUnknownFields, a trailing-content
//     check, and a generic (non-echoing) error. New handlers should
//     use this.
//   - a manual `json.NewDecoder(http.MaxBytesReader(w, r.Body, cap))`
//     where the handler needs error handling decodeJSONBody can't give:
//     the sensors-modal handlers fold the decode error into their
//     `req.ID == 0` validation, and the archive-run / optional-body
//     handlers (handlers_api.go) deliberately tolerate a decode error
//     (zero-value req = "real run, not dry") and must not have an error
//     response written for them. The MaxBytesReader sits directly in the
//     decode expression, so these are bounded by construction.
//
// One body-not-decoded exception:
//   - handlers_quiver.go's checkin path needs the RAW request body for
//     HMAC verification before JSON decode, so it does read+cap+decode
//     as a manual two-step. That chain carries its own MaxBytesReader
//     and 413 handling — verified by TestQuiverCheckin_BodyCapReturns413.
//
// Same shape as TestEscConsistency_AcrossSPAModules (NEW-30): the rule
// is the test. What it matches is the bare `json.NewDecoder(r.Body)`
// form (the unbounded failure mode, and also decodeJSONBody's own
// internal decode, which sets r.Body = MaxBytesReader on the prior line);
// every such match must have MaxBytesReader in its window. The
// wrapped-argument form `json.NewDecoder(http.MaxBytesReader(...))` is
// bounded by construction and intentionally outside the match set.
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
