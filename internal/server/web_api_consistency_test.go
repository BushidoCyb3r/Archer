package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestApiConsistency_AcrossSPAModules asserts every IIFE-private
// _api() fetch wrapper in the web SPA has the same body — same error
// shape (Promise.reject with new Error(...)), same content-type
// branching, same response decoding. The wrapper is copied per-module
// because each module's IIFE scope hides app.js's api() from it; the
// architect-review pass that surfaced this confirmed three copies
// existed (app.js's api() variant rejecting with a string is the
// outlier and intentionally separate) but the underscore-prefixed
// _api() copies in sensors.js and feeds.js are character-identical
// and should stay that way. Without an enforcement mechanism, a
// future change to one (e.g., adding a header, switching to async
// iterators on the body) silently drifts and the next reader can't
// tell which behavior is canonical.
//
// The _esc consistency test (web_esc_consistency_test.go) checks a
// semantic invariant (five HTML entities present). _api wrappers
// don't have a comparable per-character invariant — the meaningful
// equivalence is byte-for-byte. So this test extracts every _api
// function body and asserts they're all identical after whitespace
// normalization.
func TestApiConsistency_AcrossSPAModules(t *testing.T) {
	jsDir, err := filepath.Abs(filepath.Join("..", "..", "web", "static", "js"))
	if err != nil {
		t.Fatalf("resolve js dir: %v", err)
	}
	entries, err := os.ReadDir(jsDir)
	if err != nil {
		t.Fatalf("read js dir %s: %v", jsDir, err)
	}

	apiFnRE := regexp.MustCompile(`(?ms)function\s+_api\s*\([^)]*\)\s*\{(.*?)^\s*\}`)
	wsRE := regexp.MustCompile(`\s+`)

	type apiCopy struct {
		file string
		body string
	}
	var copies []apiCopy
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		if strings.HasSuffix(e.Name(), ".min.js") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(jsDir, e.Name()))
		if err != nil {
			t.Errorf("read %s: %v", e.Name(), err)
			continue
		}
		for _, m := range apiFnRE.FindAllSubmatch(body, -1) {
			normalized := strings.TrimSpace(wsRE.ReplaceAllString(string(m[1]), " "))
			copies = append(copies, apiCopy{file: e.Name(), body: normalized})
		}
	}

	const minExpected = 2
	if len(copies) < minExpected {
		t.Errorf("found %d _api definitions across SPA modules; expected at least %d (regex broken or modules removed?)", len(copies), minExpected)
		return
	}

	canon := copies[0]
	for _, c := range copies[1:] {
		if c.body != canon.body {
			t.Errorf("_api body in %s drifted from canonical (%s):\n  %s = %q\n  %s = %q",
				c.file, canon.file, canon.file, canon.body, c.file, c.body)
		}
	}
}
