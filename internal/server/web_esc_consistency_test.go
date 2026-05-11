package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEscConsistency_AcrossSPAModules asserts every IIFE-private
// _esc() in the web SPA escapes the full five-character set
// (&, <, >, ", '). Pre-NEW-30 there were three distinct shapes
// across seven files — strong (5 chars), near-strong (missing '),
// and weak (missing both " and '). The comment claiming a
// "convention" was aspirational rather than descriptive, and a
// developer copy-pasting an attribute-context interpolation into a
// weak-_esc module would silently re-introduce XSS without seeing
// any local signal that the helper was insufficient.
//
// This test is Go-side (rather than a JS test runner) because Archer
// has no JS test harness and adding one for a single audit-driven
// invariant isn't worth the dependency. A naive regex over the file
// contents is sufficient: each _esc must contain references to all
// five HTML entities (&amp; &lt; &gt; &quot; &#39;). Audit
// 2026-05-10 NEW-30.
func TestEscConsistency_AcrossSPAModules(t *testing.T) {
	jsDir, err := filepath.Abs(filepath.Join("..", "..", "web", "static", "js"))
	if err != nil {
		t.Fatalf("resolve js dir: %v", err)
	}

	// Modules that own an _esc helper. Discovery is regex-driven so a
	// new module that defines _esc gets caught automatically; the
	// allowlist below is just for the negative assertion below.
	entries, err := os.ReadDir(jsDir)
	if err != nil {
		t.Fatalf("read js dir %s: %v", jsDir, err)
	}

	// escFnRE captures the body of a `function _esc(...) { ... }`
	// definition. The bodies in this codebase are all one-liner or
	// few-liner; a balanced-brace match is overkill, so we just grab
	// from `function _esc` to the matching standalone `}` (the close
	// of the function, given the codebase formatting).
	escFnRE := regexp.MustCompile(`(?ms)function\s+_esc\s*\([^)]*\)\s*\{(.*?)^\s*\}`)

	expectedEntities := []string{
		"&amp;",
		"&lt;",
		"&gt;",
		"&quot;",
		"&#39;",
	}

	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		// Skip vendored/minified files — third-party code lives by
		// its own escape discipline and we don't audit it.
		if strings.HasSuffix(e.Name(), ".min.js") {
			continue
		}
		path := filepath.Join(jsDir, e.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		matches := escFnRE.FindAllSubmatch(body, -1)
		if len(matches) == 0 {
			continue // module doesn't define _esc — fine
		}
		for i, m := range matches {
			fnBody := string(m[1])
			for _, ent := range expectedEntities {
				if !strings.Contains(fnBody, ent) {
					t.Errorf("%s _esc #%d: missing %q entity in body:\n%s",
						e.Name(), i, ent, fnBody)
				}
			}
			found++
		}
	}

	// Belt-and-suspenders: we currently ship _esc across 8 SPA
	// modules — app, detail, table, notifications, campaigns, feeds,
	// sensors, beacon_evolution. The floor is tightened each time a
	// new module joins so a regression that drops _esc from a single
	// module trips immediately rather than waiting for two more
	// modules to also lose theirs (the "at least 6" floor pre-v0.16.1
	// would have let the first 2 modules silently inline unescaped
	// strings without breaking the test). NEW-80 from the
	// eighteenth audit round.
	const minExpected = 8
	if found < minExpected {
		t.Errorf("found %d _esc definitions across SPA modules; expected at least %d (regex broken or modules removed?)", found, minExpected)
	}
}
