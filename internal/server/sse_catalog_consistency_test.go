package server

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestSSECatalogConsistency_ServerVsClient asserts every SSE event type the
// server publishes (Publish(SSEEvent{Type: "..."})) is registered as a
// listener in the web client (web/static/js/sse.js). The client only delivers
// events it explicitly addEventListener's for, so a server type missing from
// sse.js is silently dropped in the UI — the same silent-information-loss class
// the resync_required overflow canary was built to fight. The two lists are
// maintained by hand in different languages; this is the only thing keeping
// them in lockstep (same shape as web_esc_consistency_test.go: the rule is the
// test, not a docstring that drifts as event types are added).
func TestSSECatalogConsistency_ServerVsClient(t *testing.T) {
	// 1. Server-side published types.
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	typeRE := regexp.MustCompile(`SSEEvent\{\s*Type:\s*"([^"]+)"`)
	serverTypes := map[string]string{} // type -> first file it appears in
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range typeRE.FindAllStringSubmatch(string(body), -1) {
			if _, ok := serverTypes[m[1]]; !ok {
				serverTypes[m[1]] = f
			}
		}
	}
	if len(serverTypes) < 5 {
		t.Fatalf("found only %d SSEEvent types in server source — regex broken?", len(serverTypes))
	}

	// 2. Client-registered types: read sse.js once.
	ssePath := filepath.Join("..", "..", "web", "static", "js", "sse.js")
	sseJS, err := os.ReadFile(ssePath)
	if err != nil {
		t.Fatalf("read sse.js: %v", err)
	}
	sse := string(sseJS)

	// 3. Every server type must be referenced as a quoted literal in sse.js.
	var missing []string
	for typ, file := range serverTypes {
		if !strings.Contains(sse, `'`+typ+`'`) && !strings.Contains(sse, `"`+typ+`"`) {
			missing = append(missing, typ+" (published in "+file+")")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("SSE event types published by the server but not registered in sse.js (UI will silently drop them):\n  %s", strings.Join(missing, "\n  "))
	}
}
