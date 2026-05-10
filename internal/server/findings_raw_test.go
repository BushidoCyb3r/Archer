package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestLogTypesForFinding_CoversAllEmittedTypes walks the analyzer's golden
// fixtures and asserts that every distinct finding Type produced has a
// corresponding entry in logTypesForFinding. Without this, future analyzers
// can add a new Type whose raw-log pivot silently falls through to the
// scan-everything fallback — the bug NEW-9 fixed (four wrong keys, two
// missing entries) was discoverable only by manual audit pre-test.
func TestLogTypesForFinding_CoversAllEmittedTypes(t *testing.T) {
	root := filepath.Join("..", "analysis", "testdata", "zeek")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("golden fixtures not present at %s: %v", root, err)
	}

	seen := map[string]string{} // type -> first fixture that emits it
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if filepath.Base(path) != "expected_findings.json" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var entries []struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(b, &entries); err != nil {
			t.Errorf("unmarshal %s: %v", path, err)
			return nil
		}
		for _, e := range entries {
			if e.Type == "" {
				continue
			}
			if _, ok := seen[e.Type]; !ok {
				seen[e.Type] = path
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(seen) == 0 {
		t.Fatal("no finding types discovered; fixture layout changed?")
	}

	var missing []string
	for typ := range seen {
		if _, ok := logTypesForFinding[typ]; !ok {
			missing = append(missing, typ+" (from "+seen[typ]+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("logTypesForFinding missing entries for emitted types:\n  %s", missing)
	}
}
