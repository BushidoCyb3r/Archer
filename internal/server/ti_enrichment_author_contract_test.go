package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTIEnrichmentAuthor_Contract asserts that the literal string
// "TI Enrichment" — used as the note Author when TI cross-annotation
// or TI Hit detail enrichment writes a note onto a finding — appears
// in every emitter site (ti_crossnote.go, handlers_api.go) and the
// SPA consumer (detail.js). The SPA's dock split partitions notes by
// exact author match: notes authored by "TI Enrichment" surface in
// the TI Results tab; everything else goes to Notes.
//
// Without this contract test, a rename on either side (e.g.
// "TI Enrichment" → "Threat Intel Enrichment" because someone reading
// the codebase decides the latter is more precise) would silently
// break the dock partitioning: TI notes start landing in the Notes
// tab, the TI Results tab goes empty, and the dock-tab badge counts
// drift. Same shape as NEW-74's Spectral rescued marker test —
// locks a cross-language convention as compile-time enforced rather
// than aspirational. NEW-108.
func TestTIEnrichmentAuthor_Contract(t *testing.T) {
	const author = "TI Enrichment"

	emitters := []string{
		"ti_crossnote.go",
		"handlers_api.go",
	}
	for _, path := range emitters {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(body), author) {
			t.Errorf("%s no longer writes notes authored %q — detail.js's TI Results tab depends on this exact literal for note partitioning. Either update both sides in lockstep or update this test to match the new author string.", path, author)
		}
	}

	consumerPath, err := filepath.Abs(filepath.Join("..", "..", "web", "static", "js", "detail.js"))
	if err != nil {
		t.Fatalf("resolve detail.js: %v", err)
	}
	body, err := os.ReadFile(consumerPath)
	if err != nil {
		t.Fatalf("read detail.js: %v", err)
	}
	if !strings.Contains(string(body), author) {
		t.Errorf("detail.js no longer references the author literal %q — the Go side still emits it but the SPA no longer routes the notes to the TI Results tab. The dock partitioning is broken silently.", author)
	}
}
