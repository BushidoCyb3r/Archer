package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSpectralRescueMarker_Contract asserts that the literal string
// "Spectral rescued:" — written into a Beaconing or HTTP Beaconing
// finding's Detail field when the spectral rescue path wins the
// timing-axis score — appears in both the emitter sites (conn.go,
// http_analysis.go) and the consumer site (findings_filter.go's
// spectral_only=true query-param branch). The SPA's "Spectral rescued
// only" filter chip in the advanced filter bar depends on the
// server-side substring match against this exact literal.
//
// Without this contract test, a refactor that renames the marker on
// one side (e.g. "Spectral rescued:" → "Spectral periodogram rescue:"
// because someone reading the codebase decides the latter is more
// precise) would silently break the filter chip: the chip returns
// zero rows, the "Spectral rescued only" checkbox stops working,
// calibration becomes impossible. Same shape as NEW-30's _esc
// consistency test, NEW-41's audit-action vocabulary test, NEW-61's
// raw-decoder discipline test — locks a convention as compile-time
// enforced rather than aspirational. NEW-74.
func TestSpectralRescueMarker_Contract(t *testing.T) {
	const marker = "Spectral rescued:"

	analysisDir, err := filepath.Abs(filepath.Join("..", "analysis"))
	if err != nil {
		t.Fatalf("resolve analysis dir: %v", err)
	}
	emitters := []string{
		filepath.Join(analysisDir, "conn.go"),
		filepath.Join(analysisDir, "http_analysis.go"),
	}
	for _, path := range emitters {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(body), marker) {
			t.Errorf("%s no longer emits the literal %q — findings_filter.go's spectral_only filter and the SPA's `filter-spectral-only` checkbox both depend on this marker. Either update both sides in lockstep or update this test to match the new marker.", filepath.Base(path), marker)
		}
	}

	consumer := "findings_filter.go"
	body, err := os.ReadFile(consumer)
	if err != nil {
		t.Fatalf("read %s: %v", consumer, err)
	}
	if !strings.Contains(string(body), marker) {
		t.Errorf("%s no longer references the literal %q — the emitters still produce it but the consumer no longer matches against it. The spectral_only filter is broken silently.", consumer, marker)
	}
}
