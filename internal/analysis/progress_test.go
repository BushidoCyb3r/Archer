package analysis

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestAnalyzerProgressSnapshot pins the snapshot the /api/analyze/status handler
// reads so a client reloaded mid-run can restore its progress bar: sendProgress
// records the latest pct/step, and Progress() returns them. Without this the
// status endpoint can't report where the run is, and the bar sits at 0 until the
// next coarse phase-boundary SSE event.
func TestAnalyzerProgressSnapshot(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	if pct, step := a.Progress(); pct != 0 || step != "" {
		t.Fatalf("fresh analyzer Progress() = (%d, %q); want (0, \"\")", pct, step)
	}
	a.sendProgress(55, "Log analysis")
	if pct, step := a.Progress(); pct != 55 || step != "Log analysis" {
		t.Errorf("after sendProgress Progress() = (%d, %q); want (55, \"Log analysis\")", pct, step)
	}
	a.sendProgress(88, "Threat Intel")
	if pct, step := a.Progress(); pct != 88 || step != "Threat Intel" {
		t.Errorf("Progress() not updated to latest = (%d, %q); want (88, \"Threat Intel\")", pct, step)
	}
}
