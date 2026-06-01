package server

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// TestRecoverAnalysis_SwallowsPanic is F-REL-1 (synchronous-phase backstop):
// a panic in a synchronous analysis phase (correlateFindings, aggregateRisk)
// or in post-processing must not propagate out of the analysis goroutine and
// crash the server. recoverAnalysis, deferred in the goroutine, recovers it
// and clears the analyzing flag. parallelEach covers the per-file detector
// panics; this covers everything else on the goroutine.
func TestRecoverAnalysis_SwallowsPanic(t *testing.T) {
	st := store.New(config.Default())
	st.SetAnalyzing(true)
	s := &Server{store: st, broker: NewBroker()}

	survived := func() (ok bool) {
		// If the panic escaped this frame, ok stays false (this deferred
		// func still runs, but the outer caller would itself panic). The
		// recoverAnalysis defer below is what stops the panic here.
		defer func() { ok = true }()
		defer s.recoverAnalysis("test-phase")
		panic("boom: synchronous detector panic")
	}()

	if !survived {
		t.Fatal("panic propagated past recoverAnalysis")
	}
	if st.IsAnalyzing() {
		t.Error("recoverAnalysis did not clear the analyzing flag")
	}
}
