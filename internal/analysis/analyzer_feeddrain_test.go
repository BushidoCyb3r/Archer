package analysis

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
)

// blockingFeedProvider blocks in EnabledFeedIndicators until release is closed,
// signalling entry on entered. It holds prefetchFeeds open while the rest of
// Analyze runs, so the test can observe whether Analyze waits for it.
type blockingFeedProvider struct {
	entered chan struct{}
	release chan struct{}
}

func (p *blockingFeedProvider) EnabledFeedIndicators() []feeds.SourcedIndicators {
	close(p.entered)
	<-p.release
	return nil
}

// TestAnalyze_CancelDoesNotLeakPrefetch is the F-CON-1 regression. Feed prefetch
// runs in a background goroutine that writes a.feodoIPs/urlhausIPs/urlhausHosts/
// feedSources, guarded only by the feedsDone barrier the phase-3 drain waits on.
// A cancel during phases 1–2.5 takes an early return that skips that drain —
// before the fix the goroutine leaked and kept writing those fields after
// Analyze had returned. The invariant: Analyze does not return until the
// prefetch goroutine has finished, even when cancelled early. Run under -race.
func TestAnalyze_CancelDoesNotLeakPrefetch(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	// Skip the live HTTP fetches; the only prefetch work is the blocking
	// feed-provider call we control.
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	prov := &blockingFeedProvider{entered: make(chan struct{}), release: make(chan struct{})}
	a.SetFeedProvider(prov)

	// Pause then cancel: with the resume channel open (paused) and the context
	// cancelled, the first waitIfPaused after phase 1 can only select ctx.Done()
	// and returns false, deterministically taking the early-return path that
	// skips the phase-3 feedsDone drain.
	a.Pause()
	a.Cancel()

	returned := make(chan struct{})
	go func() {
		a.Analyze(nil)
		close(returned)
	}()

	select {
	case <-prov.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("prefetch never reached the feed provider")
	}

	// Analyze must NOT have returned yet — the deferred drain holds it until
	// prefetch finishes. Before the fix it returned here, leaking the goroutine.
	select {
	case <-returned:
		t.Fatal("Analyze returned before the prefetch goroutine finished — the goroutine leaked")
	case <-time.After(100 * time.Millisecond):
	}

	// Release prefetch; Analyze must now return promptly.
	close(prov.release)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Analyze did not return after prefetch completed")
	}
}
