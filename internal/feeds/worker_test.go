package feeds

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeStore satisfies the worker's Store interface without touching
// SQLite. Each method records its calls for assertions.
type fakeStore struct {
	mu          sync.Mutex
	feeds       []Feed
	upserts     map[int64][]Indicator
	pruneCalls  []int64
	updateCalls []Feed
}

func newFakeStore(initial ...Feed) *fakeStore {
	return &fakeStore{
		feeds:   append([]Feed(nil), initial...),
		upserts: map[int64][]Indicator{},
	}
}

func (s *fakeStore) ListFeeds() []Feed {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Feed, len(s.feeds))
	copy(out, s.feeds)
	return out
}

func (s *fakeStore) UpdateFeed(f Feed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateCalls = append(s.updateCalls, f)
	for i := range s.feeds {
		if s.feeds[i].ID == f.ID {
			s.feeds[i] = f
			return nil
		}
	}
	return errors.New("feed not found")
}

func (s *fakeStore) UpsertFeedIndicators(feedID int64, inds []Indicator, now int64) (added, refreshed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := s.upserts[feedID]
	existingSet := make(map[string]bool, len(existing))
	for _, e := range existing {
		existingSet[e.Indicator] = true
	}
	for _, ind := range inds {
		if existingSet[ind.Indicator] {
			refreshed++
		} else {
			added++
			existing = append(existing, ind)
		}
	}
	s.upserts[feedID] = existing
	return added, refreshed, nil
}

func (s *fakeStore) RemoveStaleIndicators(feedID int64, before int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneCalls = append(s.pruneCalls, feedID)
	return 0, nil
}

// fakeAdapter returns the indicator slice it was constructed with.
type fakeAdapter struct {
	indicators []Indicator
	err        error
	calls      int
	mu         sync.Mutex
}

func (a *fakeAdapter) Source() SourceType { return SourceMISP }
func (a *fakeAdapter) Fetch(ctx context.Context, since int64) (FetchResult, error) {
	_ = since
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	if a.err != nil {
		return FetchResult{}, a.err
	}
	return FetchResult{Indicators: append([]Indicator(nil), a.indicators...)}, nil
}

// waitFor polls cond until it returns true or a generous deadline elapses,
// failing the test on timeout. Mirrors the poll-until-deadline pattern in
// internal/server/prune_test.go — preferred over a fixed time.Sleep, which
// either flakes under load (too short) or wastes wall-clock (too long).
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func TestWorker_RunsOneFetchPerFeedOnStart(t *testing.T) {
	store := newFakeStore(Feed{
		ID: 1, SourceType: SourceMISP, Name: "test", URL: "x", APIKey: "k",
		IndicatorAgingDays: 30, Enabled: true,
	})
	adapter := &fakeAdapter{indicators: []Indicator{
		{Indicator: "203.0.113.1", Type: IndicatorIP, SourceID: "1"},
		{Indicator: "evil.test", Type: IndicatorDomain, SourceID: "2"},
	}}
	w := NewWorker(store, func(f Feed) (Adapter, error) { return adapter, nil })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// Wait briefly for the first tick to land. The worker fires
	// immediately on start; 100ms is plenty.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		got := len(store.upserts[1])
		store.mu.Unlock()
		if got >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	store.mu.Lock()
	got := len(store.upserts[1])
	store.mu.Unlock()
	if got != 2 {
		t.Errorf("expected 2 indicators upserted, got %d", got)
	}

	adapter.mu.Lock()
	calls := adapter.calls
	adapter.mu.Unlock()
	if calls < 1 {
		t.Errorf("adapter Fetch called %d times, expected >= 1", calls)
	}
}

func TestWorker_SkipsDisabledFeeds(t *testing.T) {
	store := newFakeStore(
		Feed{ID: 1, SourceType: SourceMISP, Name: "disabled", URL: "x", APIKey: "k", Enabled: false},
		Feed{ID: 2, SourceType: SourceMISP, Name: "enabled", URL: "x", APIKey: "k", IndicatorAgingDays: 30, Enabled: true},
	)
	disabled := &fakeAdapter{indicators: []Indicator{{Indicator: "d", Type: IndicatorIP}}}
	enabled := &fakeAdapter{indicators: []Indicator{{Indicator: "e", Type: IndicatorIP}}}
	w := NewWorker(store, func(f Feed) (Adapter, error) {
		if f.ID == 1 {
			return disabled, nil
		}
		return enabled, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// Deterministic signal that the worker completed a full reconcile pass over
	// the feed list: the ENABLED feed got fetched. A reconcile iterates the
	// whole list in one pass, so once the enabled feed has been fetched the
	// disabled feed has been evaluated-and-skipped in that same pass — no fixed
	// sleep needed to "wait for a tick that shouldn't happen".
	waitFor(t, func() bool {
		enabled.mu.Lock()
		defer enabled.mu.Unlock()
		return enabled.calls >= 1
	}, "enabled sibling feed never fetched")
	cancel()

	disabled.mu.Lock()
	calls := disabled.calls
	disabled.mu.Unlock()
	if calls != 0 {
		t.Errorf("disabled feed should not fetch; got %d calls", calls)
	}
}

func TestWorker_RecordsErrorOnAdapterFailure(t *testing.T) {
	store := newFakeStore(Feed{
		ID: 1, SourceType: SourceMISP, Name: "test", URL: "x", APIKey: "k",
		Enabled: true,
	})
	adapter := &fakeAdapter{err: errors.New("simulated upstream failure")}
	w := NewWorker(store, func(f Feed) (Adapter, error) { return adapter, nil })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		hasErr := false
		for _, c := range store.updateCalls {
			if c.Status == "error" {
				hasErr = true
				break
			}
		}
		store.mu.Unlock()
		if hasErr {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	store.mu.Lock()
	defer store.mu.Unlock()
	foundError := false
	for _, c := range store.updateCalls {
		if c.Status == "error" && c.LastError != "" {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Errorf("expected an UpdateFeed call recording status=error; got %+v", store.updateCalls)
	}
}

func TestWorker_StopsLoopWhenFeedDisabled(t *testing.T) {
	store := newFakeStore(Feed{
		ID: 1, SourceType: SourceMISP, Name: "test", URL: "x", APIKey: "k",
		Enabled: true,
	})
	adapter := &fakeAdapter{indicators: []Indicator{{Indicator: "x", Type: IndicatorIP}}}
	w := NewWorker(store, func(f Feed) (Adapter, error) { return adapter, nil })
	w.reconcileInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// Poll until the first tick lands (deterministic) — proves the loop is
	// alive before we disable the feed.
	waitFor(t, func() bool {
		adapter.mu.Lock()
		defer adapter.mu.Unlock()
		return adapter.calls >= 1
	}, "first tick never fired")

	// Disable the feed, then let any in-flight reconcile (which may have
	// snapshotted the feed list before the flip) settle.
	store.mu.Lock()
	store.feeds[0].Enabled = false
	store.mu.Unlock()
	time.Sleep(2 * w.reconcileInterval)

	adapter.mu.Lock()
	afterDisable := adapter.calls
	adapter.mu.Unlock()

	// Over a multi-interval window the count must stay stable: a loop still
	// fetching the (now-disabled) feed every 50ms would add ~6 calls.
	time.Sleep(6 * w.reconcileInterval)
	cancel()

	adapter.mu.Lock()
	endCalls := adapter.calls
	adapter.mu.Unlock()

	if endCalls != afterDisable {
		t.Errorf("feed kept fetching after disable: afterDisable=%d endCalls=%d", afterDisable, endCalls)
	}
}
