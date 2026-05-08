package feeds

import (
	"context"
	"log"
	"sync"
	"time"
)

// Store is the subset of the central store the worker needs.
// Defined as an interface here so the worker can be unit-tested
// against an in-memory fake without taking a SQLite dependency.
type Store interface {
	ListFeeds() []Feed
	UpdateFeed(f Feed) error
	UpsertFeedIndicators(feedID int64, inds []Indicator, now int64) (added, refreshed int, err error)
	RemoveStaleIndicators(feedID int64, before int64) (int, error)
}

// AdapterFor maps a SourceType to a constructed Adapter for a given
// Feed. Pluggable so tests can inject a fake adapter and so future
// source-types (OpenCTI in slice 3) hook in cleanly.
type AdapterFor func(f Feed) (Adapter, error)

// Worker schedules per-feed refreshes. One Worker manages all
// configured feeds; each feed gets its own goroutine that ticks on
// its configured cadence. The Worker re-syncs its goroutine set
// against the feeds table every reconcileInterval (default 30s) so
// admin-UI add/remove/enable/disable changes propagate without a
// server restart.
type Worker struct {
	store      Store
	adapterFor AdapterFor

	mu       sync.Mutex
	cancels  map[int64]context.CancelFunc
	versions map[int64]string // cadence|enabled signature; restart loop on change

	now func() time.Time

	reconcileInterval time.Duration
}

// NewWorker constructs a Worker.
func NewWorker(s Store, adapterFor AdapterFor) *Worker {
	return &Worker{
		store:             s,
		adapterFor:        adapterFor,
		cancels:           make(map[int64]context.CancelFunc),
		versions:          make(map[int64]string),
		now:               time.Now,
		reconcileInterval: 30 * time.Second,
	}
}

// Run blocks, reconciling per-feed loops until ctx is cancelled. Spawn
// in a goroutine. On shutdown, the context cancellation propagates to
// each per-feed loop.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.reconcileInterval)
	defer ticker.Stop()
	w.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			w.stopAll()
			return
		case <-ticker.C:
			w.reconcile(ctx)
		}
	}
}

// reconcile spawns a per-feed goroutine for any newly-enabled feed,
// stops the goroutine for any newly-disabled or removed feed, and
// restarts the goroutine for any feed whose cadence changed (the only
// way to update the ticker interval is to rebuild the loop).
func (w *Worker) reconcile(ctx context.Context) {
	feeds := w.store.ListFeeds()

	live := make(map[int64]bool, len(feeds))
	for _, f := range feeds {
		live[f.ID] = true
		sig := versionSig(f)
		w.mu.Lock()
		oldSig, running := w.versions[f.ID]
		w.mu.Unlock()
		if !f.Enabled {
			if running {
				w.stop(f.ID)
			}
			continue
		}
		if running && oldSig == sig {
			continue
		}
		// Either not running, or cadence/enabled flipped — restart.
		if running {
			w.stop(f.ID)
		}
		w.start(ctx, f, sig)
	}

	// Sweep up loops for feeds that no longer exist.
	w.mu.Lock()
	for id := range w.cancels {
		if !live[id] {
			delete(w.cancels, id)
			delete(w.versions, id)
		}
	}
	w.mu.Unlock()
}

func (w *Worker) start(parent context.Context, f Feed, sig string) {
	ctx, cancel := context.WithCancel(parent)
	w.mu.Lock()
	w.cancels[f.ID] = cancel
	w.versions[f.ID] = sig
	w.mu.Unlock()
	go w.runOne(ctx, f.ID)
}

func (w *Worker) stop(id int64) {
	w.mu.Lock()
	if cancel, ok := w.cancels[id]; ok {
		cancel()
		delete(w.cancels, id)
		delete(w.versions, id)
	}
	w.mu.Unlock()
}

func (w *Worker) stopAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, cancel := range w.cancels {
		cancel()
		delete(w.cancels, id)
		delete(w.versions, id)
	}
}

// runOne is the per-feed loop. Re-reads the feed row before each tick
// so URL / API key / cadence changes the operator made via the admin
// UI take effect without a worker restart. Cadence changes themselves
// require a loop restart (handled by reconcile) because the ticker
// interval is fixed at start; intra-tick changes to refresh_cadence
// are noted but applied on the next reconcile.
func (w *Worker) runOne(ctx context.Context, feedID int64) {
	// Refresh feed config inside the loop so the first tick uses
	// current state even if the row was updated between
	// ListFeeds() and start().
	cur := w.lookup(feedID)
	if cur.ID == 0 {
		return
	}
	cadence := time.Duration(cur.RefreshCadenceMinutes) * time.Minute
	if cadence <= 0 {
		cadence = 60 * time.Minute
	}

	// First tick fires immediately on start so a freshly-added feed
	// populates without waiting a full cycle.
	w.tick(ctx, feedID)
	t := time.NewTicker(cadence)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx, feedID)
		}
	}
}

// tick performs one fetch+upsert+prune cycle for the given feed.
// Failures are recorded in the feed row's last_error/status fields
// and don't crash the loop; transient upstream issues just skip a
// cycle.
func (w *Worker) tick(ctx context.Context, feedID int64) {
	f := w.lookup(feedID)
	if f.ID == 0 || !f.Enabled {
		return
	}

	adapter, err := w.adapterFor(f)
	if err != nil {
		w.recordError(f, "adapter init: "+err.Error())
		return
	}

	mark := f
	mark.Status = "fetching"
	_ = w.store.UpdateFeed(mark)

	inds, err := adapter.Fetch(ctx)
	if err != nil {
		w.recordError(f, "fetch: "+err.Error())
		return
	}

	now := w.now().Unix()
	added, refreshed, err := w.store.UpsertFeedIndicators(f.ID, inds, now)
	if err != nil {
		w.recordError(f, "upsert: "+err.Error())
		return
	}

	// Aging: remove anything not seen in this cycle and older than the
	// configured window. Indicators present in this fetch had their
	// last_seen bumped to `now` above, so they survive the cutoff.
	if f.IndicatorAgingDays > 0 {
		cutoff := now - int64(f.IndicatorAgingDays)*86400
		_, _ = w.store.RemoveStaleIndicators(f.ID, cutoff)
	}

	done := f
	done.LastRefreshAt = now
	done.LastIndicatorCount = added + refreshed
	done.LastError = ""
	done.Status = "ok"
	_ = w.store.UpdateFeed(done)

	log.Printf("feeds: %s/%s — added %d, refreshed %d", f.SourceType, f.Name, added, refreshed)
}

func (w *Worker) lookup(feedID int64) Feed {
	for _, f := range w.store.ListFeeds() {
		if f.ID == feedID {
			return f
		}
	}
	return Feed{}
}

func (w *Worker) recordError(f Feed, msg string) {
	f.LastError = msg
	f.Status = "error"
	_ = w.store.UpdateFeed(f)
	log.Printf("feeds: %s/%s — %s", f.SourceType, f.Name, msg)
}

// versionSig captures the fields whose change requires a loop
// restart (cadence and enabled flag). URL/API-key changes are read
// per-tick so they don't need a restart.
func versionSig(f Feed) string {
	enabled := "0"
	if f.Enabled {
		enabled = "1"
	}
	return enabled + ":" + itoa(f.RefreshCadenceMinutes)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
