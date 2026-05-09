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
// configured feeds; each feed gets its own goroutine that ticks on a
// fixed 60-minute cadence. The Worker re-syncs its goroutine set
// against the feeds table every reconcileInterval (default 30s) so
// admin-UI add/remove/enable/disable changes propagate without a
// server restart.
//
// As of v0.6.0 the Worker is no longer started by default — feed
// refresh runs synchronously before each watch full-pass. This code
// is kept for the rare deployment that wants the old per-feed
// background loop; re-enable by uncommenting startFeedWorker in
// server.New.
type Worker struct {
	store      Store
	adapterFor AdapterFor

	mu       sync.Mutex
	cancels  map[int64]context.CancelFunc
	versions map[int64]string // enabled signature; restart loop on change

	now func() time.Time

	reconcileInterval time.Duration
}

// workerCadence is the fixed per-feed refresh interval used by the
// (now-disabled-by-default) background Worker. Was per-feed configurable
// pre-v0.7.0; uniform here since the watch full-pass is the primary
// refresh path and operators no longer need per-feed scheduling.
const workerCadence = 60 * time.Minute

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

// reconcile spawns a per-feed goroutine for any newly-enabled feed
// and stops the goroutine for any newly-disabled or removed feed.
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
		// Either not running, or enabled flipped — restart.
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
// so URL / API key changes the operator made via the admin UI take
// effect without a worker restart.
func (w *Worker) runOne(ctx context.Context, feedID int64) {
	if cur := w.lookup(feedID); cur.ID == 0 {
		return
	}

	// First tick fires immediately on start so a freshly-added feed
	// populates without waiting a full cycle.
	w.tick(ctx, feedID)
	t := time.NewTicker(workerCadence)
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
// restart (just the enabled flag now). URL / API-key changes are
// read per-tick so they don't need a restart.
func versionSig(f Feed) string {
	if f.Enabled {
		return "1"
	}
	return "0"
}
