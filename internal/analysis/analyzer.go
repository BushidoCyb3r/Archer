package analysis

import (
	"context"
	"math"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// sensorWindow is the per-sensor capture window used by time-based
// scoring (Beaconing histogram + duration). Keying the window by
// sensor keeps multi-sensor /logs/ trees independent — a January
// capture and an October capture each get scored against their own
// span instead of being smeared across the union of both.
type sensorWindow struct {
	min, max float64
}

// Analyzer orchestrates all Zeek log analysis steps.
type Analyzer struct {
	cfg           config.Config
	logsDir       string
	progressCh    chan<- ProgressEvent
	statusCh      chan<- string
	mu            sync.RWMutex
	findings      []model.Finding
	nextID        int
	sensorWindows map[string]sensorWindow
	sslUIDIndex   map[string]sslEntry
	httpUIDIndex  map[string]httpEntry

	// Pre-fetched threat intel feeds (populated during phase 0)
	feodoIPs     map[string]bool
	urlhausIPs   map[string]bool
	urlhausHosts map[string]bool

	// MISP / OpenCTI feed indicators, sourced via FeedProvider. Loaded
	// during phase 0 alongside the built-in feeds so checkTI /
	// checkSuspiciousURLs see the same shape regardless of source. Nil
	// FeedProvider = no MISP/OpenCTI hits, just built-ins.
	feedProvider FeedProvider
	feedSources  []SourcedFeedIndicators

	// Cancellation and pause
	ctx      context.Context
	cancel   context.CancelFunc
	resumeMu sync.Mutex
	resumeCh chan struct{} // closed = running, open = paused
}

// New creates an Analyzer. progressCh and statusCh may be nil.
// logsDir is the directory below which sensor names are derived (the
// first path component under it); it can be /logs for live analysis or
// /data/archive for archive-IOC re-scans. Pass "" to disable per-sensor
// bucketing — every record then lands in a single anonymous bucket
// (the legacy behavior, retained for tests that don't care about
// sensor identity).
func New(cfg config.Config, logsDir string, progressCh chan<- ProgressEvent, statusCh chan<- string) *Analyzer {
	ctx, cancel := context.WithCancel(context.Background())
	resumeCh := make(chan struct{})
	close(resumeCh) // start in running state
	return &Analyzer{
		cfg:           cfg,
		logsDir:       logsDir,
		progressCh:    progressCh,
		statusCh:      statusCh,
		sensorWindows: make(map[string]sensorWindow),
		sslUIDIndex:   make(map[string]sslEntry),
		httpUIDIndex:  make(map[string]httpEntry),
		ctx:           ctx,
		cancel:        cancel,
		resumeCh:      resumeCh,
	}
}

// sensorOf returns the first path component under logsDir, which is the
// sensor name in a Quiver-fed deployment. Returns "" when logsDir is
// empty or filePath escapes it — callers treat "" as a single anonymous
// bucket so detection still runs on hand-fed paths that don't follow
// the /<sensor>/<date>/ layout.
func (a *Analyzer) sensorOf(filePath string) string {
	if a.logsDir == "" {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(a.logsDir), filepath.Clean(filePath))
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	parts := strings.SplitN(rel, string(filepath.Separator), 2)
	if len(parts) > 0 && parts[0] != "." {
		return parts[0]
	}
	return ""
}

// observeWindow records ts against sensor's capture window. Caller
// holds nothing; this method takes a.mu briefly to merge.
func (a *Analyzer) observeWindow(sensor string, ts float64) {
	if ts <= 0 {
		return
	}
	a.mu.Lock()
	w := a.sensorWindows[sensor]
	if w.min == 0 || ts < w.min {
		w.min = ts
	}
	if ts > w.max {
		w.max = ts
	}
	a.sensorWindows[sensor] = w
	a.mu.Unlock()
}

// windowOf returns the capture window for sensor under read lock.
// Returns zero values when the sensor was never observed.
func (a *Analyzer) windowOf(sensor string) sensorWindow {
	a.mu.RLock()
	w := a.sensorWindows[sensor]
	a.mu.RUnlock()
	return w
}

// SetFeedProvider wires the source of MISP/OpenCTI feed indicators
// the analyzer should consult during TI matching. May be called at
// any time; the next prefetchFeeds invocation picks it up. Pass nil
// to detach.
func (a *Analyzer) SetFeedProvider(p FeedProvider) { a.feedProvider = p }

// Cancel stops the analysis as soon as possible.
func (a *Analyzer) Cancel() { a.cancel() }

// Ctx returns the analyzer's context (used by callers to detect cancellation).
func (a *Analyzer) Ctx() context.Context { return a.ctx }

// Pause suspends dispatch of new work. In-flight goroutines finish normally.
func (a *Analyzer) Pause() {
	a.resumeMu.Lock()
	defer a.resumeMu.Unlock()
	select {
	case <-a.resumeCh:
		// currently running (channel closed) → open a new channel to block
		a.resumeCh = make(chan struct{})
	default:
		// already paused
	}
}

// Resume unblocks a paused analysis.
func (a *Analyzer) Resume() {
	a.resumeMu.Lock()
	defer a.resumeMu.Unlock()
	select {
	case <-a.resumeCh:
		// already running
	default:
		close(a.resumeCh) // unblock waiting goroutines
	}
}

// IsPaused reports whether the analyzer is currently paused.
func (a *Analyzer) IsPaused() bool {
	a.resumeMu.Lock()
	ch := a.resumeCh
	a.resumeMu.Unlock()
	select {
	case <-ch:
		return false
	default:
		return true
	}
}

// waitIfPaused blocks until resumed or cancelled. Returns false if cancelled.
func (a *Analyzer) waitIfPaused() bool {
	a.resumeMu.Lock()
	ch := a.resumeCh
	a.resumeMu.Unlock()
	select {
	case <-ch:
		return true
	case <-a.ctx.Done():
		return false
	}
}

// Analyze runs all detection steps and returns findings.
// It can be stopped via Cancel() or paused/resumed via Pause()/Resume().
//
// Execution is pipelined into four phases:
//
//	Phase 0: threat-intel feed prefetch (network I/O, overlaps with phase 1)
//	Phase 1: all log-type analyzers in parallel (independent of each other)
//	Phase 2: HTTP analysis (sequential — needs sslUIDIndex from phase 1)
//	Phase 3: URL + TI checks in parallel (need cached feeds from phase 0)
//	Phase 4: host risk scoring (needs all findings)
func (a *Analyzer) Analyze(files []string) []model.Finding {
	collect := func() []model.Finding {
		a.mu.RLock()
		out := make([]model.Finding, len(a.findings))
		copy(out, a.findings)
		a.mu.RUnlock()
		return out
	}

	// ── Phase 0: start feed prefetch in background ───────────────────────────
	a.sendStatus("Fetching threat intel feeds…")
	feedsDone := make(chan struct{})
	go func() {
		a.prefetchFeeds(files)
		close(feedsDone)
	}()
	a.sendProgress(3, "Fetch Feeds")

	// ── Phase 1: independent log analyzers (all run in parallel) ─────────────
	type namedStep struct {
		name string
		fn   func([]string)
	}
	phase1 := []namedStep{
		{"Notices", a.analyzeNotice},
		{"Connections", a.analyzeConn},
		{"DNS", a.analyzeDNS},
		{"SSL/TLS", a.analyzeSSL},
		{"X.509 Certs", a.analyzeX509},
		{"File Downloads", a.analyzeFiles},
		{"Weird Events", a.analyzeWeird},
	}

	var wg1 sync.WaitGroup
	var done1 atomic.Int64
	total1 := int64(len(phase1))
	for _, s := range phase1 {
		wg1.Add(1)
		go func(name string, fn func([]string)) {
			defer wg1.Done()
			a.sendStatus("Analyzing: " + name + "…")
			fn(files)
			n := done1.Add(1)
			pct := 3 + int(float64(n)/float64(total1)*52)
			a.sendProgress(pct, name)
		}(s.name, s.fn)
	}
	wg1.Wait()
	a.sendProgress(55, "Log analysis")

	// waitIfPaused blocks until resumed; returns false if cancelled
	if !a.waitIfPaused() {
		return collect()
	}

	// ── Phase 2: HTTP (needs sslUIDIndex built by analyzeSSL in phase 1) ─────
	a.sendStatus("Analyzing: HTTP…")
	a.analyzeHTTP(files)
	a.sendProgress(68, "HTTP")

	if !a.waitIfPaused() {
		return collect()
	}

	// ── Phase 3: threat intel checks (need cached feeds from phase 0) ─────────
	<-feedsDone // ensure prefetch is complete
	a.sendStatus("Running threat intelligence checks…")
	var wg3 sync.WaitGroup
	wg3.Add(3)
	go func() { defer wg3.Done(); a.checkSuspiciousURLs(files) }()
	go func() { defer wg3.Done(); a.checkTI(files) }()
	go func() { defer wg3.Done(); a.checkFileHashes(files) }()
	wg3.Wait()
	a.sendProgress(88, "Threat Intel")

	if !a.waitIfPaused() {
		return collect()
	}

	// ── Phase 4: host risk scoring ────────────────────────────────────────────
	a.sendStatus("Scoring host risk…")
	a.aggregateRisk(files)
	a.sendProgress(100, "Complete")

	return collect()
}

// AnalyzeTIOnly runs the IOC + Feodo + URLhaus + suspicious-URL phases
// over the given file set without doing any of the expensive scoring
// (beacon, exfil, lateral, DNS-tunnel, file analysis, weird, x509, http).
// Used by the "Scan archive" admin action so a freshly added IOC or TI
// feed can match against historical logs that have already aged out of
// /logs into /data/archive. Host risk aggregation is also skipped — that
// step folds the full finding set, which would over-attribute scores
// when this pass intentionally produces only TI hits.
func (a *Analyzer) AnalyzeTIOnly(files []string) []model.Finding {
	collect := func() []model.Finding {
		a.mu.RLock()
		out := make([]model.Finding, len(a.findings))
		copy(out, a.findings)
		a.mu.RUnlock()
		return out
	}

	a.sendStatus("Fetching threat intel feeds…")
	feedsDone := make(chan struct{})
	go func() {
		a.prefetchFeeds(files)
		close(feedsDone)
	}()
	a.sendProgress(10, "Fetch Feeds")

	<-feedsDone
	if !a.waitIfPaused() {
		return collect()
	}

	a.sendStatus("Scanning archive against IOC list and TI feeds…")
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); a.checkSuspiciousURLs(files) }()
	go func() { defer wg.Done(); a.checkTI(files) }()
	go func() { defer wg.Done(); a.checkFileHashes(files) }()
	wg.Wait()
	a.sendProgress(100, "Complete")

	return collect()
}

func (a *Analyzer) add(f model.Finding) {
	a.mu.Lock()
	a.nextID++
	f.ID = a.nextID
	// SourceFile is intentionally not defaulted. Per-record analyzers fill
	// it with the originating Zeek log path; aggregate detections (Beacon-
	// ing, Strobe, Exfil, NXDOMAIN flood, Subdomain Diversity, HTTP
	// Beaconing, Host Risk Score) span many records across many files and
	// honestly have no single source file — leaving the field empty is
	// truthful, where the old behaviour of defaulting to f.Type produced
	// misleading values like "Beaconing" or "URLhaus" in CSV/JSON exports.
	a.findings = append(a.findings, f)
	a.mu.Unlock()
}

func (a *Analyzer) sendProgress(pct int, step string) {
	if a.progressCh != nil {
		select {
		case a.progressCh <- ProgressEvent{Pct: pct, Step: step}:
		default:
		}
	}
}

func (a *Analyzer) sendStatus(msg string) {
	if a.statusCh != nil {
		select {
		case a.statusCh <- msg:
		default:
		}
	}
}

// parallelEach runs fn on each file concurrently, bounded by both CPU count
// and the process memory budget. It checks for cancellation and pause between
// file dispatches.
func (a *Analyzer) parallelEach(files []string, fn func(path string)) {
	n := len(files)
	if n == 0 {
		return
	}
	workers := memoryBoundedWorkers(runtime.NumCPU())
	if workers > n {
		workers = n
	}
	if workers <= 1 {
		for _, f := range files {
			if a.ctx.Err() != nil {
				return
			}
			if !a.waitIfPaused() {
				return
			}
			fn(f)
		}
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for _, f := range files {
		if a.ctx.Err() != nil {
			break
		}
		if !a.waitIfPaused() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(path)
		}(f)
	}
	wg.Wait()
}

// memoryBoundedWorkers caps the caller's desired parallelism by the Go memory
// limit. Each concurrent log parser is estimated to peak around perWorkerBytes
// of live data while merging its local maps, so we divide the soft budget and
// take the lower of CPU count and memory count. Small hosts get 1–2 workers;
// big hosts get full CPU parallelism.
func memoryBoundedWorkers(cpus int) int {
	const perWorkerBytes int64 = 256 << 20 // 256 MiB per concurrent file parser
	lim := debug.SetMemoryLimit(-1)
	if lim <= 0 || lim == math.MaxInt64 {
		return cpus
	}
	byMem := int(lim / perWorkerBytes)
	if byMem < 1 {
		byMem = 1
	}
	if byMem < cpus {
		return byMem
	}
	return cpus
}

// filterFiles returns only files that match a given Zeek log type name.
func filterFiles(files []string, logType string) []string {
	var out []string
	for _, f := range files {
		base := filepath.Base(f)
		base = strings.TrimSuffix(base, ".gz")
		base = strings.TrimSuffix(base, ".log")
		if base == logType || strings.HasPrefix(base, logType+".") || strings.HasPrefix(base, logType+"_") {
			out = append(out, f)
		}
	}
	return out
}
