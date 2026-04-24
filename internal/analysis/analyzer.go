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

// Analyzer orchestrates all Zeek log analysis steps.
type Analyzer struct {
	cfg          config.Config
	progressCh   chan<- ProgressEvent
	statusCh     chan<- string
	mu           sync.RWMutex
	findings     []model.Finding
	nextID       int
	datasetMin   float64
	datasetMax   float64
	sslUIDIndex  map[string]sslEntry
	httpUIDIndex map[string]httpEntry

	// Pre-fetched threat intel feeds (populated during phase 0)
	feodoIPs     map[string]bool
	urlhausIPs   map[string]bool
	urlhausHosts map[string]bool

	// Cancellation and pause
	ctx      context.Context
	cancel   context.CancelFunc
	resumeMu sync.Mutex
	resumeCh chan struct{} // closed = running, open = paused
}

// New creates an Analyzer. progressCh and statusCh may be nil.
func New(cfg config.Config, progressCh chan<- ProgressEvent, statusCh chan<- string) *Analyzer {
	ctx, cancel := context.WithCancel(context.Background())
	resumeCh := make(chan struct{})
	close(resumeCh) // start in running state
	return &Analyzer{
		cfg:          cfg,
		progressCh:   progressCh,
		statusCh:     statusCh,
		datasetMin:   math.MaxFloat64,
		datasetMax:   0,
		sslUIDIndex:  make(map[string]sslEntry),
		httpUIDIndex: make(map[string]httpEntry),
		ctx:          ctx,
		cancel:       cancel,
		resumeCh:     resumeCh,
	}
}

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
		{"Notices",        a.analyzeNotice},
		{"Connections",    a.analyzeConn},
		{"DNS",            a.analyzeDNS},
		{"SSL/TLS",        a.analyzeSSL},
		{"X.509 Certs",   a.analyzeX509},
		{"File Downloads", a.analyzeFiles},
		{"Weird Events",   a.analyzeWeird},
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
	wg3.Add(2)
	go func() { defer wg3.Done(); a.checkSuspiciousURLs(files) }()
	go func() { defer wg3.Done(); a.checkTI(files) }()
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

func (a *Analyzer) add(f model.Finding) {
	a.mu.Lock()
	a.nextID++
	f.ID = a.nextID
	if f.SourceFile == "" {
		f.SourceFile = f.Type
	}
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
