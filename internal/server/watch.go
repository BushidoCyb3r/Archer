package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
)

// startWatch starts the watch loop if watch is enabled in the config.
// Safe to call at startup and after any config change — cancels any existing
// loop first. The interval is read from config: 0/24 = once daily at the
// anchor time, 12/6/4/1 = sub-daily ticks aligned to the anchor's hour.
func (s *Server) startWatch() {
	watchTime, enabled := s.store.GetWatch()
	if !enabled || watchTime == "" {
		return
	}
	tz := s.store.GetTimezone()
	intervalHours := s.store.GetWatchInterval()

	ctx, cancel := context.WithCancel(context.Background())

	s.watchMu.Lock()
	if s.watchCancel != nil {
		s.watchCancel()
	}
	s.watchCancel = cancel
	s.watchMu.Unlock()

	go s.runWatchLoop(ctx, watchTime, tz, intervalHours)
}

// stopWatch cancels the running watch loop, if any.
func (s *Server) stopWatch() {
	s.watchMu.Lock()
	if s.watchCancel != nil {
		s.watchCancel()
		s.watchCancel = nil
	}
	s.watchMu.Unlock()
}

// runWatchLoop sleeps until the next scheduled tick, triggers analysis,
// then repeats. Exits on cancellation or whenever the configured
// time/TZ/interval/enabled state changes — startWatch will spin up a fresh
// loop with the new values.
func (s *Server) runWatchLoop(ctx context.Context, hhmm, tzName string, intervalHours int) {
	for {
		loc := loadLocationOrUTC(tzName)
		next, err := nextOccurrenceInterval(hhmm, intervalHours, loc)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
			currentTime, enabled := s.store.GetWatch()
			currentTZ := s.store.GetTimezone()
			currentInterval := s.store.GetWatchInterval()
			if !enabled || currentTime != hhmm || currentTZ != tzName || currentInterval != intervalHours {
				return
			}
			s.triggerWatchAnalysis()
		}
	}
}

// loadLocationOrUTC resolves an IANA timezone name, falling back to UTC for
// empty or unparseable input. A bad TZ shouldn't break the watch loop —
// firing in UTC is preferable to not firing at all.
func loadLocationOrUTC(name string) *time.Location {
	if name == "" {
		return time.UTC
	}
	if loc, err := time.LoadLocation(name); err == nil {
		return loc
	}
	return time.UTC
}

// formatRelativeTime renders a time as a compact, scannable string for the
// watch-mode UI. Today/Tomorrow get spelled out (the common case); same-week
// dates fall back to weekday + time; further-out dates use month-day; only
// dates in a different calendar year include the year. The timezone
// abbreviation is intentionally NOT included — the caller's UI already
// shows the configured timezone in the input above.
//
// Examples (all in the supplied loc):
//
//	Today 06:00
//	Tomorrow 00:00
//	Mon 14:30
//	May 12 09:00
//	Jan 3 2027 02:00
func formatRelativeTime(t time.Time, loc *time.Location) string {
	nowLoc := time.Now().In(loc)
	tLoc := t.In(loc)
	nowDate := time.Date(nowLoc.Year(), nowLoc.Month(), nowLoc.Day(), 0, 0, 0, 0, loc)
	tDate := time.Date(tLoc.Year(), tLoc.Month(), tLoc.Day(), 0, 0, 0, 0, loc)
	daysDiff := int(tDate.Sub(nowDate).Hours() / 24)
	hm := tLoc.Format("15:04")
	switch {
	case daysDiff == 0:
		return "Today " + hm
	case daysDiff == 1:
		return "Tomorrow " + hm
	case daysDiff > 1 && daysDiff < 7 && tLoc.Year() == nowLoc.Year():
		return tLoc.Format("Mon ") + hm
	case tLoc.Year() == nowLoc.Year():
		return tLoc.Format("Jan 2 ") + hm
	default:
		return tLoc.Format("Jan 2 2006 ") + hm
	}
}

// nextOccurrence returns the next wall-clock time in loc when HH:MM will
// occur. If that time has already passed today (in loc), returns tomorrow.
func nextOccurrence(hhmm string, loc *time.Location) (time.Time, error) {
	var h, m int
	if _, err := parseHHMM(hhmm, &h, &m); err != nil {
		return time.Time{}, err
	}
	now := time.Now().In(loc)
	next := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, loc)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next, nil
}

// nextOccurrenceInterval returns the next scheduled tick. interval==0 (or
// 24) is the legacy daily semantic — fire once per day at HH:MM. Otherwise
// the watch fires every `interval` hours starting from a base hour aligned
// to HH (so an admin who picks "every 4h at 02:30" sees runs at 02:30,
// 06:30, 10:30, …, regardless of when they enabled it).
func nextOccurrenceInterval(hhmm string, interval int, loc *time.Location) (time.Time, error) {
	var h, m int
	if _, err := parseHHMM(hhmm, &h, &m); err != nil {
		return time.Time{}, err
	}
	if interval == 0 || interval == 24 {
		return nextOccurrence(hhmm, loc)
	}
	if interval != 1 && interval != 4 && interval != 6 && interval != 12 {
		// Defensive: an unsupported interval falls back to daily so the
		// loop keeps firing instead of silently dying.
		return nextOccurrence(hhmm, loc)
	}
	now := time.Now().In(loc)
	// Anchor: HH mod interval gives the hour-of-cycle the admin picked.
	// E.g. interval=4, HH=10 → anchor=2, so runs are 02, 06, 10, 14, 18, 22.
	anchor := h % interval
	candidate := time.Date(now.Year(), now.Month(), now.Day(), anchor, m, 0, 0, loc)
	for !candidate.After(now) {
		candidate = candidate.Add(time.Duration(interval) * time.Hour)
	}
	return candidate, nil
}

// parseHHMM validates and parses an "HH:MM" string.
func parseHHMM(hhmm string, h, m *int) (bool, error) {
	parts := strings.SplitN(hhmm, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	var ph, pm int
	if _, err := parseIntRange(parts[0], 0, 23, &ph); err != nil {
		return false, err
	}
	if _, err := parseIntRange(parts[1], 0, 59, &pm); err != nil {
		return false, err
	}
	*h, *m = ph, pm
	return true, nil
}

func parseIntRange(s string, min, max int, out *int) (bool, error) {
	v := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, nil
		}
		v = v*10 + int(c-'0')
	}
	if v < min || v > max {
		return false, nil
	}
	*out = v
	return true, nil
}

// triggerWatchAnalysis scans logsDir and starts the appropriate analysis
// run for this watch tick. Two-tier cadence:
//
//   - The first watch tick of each UTC calendar day runs the full pipeline
//     (Beaconing, HTTP analysis, all detectors). Statistical detectors
//     need the long temporal window to spot patterns — beaconing math
//     operates on hours/days of (src, dst, port) intervals, not the last
//     hour in isolation.
//   - Subsequent same-day ticks run an incremental TI/IOC pass over only
//     the log files modified since the last run. New bad-IP contacts get
//     surfaced within one tick interval, but the expensive statistical
//     phases skip until tomorrow's first tick refreshes them.
//
// On a fresh deployment (no prior full run on record), the first tick
// always does a full run to establish a baseline before incremental
// ticks have anything to be incremental against.
//
// Watch runs are unattended; the full-run path honors the dataset
// fingerprint skip so we don't burn CPU re-producing identical findings
// when nothing on disk has changed.
func (s *Server) triggerWatchAnalysis() {
	if s.store.IsAnalyzing() {
		return
	}
	files := s.scanLogsDir()
	if len(files) == 0 {
		return
	}

	// WatchAlwaysFull forces every tick to run the full pipeline,
	// bypassing the two-tier date-based decision below. Operator opts in
	// from Settings → Watch Mode when they want statistical detectors
	// refreshing every tick (active hunt) instead of once a day.
	if s.store.GetConfig().WatchAlwaysFull {
		s.refreshFeedsBeforeFullPass()
		s.launchAnalysisWithOptions(files, false)
		return
	}

	// Two-tier full/incremental boundary respects the operator's
	// configured timezone — same Location the off-hours detector and
	// the findings filter use. Pre-fix the boundary was hard-coded to
	// UTC, so an operator in (say) America/Los_Angeles would see the
	// "first full run of the day" fire at 5 PM local in winter / 4 PM
	// in summer instead of midnight, and the day-boundary anchored
	// statistics (beacon mean interval, exfil aggregation) would split
	// across two operator-local days even when no actual day change
	// had happened from their perspective. Audit 2026-05-10 NEW-12.
	loc := s.operatorLocation()
	now := time.Now().In(loc)
	lastFull := s.store.GetLastFullAnalysisTime().In(loc)
	needFull := lastFull.IsZero() ||
		lastFull.Year() != now.Year() ||
		lastFull.YearDay() != now.YearDay()

	if needFull {
		// beacon_history retention is now swept by the dedicated
		// startBeaconHistoryPruneLoop goroutine (NEW-86 v0.16.3) —
		// piggy-backing on the watch's needFull gate silently
		// broke retention for deployments running with the watch
		// disabled. The prune loop runs unconditional on watch
		// config, so the watch path no longer needs to invoke it.
		s.refreshFeedsBeforeFullPass()
		s.launchAnalysisWithOptions(files, false)
		return
	}

	// Same UTC day: incremental tick. Filter the file set to anything
	// modified since the last run, with a 5-minute overlap buffer so a
	// log rotated right at the boundary gets picked up next time instead
	// of silently missed.
	lastRun := s.store.GetLastAnalysisTime()
	if lastRun.IsZero() {
		// Defensive: shouldn't happen if lastFull is set, but if it does
		// fall through to a full run rather than silently skipping.
		s.launchAnalysisWithOptions(files, false)
		return
	}
	cutoff := lastRun.Add(-5 * time.Minute)
	newFiles := make([]string, 0, len(files))
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil || info.IsDir() {
			continue
		}
		if info.ModTime().After(cutoff) {
			newFiles = append(newFiles, f)
		}
	}
	if len(newFiles) == 0 {
		// No new log evidence since the last run — skip without burning
		// CPU. Watch will try again at the next tick; tomorrow's first
		// tick will refresh statistical detectors regardless.
		s.broker.Publish(SSEEvent{Type: "status", Data: `{"msg":"Incremental tick: no new logs since last run."}`})
		return
	}
	s.launchIncrementalAnalysis(newFiles)
}

// refreshFeedsBeforeFullPass runs a synchronous, all-feeds refresh
// before the watch scheduler launches a full-pass analysis. Capped at
// 10 minutes — most ticks are cheap incrementals (MISP's restSearch
// `timestamp` filter), but the periodic full sync at the per-feed
// cadence still has to walk the whole feed and that's where the cap
// matters. Type-shard parallelism keeps even the periodic full sync
// well under the cap on realistic feeds; beyond 10 minutes the
// upstream is more likely stuck than slow. The auto-cadence feed
// worker is intentionally disabled, so this is the path that keeps
// MISP/OpenCTI indicators in sync with the watch schedule.
// Incremental analysis ticks deliberately skip this — they only use
// the built-in Feodo Tracker / URLhaus indicators (see
// launchIncrementalAnalysis).
func (s *Server) refreshFeedsBeforeFullPass() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	s.refreshAllFeedsForWatch(ctx)
}

// launchIncrementalAnalysis runs Phase 0 (feed prefetch) + Phase 3 (TI
// matching with per-source fan-out) over the supplied file subset — no
// statistical detectors, no host-risk aggregation. Used by the watch
// loop on same-day ticks where the expensive analysis already ran
// earlier in the day. The TI phase is stateless per record (each
// connection is independently meaningful), so a small file subset is
// safe — unlike Beaconing or HTTP analysis which need the long window.
func (s *Server) launchIncrementalAnalysis(files []string) {
	cfg := s.store.GetConfig()
	s.store.SetAnalyzing(true)
	progressCh := make(chan analysis.ProgressEvent, 32)
	statusCh := make(chan string, 32)

	go func() {
		for evt := range progressCh {
			data, _ := json.Marshal(evt)
			s.broker.Publish(SSEEvent{Type: "progress", Data: string(data)})
		}
	}()
	go func() {
		for msg := range statusCh {
			data, _ := json.Marshal(map[string]string{"msg": msg})
			s.broker.Publish(SSEEvent{Type: "status", Data: string(data)})
		}
	}()

	announce, _ := json.Marshal(map[string]string{
		"msg": fmt.Sprintf("Incremental TI pass over %d new file(s) since last run.", len(files)),
	})
	s.broker.Publish(SSEEvent{Type: "status", Data: string(announce)})

	logsDir := s.logsDir
	go func() {
		az := analysis.New(cfg, logsDir, progressCh, statusCh)
		// Match against MISP/OpenCTI indicators on incremental ticks
		// using whatever's currently in the DB — no fetch. The watch
		// full-pass tick is the only path that refreshes upstream feeds
		// (refreshFeedsBeforeFullPass), so an incremental pass between
		// full passes sees a stable indicator set. This closes the
		// "wait until tomorrow's full pass" gap on fresh IOC matches at
		// the cost of a few seconds per tick rebuilding the indicator
		// buckets from SQLite. Built-in Feodo/URLhaus also load via
		// prefetchFeeds inside AnalyzeTIOnly.
		az.SetFeedProvider(s.store)

		// Pin defaultSensor BEFORE AnalyzeTIOnly for the same reason
		// the full pass does. AnalyzeTIOnly's HTTP-derived TI matches
		// (URLhaus and MISP/OpenCTI feed domains hit in url.log) emit
		// findings without a SourceFile because http_analysis.go
		// doesn't track which conn.log path the URI came from — so
		// Analyzer.add's sensorOf() resolution returns empty for them.
		// In a single-sensor deployment that left those TI Hits with
		// Sensor="" in the Sensors column, which read as a bug even
		// though the data was correct. defaultSensor closes the gap.
		if logsDir != "" {
			sensorSet := make(map[string]struct{})
			for _, fp := range files {
				if s := sensorFromPath(logsDir, fp); s != "" {
					sensorSet[s] = struct{}{}
				}
			}
			if len(sensorSet) == 1 {
				for s := range sensorSet {
					az.SetDefaultSensor(s)
				}
			}
		}

		s.analyzerMu.Lock()
		s.activeAnalyzer = az
		s.analyzerMu.Unlock()

		defer func() {
			s.analyzerMu.Lock()
			s.activeAnalyzer = nil
			s.analyzerMu.Unlock()
			close(progressCh)
			close(statusCh)
		}()

		startedAt := time.Now().UTC()
		findings := az.AnalyzeTIOnly(files)

		// SetFindingsIncremental (rather than SetFindings) so the
		// rollup-purge branch in setFindingsImpl is skipped — this
		// pass didn't run correlateFindings or aggregateRisk, so
		// every existing Correlated Activity and Host Risk Score
		// row's fingerprint is absent from newFPSet by definition.
		// Calling SetFindings here used to silently drop them all
		// every 6 hours, leaving a rollup hole between full passes.
		newNotifs := s.store.SetFindingsIncremental(findings)
		s.crossAnnotateNewTIHits(findings)
		for _, n := range newNotifs {
			nData, _ := json.Marshal(n)
			s.broker.Publish(SSEEvent{Type: "notification", Data: string(nData)})
		}

		wasCancelled := az.Ctx().Err() != nil
		if !wasCancelled {
			// Incremental updates the "any run" timestamp only — does NOT
			// touch the full-run timestamp, so tomorrow's first tick still
			// triggers a full pass. Uses startedAt for the same reason as
			// launchAnalysisWithOptions: files synced during this pass
			// must be caught by the next incremental.
			s.store.SetLastAnalysisTime(startedAt)
		}

		newCount := 0
		for _, f := range findings {
			if f.IsNew {
				newCount++
			}
		}
		data, _ := json.Marshal(map[string]any{
			"count":       len(findings),
			"new_count":   newCount,
			"cancelled":   wasCancelled,
			"incremental": true,
		})
		s.broker.Publish(SSEEvent{Type: "done", Data: string(data)})
	}()
}

// preflightMemoryWarning estimates peak analysis memory from total log size
// and compares it against the Go soft-memory budget. Returns a warning
// message when the run is projected to approach or exceed the budget, or ""
// when the run is expected to fit comfortably. Non-blocking — callers should
// emit this as a status event but still proceed.
func (s *Server) preflightMemoryWarning(files []string) string {
	var totalBytes int64
	for _, p := range files {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			totalBytes += info.Size()
		}
	}
	if totalBytes == 0 {
		return ""
	}
	// Empirical ratio on post-refactor Zeek workloads: peak working set is
	// roughly 1.2× total log byte-size (conservatively rounded up from the
	// 3.2 GB dataset → 3.2 GB peak observation).
	estPeak := int64(float64(totalBytes) * 1.2)

	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		return ""
	}
	if float64(estPeak) < 0.8*float64(limit) {
		return ""
	}

	verb := "approaching"
	if estPeak > limit {
		verb = "likely exceeding"
	}
	return fmt.Sprintf(
		"Preflight: %s of logs, estimated peak memory %s — %s the %s container budget. Analysis will proceed; watch `docker stats` or set ARCHER_MEMORY higher if it OOMs.",
		humanBytes(totalBytes), humanBytes(estPeak), verb, humanBytes(limit),
	)
}

// humanBytes formats a byte count with IEC units (KiB/MiB/GiB) at one decimal
// place for values below 10 in their chosen unit.
func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	v := float64(n) / 1024.0
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v < 10 {
		return fmt.Sprintf("%.1f %s", v, units[i])
	}
	return fmt.Sprintf("%.0f %s", v, units[i])
}

// datasetFingerprint hashes the (relpath, size, mtime) tuple of every file
// that will be analyzed. Two runs produce the same fingerprint iff the set of
// files and each file's size + mtime are identical — the cheapest accurate
// proxy for "nothing has changed" without re-reading file contents.
func (s *Server) datasetFingerprint(files []string) string {
	type entry struct {
		rel  string
		size int64
		mod  int64
	}
	entries := make([]entry, 0, len(files))
	for _, p := range files {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		rel := p
		if s.logsDir != "" {
			if r, err := filepath.Rel(s.logsDir, p); err == nil {
				rel = r
			}
		}
		entries = append(entries, entry{rel, info.Size(), info.ModTime().UnixNano()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", e.rel, e.size, e.mod)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// scanLogsDir walks the configured logs directory and returns all recognised log files.
// The /logs/_archived/ subtree (purged-sensor data rotated aside by the
// admin Purge action) is intentionally excluded — analyzing those logs
// every full pass would re-emit findings for sensors the operator has
// deliberately retired.
func (s *Server) scanLogsDir() []string {
	var files []string
	if s.logsDir == "" {
		return files
	}
	archiveSubtree := filepath.Join(s.logsDir, "_archived")
	filepath.Walk(s.logsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path == archiveSubtree {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if strings.HasSuffix(name, ".log") ||
			strings.HasSuffix(name, ".log.gz") ||
			strings.HasSuffix(name, ".gz") ||
			strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".ndjson") {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// launchAnalysis starts the full analysis pipeline in a background goroutine.
// It is shared between the HTTP handler and the watch scheduler. Manual
// invocations should use this (which always runs); watch uses the "options"
// form below with force=false to honor the dataset-fingerprint skip.
//
// Returns true if the analysis was claimed and launched, false if another
// analysis is already in flight. HTTP handlers can use the return to emit
// a 409 Conflict; the watch scheduler doesn't need to react since its
// outer guard already checks IsAnalyzing. Audit 2026-05-10 NEW-31.
func (s *Server) launchAnalysis(files []string) bool {
	return s.launchAnalysisWithOptions(files, true)
}

func (s *Server) launchAnalysisWithOptions(files []string, force bool) bool {
	// Atomic check-and-set claim on the analysis slot. Pre-NEW-31
	// callers separately checked IsAnalyzing then later called
	// SetAnalyzing(true), leaving a TOCTOU window where a near-
	// simultaneous trigger (watch tick fires while user clicks
	// "Analyze sensor logs", or two watch ticks fire in quick
	// succession when a run takes longer than the watch interval)
	// could pass both guards and spawn parallel analyzer goroutines.
	// Consequences were nasty: cancel-button semantics broke (only
	// the second goroutine stopped), SSE progress events
	// interleaved, memory doubled. TryStartAnalysis collapses the
	// check+set into one mutex-protected operation. Audit 2026-05-10
	// NEW-31.
	if !s.store.TryStartAnalysis() {
		s.broker.Publish(SSEEvent{Type: "status", Data: `{"msg":"Analysis already in progress — second trigger ignored."}`})
		return false
	}

	if !force {
		fp := s.datasetFingerprint(files)
		if fp != "" && fp == s.store.GetLastAnalysisFingerprint() {
			s.store.SetAnalyzing(false)
			s.broker.Publish(SSEEvent{Type: "status", Data: `{"msg":"No changes since last analysis — skipping."}`})
			return true
		}
	}

	if warn := s.preflightMemoryWarning(files); warn != "" {
		log.Printf("preflight: %s", warn)
		msg, _ := json.Marshal(map[string]string{"msg": warn})
		s.broker.Publish(SSEEvent{Type: "status", Data: string(msg)})
	}

	cfg := s.store.GetConfig()
	progressCh := make(chan analysis.ProgressEvent, 32)
	statusCh := make(chan string, 32)

	go func() {
		for evt := range progressCh {
			data, _ := json.Marshal(evt)
			s.broker.Publish(SSEEvent{Type: "progress", Data: string(data)})
		}
	}()
	go func() {
		for msg := range statusCh {
			data, _ := json.Marshal(map[string]string{"msg": msg})
			s.broker.Publish(SSEEvent{Type: "status", Data: string(data)})
		}
	}()

	logsDir := s.logsDir
	go func() {
		az := analysis.New(cfg, logsDir, progressCh, statusCh)
		az.SetFeedProvider(s.store)
		az.SetFindingsProvider(s.store)
		az.SetAllowlistMatcher(func(c string) bool {
			return s.store.AllowlistMatcher().Matches(c)
		})

		// Pre-compute the deployment's sensor set from the file list
		// and pin the analyzer's default Sensor BEFORE Analyze runs.
		// Single-sensor deployments get every emitted finding tagged
		// with that one sensor at a.add() time, including aggregates
		// whose empty SourceFile would otherwise leave Sensor blank.
		// This matters specifically for correlateFindings: it
		// partitions (src, dst) pairs on Sensor, and historical
		// contributors arrive from store with their persisted Sensor
		// already populated. Pre-fix the watch loop assigned Sensor
		// AFTER Analyze returned, so fresh contributors went into
		// correlate with Sensor="" and historical with "deathstar" —
		// two pairKeys, two duplicate Correlated Activity rows.
		// Multi-sensor deployments leave defaultSensor unset; the
		// per-finding a.sensorOf(SourceFile) path inside add() still
		// attributes per-record findings correctly, and aggregates
		// with no clear sensor ship with Sensor="" the same way the
		// post-loop's multi-branch behaved.
		if logsDir != "" {
			sensorSet := make(map[string]struct{})
			for _, fp := range files {
				if s := sensorFromPath(logsDir, fp); s != "" {
					sensorSet[s] = struct{}{}
				}
			}
			if len(sensorSet) == 1 {
				for s := range sensorSet {
					az.SetDefaultSensor(s)
				}
			}
		}

		s.analyzerMu.Lock()
		s.activeAnalyzer = az
		s.analyzerMu.Unlock()

		defer func() {
			s.analyzerMu.Lock()
			s.activeAnalyzer = nil
			s.analyzerMu.Unlock()
			close(progressCh)
			close(statusCh)
		}()

		// Capture the start time before Analyze runs. SetLastAnalysisTime
		// uses startedAt (not the post-analysis wall clock) so the next
		// incremental tick's mtime cutoff covers files written during the
		// analysis window — a long run on a large corpus can take 30+
		// minutes, and logs rsynced during that window would otherwise
		// have mtimes before the post-analysis timestamp and be silently
		// excluded from every subsequent incremental until the next
		// UTC-day full pass.
		startedAt := time.Now().UTC()
		findings := az.Analyze(files)

		newNotifs := s.store.SetFindings(findings)
		s.crossAnnotateNewTIHits(findings)
		for _, n := range newNotifs {
			nData, _ := json.Marshal(n)
			s.broker.Publish(SSEEvent{Type: "notification", Data: string(nData)})
		}

		wasCancelled := az.Ctx().Err() != nil
		if !wasCancelled {
			s.store.SetLastAnalysisFingerprint(s.datasetFingerprint(files))
			// SetLastFullAnalysisTime uses the completion time so the
			// full-vs-incremental day gate (UTC YearDay comparison) reflects
			// when this run actually finished. SetLastAnalysisTime uses
			// startedAt so the incremental mtime cutoff reaches back to
			// when this pass began reading files, covering logs written
			// during the analysis window.
			now := time.Now().UTC()
			s.store.SetLastFullAnalysisTime(now)
			s.store.SetLastAnalysisTime(startedAt)
			// The post-analysis archive only fires for the automated daily
			// watch tick (force=false). Manual analyses — including the
			// "Discard findings & re-analyze" reset — must not silently move
			// log files out from under the user. Admins who want to archive
			// on demand have the "Run Archive Now" button.
			if !force {
				if arc := s.store.GetArchive(); arc.Enabled {
					res := s.runArchive(arc.AfterDays, arc.PruneFindingsOnArchive, false, "scheduled")
					if res.Err != "" {
						log.Printf("archive: %s", res.Err)
					}
				}
			}
		}

		newCount := 0
		for _, f := range findings {
			if f.IsNew {
				newCount++
			}
		}
		data, _ := json.Marshal(map[string]any{
			"count":     len(findings),
			"new_count": newCount,
			"cancelled": wasCancelled,
		})
		s.broker.Publish(SSEEvent{Type: "done", Data: string(data)})
	}()
	return true
}
