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

// startWatch starts the daily watch loop if watch is enabled in the config.
// Safe to call at startup and after any config change — cancels any existing loop first.
func (s *Server) startWatch() {
	watchTime, enabled := s.store.GetWatch()
	if !enabled || watchTime == "" {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	s.watchMu.Lock()
	if s.watchCancel != nil {
		s.watchCancel()
	}
	s.watchCancel = cancel
	s.watchMu.Unlock()

	go s.runWatchLoop(ctx, watchTime)
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

// runWatchLoop sleeps until the next UTC occurrence of hhmm, triggers analysis, then repeats.
func (s *Server) runWatchLoop(ctx context.Context, hhmm string) {
	for {
		next, err := nextUTCOccurrence(hhmm)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
			// Re-check config in case watch was disabled while we were sleeping
			currentTime, enabled := s.store.GetWatch()
			if !enabled || currentTime != hhmm {
				return
			}
			s.triggerWatchAnalysis()
		}
	}
}

// nextUTCOccurrence returns the next wall-clock time (UTC) when HH:MM will occur.
// If that time has already passed today, it returns tomorrow's occurrence.
func nextUTCOccurrence(hhmm string) (time.Time, error) {
	var h, m int
	if _, err := parseHHMM(hhmm, &h, &m); err != nil {
		return time.Time{}, err
	}
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next, nil
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

// triggerWatchAnalysis scans logsDir and starts a full analysis run. Watch
// runs are unattended, so they honor the dataset-fingerprint skip: if nothing
// on disk has changed since the last successful run, this returns without
// burning CPU to produce identical findings.
func (s *Server) triggerWatchAnalysis() {
	if s.store.IsAnalyzing() {
		return
	}
	files := s.scanLogsDir()
	if len(files) == 0 {
		return
	}
	s.store.SetUploadedFiles(files)
	s.launchAnalysisWithOptions(files, false)
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
func (s *Server) scanLogsDir() []string {
	var files []string
	if s.logsDir == "" {
		return files
	}
	filepath.Walk(s.logsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
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
func (s *Server) launchAnalysis(files []string) {
	s.launchAnalysisWithOptions(files, true)
}

func (s *Server) launchAnalysisWithOptions(files []string, force bool) {
	if !force {
		fp := s.datasetFingerprint(files)
		if fp != "" && fp == s.store.GetLastAnalysisFingerprint() {
			s.broker.Publish(SSEEvent{Type: "status", Data: `{"msg":"No changes since last analysis — skipping."}`})
			return
		}
	}

	if warn := s.preflightMemoryWarning(files); warn != "" {
		log.Printf("preflight: %s", warn)
		msg, _ := json.Marshal(map[string]string{"msg": warn})
		s.broker.Publish(SSEEvent{Type: "status", Data: string(msg)})
	}

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

	logsDir := s.logsDir
	go func() {
		az := analysis.New(cfg, progressCh, statusCh)

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

		findings := az.Analyze(files)

		if logsDir != "" {
			datasetSet := make(map[string]struct{})
			for _, fp := range files {
				if ds := datasetFromPath(logsDir, fp); ds != "" {
					datasetSet[ds] = struct{}{}
				}
			}
			if len(datasetSet) == 1 {
				var singleDS string
				for ds := range datasetSet {
					singleDS = ds
				}
				for i := range findings {
					findings[i].Dataset = singleDS
				}
			} else {
				for i := range findings {
					findings[i].Dataset = datasetFromPath(logsDir, findings[i].SourceFile)
				}
			}
		}

		newNotifs := s.store.SetFindings(findings)
		for _, n := range newNotifs {
			nData, _ := json.Marshal(n)
			s.broker.Publish(SSEEvent{Type: "notification", Data: string(nData)})
		}

		wasCancelled := az.Ctx().Err() != nil
		if !wasCancelled {
			s.store.SetLastAnalysisFingerprint(s.datasetFingerprint(files))
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
}
