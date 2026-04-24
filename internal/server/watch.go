package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

// triggerWatchAnalysis scans logsDir and starts a full analysis run.
func (s *Server) triggerWatchAnalysis() {
	if s.store.IsAnalyzing() {
		return
	}
	files := s.scanLogsDir()
	if len(files) == 0 {
		return
	}
	s.store.SetUploadedFiles(files)
	s.launchAnalysis(files)
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
// It is shared between the HTTP handler and the watch scheduler.
func (s *Server) launchAnalysis(files []string) {
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

		newCount := 0
		wasCancelled := az.Ctx().Err() != nil
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
