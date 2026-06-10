package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		watchTime, enabled := s.store.GetWatch()
		tz := s.store.GetTimezone()
		intervalHours := s.store.GetWatchInterval()
		resp := map[string]any{
			"time":           watchTime,
			"enabled":        enabled,
			"timezone":       tz,
			"interval_hours": intervalHours,
		}
		if enabled && watchTime != "" {
			loc := loadLocationOrUTC(tz)
			// Surface the timezone abbreviation (EDT, PST, UTC, …) once,
			// instead of repeating the long IANA name three times across
			// the schedule preview, the next-run line, and the next-full
			// line. Frontend renders the abbrev once on the cadence head
			// and leaves the time strings unadorned.
			abbrev := time.Now().In(loc).Format("MST")
			if abbrev == "" {
				abbrev = "UTC"
			}
			resp["timezone_abbr"] = abbrev

			if next, err := nextOccurrenceInterval(watchTime, intervalHours, loc); err == nil {
				resp["next_run"] = formatRelativeTime(next, loc)

				// Two-tier cadence: derive next_run_kind and next_full_run so
				// the sidebar can tell the analyst whether the upcoming tick
				// is the daily full-pipeline pass or an incremental TI-only
				// pass — matters for "is my beacon detection going to refresh
				// at the next tick?" mental modelling. Mirrors the decision
				// logic in triggerWatchAnalysis (see watch.go).
				//
				// Operator can opt out of the two-tier behavior via the
				// "Always run full scan" toggle in Settings → Watch Mode;
				// when on, every tick is full and the sidebar drops the
				// "Next Full Scan" follow-up line.
				alwaysFull := s.store.GetConfig().WatchAlwaysFull
				lastFull := s.store.GetLastFullAnalysisTime()
				isFullTick := func(t time.Time) bool {
					if alwaysFull || lastFull.IsZero() {
						return true
					}
					utc := t.UTC()
					lf := lastFull.UTC()
					return utc.Year() != lf.Year() || utc.YearDay() != lf.YearDay()
				}
				nextIsFull := isFullTick(next)
				if nextIsFull {
					resp["next_run_kind"] = "full"
					resp["next_full_run"] = resp["next_run"]
				} else {
					resp["next_run_kind"] = "incremental"
					// Walk forward in the cadence until we land on a tick
					// whose UTC date differs from the last full run's date.
					// Bounded search: at hourly cadence the next-day boundary
					// is at most 25 hops away; at 12h cadence at most 3.
					step := time.Duration(intervalHours) * time.Hour
					if intervalHours == 0 || intervalHours == 24 {
						step = 24 * time.Hour
					}
					candidate := next
					for i := 0; i < 30; i++ {
						candidate = candidate.Add(step)
						if isFullTick(candidate) {
							resp["next_full_run"] = formatRelativeTime(candidate, loc)
							break
						}
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	case http.MethodPost, http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Time          string `json:"time"`
			Enabled       bool   `json:"enabled"`
			Timezone      string `json:"timezone"`
			IntervalHours int    `json:"interval_hours"`
		}
		if err := decodeJSONBody(w, r, &req, 4<<10); err != nil {
			return
		}
		// Validate HH:MM format when enabling
		if req.Enabled {
			var h, m int
			if !parseHHMM(req.Time, &h, &m) {
				jsonError(w, "time must be HH:MM in 24-hour format", http.StatusBadRequest)
				return
			}
		}
		// Validate IANA timezone name. Empty is allowed and means UTC.
		if req.Timezone != "" {
			if _, err := time.LoadLocation(req.Timezone); err != nil {
				jsonError(w, `invalid timezone — use an IANA name like "America/New_York"`, http.StatusBadRequest)
				return
			}
		}
		// Validate interval. 0 (or 24) means daily; otherwise must be one of
		// the supported sub-daily cadences. Anything else gets clamped to 0
		// rather than rejected — the UI is the source of truth here.
		switch req.IntervalHours {
		case 0, 1, 4, 6, 12, 24:
			// ok
		default:
			req.IntervalHours = 0
		}
		beforeTime, beforeEnabled := s.store.GetWatch()
		beforeTZ := s.store.GetTimezone()
		beforeInterval := s.store.GetWatchInterval()
		s.store.SetWatch(req.Time, req.Timezone, req.Enabled, req.IntervalHours)
		if req.Enabled {
			s.startWatch()
		} else {
			s.stopWatch()
		}
		s.recordAudit(r, "watch_change", auditEvent{
			TargetType: "watch",
			BeforeValue: map[string]any{
				"enabled": beforeEnabled, "time": beforeTime,
				"timezone": beforeTZ, "interval_hours": beforeInterval,
			},
			AfterValue: map[string]any{
				"enabled": req.Enabled, "time": req.Time,
				"timezone": req.Timezone, "interval_hours": req.IntervalHours,
			},
		})
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetArchive())

	case http.MethodPost, http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req store.ArchiveSettings
		if err := decodeJSONBody(w, r, &req, 4<<10); err != nil {
			return
		}
		if req.Enabled && req.AfterDays <= 0 {
			jsonError(w, "after_days must be positive when enabling", http.StatusBadRequest)
			return
		}
		s.store.SetArchive(req)
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleArchiveRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	me := userFromCtx(r)
	if me.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	settings := s.store.GetArchive()
	if settings.AfterDays <= 0 {
		jsonError(w, "configure archive_after_days before running", http.StatusBadRequest)
		return
	}

	// Empty body = real run; {"dry_run": true} = preview. The body is
	// optional so existing clients that just POST without a body keep
	// working.
	var req struct {
		DryRun bool `json:"dry_run"`
	}
	if r.ContentLength > 0 {
		// Tiny body; decode errors are tolerated (req stays at zero
		// values, which is the "real run, not dry" default — matches
		// the pre-fix shape so existing clients posting empty / bad
		// bodies keep working). Body is still bounded so a hostile
		// caller can't push a multi-MB payload at this endpoint just
		// to have us discard it. We don't use decodeJSONBody here
		// because it writes a response on error, which would conflict
		// with the 202/200 we want to write below; the cap+silent-
		// ignore shape needs MaxBytesReader directly.
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req)
	}

	if !req.DryRun {
		if !s.store.TryStartAnalysis() {
			jsonError(w, "analysis in progress", http.StatusConflict)
			return
		}
		defer s.store.SetAnalyzing(false)
	}
	triggeredBy := me.DisplayName()
	if req.DryRun {
		triggeredBy = "" // preview never gets recorded, but be explicit
	}
	res := s.runArchive(settings.AfterDays, settings.PruneFindingsOnArchive, req.DryRun, triggeredBy)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// handleArchiveScan walks /data/archive and runs an IOC + TI-feed
// scan over its contents. Findings merge with the regular finding set
// — the SetFindings fingerprint logic preserves analyst state on any
// hits that were already known. Admin-only, mutually exclusive with a
// regular analysis run.
func (s *Server) handleArchiveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	files := s.scanArchiveDir()
	if len(files) == 0 {
		jsonError(w, "no archived logs to scan", http.StatusBadRequest)
		return
	}
	// launchTIOnly does the atomic TryStartAnalysis claim — see
	// NEW-31 in store.go. We don't separately IsAnalyzing here
	// because the claim is the source of truth; a separate check
	// would just re-introduce the TOCTOU window. On contention
	// launchTIOnly emits an SSE status message and returns; the
	// HTTP response below still says "started" but the SSE is the
	// authoritative signal.
	if !s.launchTIOnly(files) {
		jsonError(w, "another analysis is already in progress", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "started", "files": len(files)})
}

// launchTIOnly is the archive-scan analogue of launchAnalysisWithOptions.
// It runs only the IOC/TI phases of the analyzer, preserves all live
// findings via SetFindings's fingerprint merge, and reuses the regular
// progress/status/done/notification SSE events so the existing UI shows
// the run without any frontend changes.
//
// Returns false if another analysis is already in flight — the caller
// must handle the contention (typically with a 409 Conflict response).
// Audit 2026-05-10 NEW-31.
func (s *Server) launchTIOnly(files []string) bool {
	if !s.store.TryStartAnalysis() {
		return false
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

	s.analysisWg.Add(1)
	go func() {
		defer s.analysisWg.Done()
		defer s.recoverAnalysis("archive-scan")
		// Archive scan reuses the /logs/<sensor>/<date>/ layout under
		// /data/archive — so passing archiveDir as the analyzer's path
		// root yields the same sensor names that the live tree would.
		az := analysis.New(cfg, archiveDir, progressCh, statusCh)
		az.SetFeedProvider(s.store)

		// Pin defaultSensor before AnalyzeTIOnly so HTTP-derived TI
		// matches (URLhaus + MISP/OpenCTI feed-domain hits in url.log)
		// — which emit findings without a SourceFile — pick up the
		// deployment's lone sensor name instead of landing empty in
		// the Sensors column. Multi-sensor archives leave default
		// unset; per-file sensorOf in Analyzer.add still attributes
		// the SourceFile-bearing TI Hits correctly.
		if archiveDir != "" {
			sensorSet := make(map[string]struct{})
			for _, fp := range files {
				if s := sensorFromPath(archiveDir, fp); s != "" {
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
			s.store.SetAnalyzing(false)
			s.analyzerMu.Lock()
			s.activeAnalyzer = nil
			s.analyzerMu.Unlock()
			close(progressCh)
			close(statusCh)
		}()

		findings := az.AnalyzeTIOnly(files)

		wasCancelled := az.Ctx().Err() != nil
		if !wasCancelled {
			// SetFindingsIncremental (not SetFindings) so the rollup
			// purge inside setFindingsImpl is skipped. The archive scan
			// is a TI-only pass — running it shouldn't drop the live
			// store's Correlated Activity / Host Risk Score rows just
			// because this run didn't regenerate them.
			newNotifs := s.store.SetFindingsIncremental(findings)
			s.crossAnnotateNewTIHits(findings)
			for _, n := range newNotifs {
				nData, _ := json.Marshal(n)
				s.broker.Publish(SSEEvent{Type: "notification", Data: string(nData)})
			}
		}
		data, _ := json.Marshal(map[string]any{
			"count":     len(findings),
			"new_count": s.store.CountNewFindings(),
			"cancelled": wasCancelled,
		})
		s.broker.Publish(SSEEvent{Type: "done", Data: string(data)})
	}()
	return true
}
