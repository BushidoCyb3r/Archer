package server

import (
	"encoding/json"
	"net/http"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

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
	var cleared int
	if !s.launchAnalysisWithOptions(files, true, func() { cleared = s.store.ClearFindings() }) {
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

	hasAnalyzer := az != nil
	slotHeld := s.store.IsAnalyzing()
	running := hasAnalyzer || slotHeld
	paused := hasAnalyzer && az.IsPaused()
	blocked := slotHeld && !hasAnalyzer
	resp := map[string]any{"running": running, "paused": paused, "blocked": blocked}
	// Carry the current progress so a client connecting mid-run (a page reload
	// during analysis) can restore its progress bar immediately, rather than
	// resetting to 0 and waiting for the next coarse phase-boundary SSE event.
	if hasAnalyzer {
		pct, step := az.Progress()
		resp["pct"] = pct
		resp["step"] = step
	}
	// Surface a persistent findings-write failure so it's visible on a page
	// reload, not just in the live SSE status event the watch path emits.
	if pe := s.store.PersistenceError(); pe != "" {
		resp["persist_error"] = pe
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
