package server

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	model "github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// scoreExplanationsMap is a package-level copy for template/JS use.
var scoreExplanationsMap = model.ScoreExplanations

// Server holds all server dependencies.
type Server struct {
	store          *store.Store
	users          *store.UserStore
	broker         *Broker
	webDir         string
	logsDir        string
	mux            *http.ServeMux
	analyzerMu     sync.Mutex
	activeAnalyzer *analysis.Analyzer
	watchMu        sync.Mutex
	watchCancel    context.CancelFunc
	tlsFingerprint string
}

// New creates and wires all routes, then starts the watch loop if configured.
func New(st *store.Store, us *store.UserStore, broker *Broker, webDir, logsDir string) *Server {
	s := &Server{store: st, users: us, broker: broker, webDir: webDir, logsDir: logsDir, mux: http.NewServeMux()}
	s.routes()
	s.startWatch() // no-op if watch is disabled or unconfigured
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// SetTLSFingerprint stores the public-key SHA256 of Archer's TLS cert so
// the Quiver enrollment one-liner can pin against it via curl --pinnedpubkey.
func (s *Server) SetTLSFingerprint(fp string) { s.tlsFingerprint = fp }

// TLSFingerprint returns the value previously set by SetTLSFingerprint.
// Empty when TLS bootstrap was skipped (e.g. plain-HTTP-only dev runs).
func (s *Server) TLSFingerprint() string { return s.tlsFingerprint }

// SensorFacingHost returns the hostname/IP an admin should embed into
// sensor enrollment commands. The admin-supplied override in settings
// wins; otherwise we fall back to the Host header on the request that
// generated the install one-liner — which is what the admin's browser
// itself is using to reach Archer, almost always the right answer.
func (s *Server) SensorFacingHost(r *http.Request) string {
	if h := s.store.GetSensorFacingHost(); h != "" {
		return h
	}
	if r != nil && r.Host != "" {
		return r.Host
	}
	return "archer:8443"
}

func (s *Server) routes() {
	// Static files — no auth required, no-store to ensure JS/CSS updates are always fresh
	staticDir := filepath.Join(s.webDir, "static")
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir)))
	s.mux.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		staticHandler.ServeHTTP(w, r)
	}))

	// Auth — no session required
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/register", s.handleRegister)
	s.mux.HandleFunc("/logout", s.handleLogout)

	// Role-aware middleware helpers
	//   any(h)      — authenticated, any role
	//   write(h)    — authenticated, analyst or admin
	//   admin(h)    — authenticated, admin only
	any   := func(h http.HandlerFunc) http.Handler { return s.requireAuth(http.HandlerFunc(h)) }
	write := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(requireRole(model.RoleAnalyst, model.RoleAdmin)(http.HandlerFunc(h)))
	}
	admin := func(h http.HandlerFunc) http.Handler {
		return s.requireAuth(requireRole(model.RoleAdmin)(http.HandlerFunc(h)))
	}

	// UI (any authenticated user)
	s.mux.Handle("/", any(s.handleIndex))

	// SSE (any authenticated user)
	s.mux.Handle("/events", any(s.handleSSE))

	// File management — scan/clear require analyst+; plain file list is read-only
	s.mux.Handle("/api/logs/scan", any(s.handleLogsScan))   // GET=any, POST enforced inside handler
	s.mux.Handle("/api/files", any(s.handleFiles))
	s.mux.Handle("/api/files/clear", write(s.handleClearFiles))

	// Analysis — analyst+
	s.mux.Handle("/api/analyze", write(s.handleAnalyze))
	s.mux.Handle("/api/analyze/status", any(s.handleAnalyzeStatus))
	s.mux.Handle("/api/analyze/cancel", write(s.handleAnalyzeCancel))
	s.mux.Handle("/api/analyze/pause",  write(s.handleAnalyzePause))
	s.mux.Handle("/api/analyze/resume", write(s.handleAnalyzeResume))
	s.mux.Handle("/api/analyze/reset",  any(s.handleAnalyzeReset)) // admin enforced inside handler

	// Findings — read=any, write=analyst+
	s.mux.Handle("/api/findings", any(s.handleFindings))
	s.mux.Handle("/api/findings/", any(s.handleFindingRouter)) // write checks done per-method inside

	// Config — read=any, write=admin only
	s.mux.Handle("/api/config", any(s.handleConfig)) // PUT enforced inside handler

	// Lists — read=any, write=analyst+
	s.mux.Handle("/api/allowlist", any(s.handleAllowlist))   // PUT enforced inside handler
	s.mux.Handle("/api/ioc", any(s.handleIOC))               // PUT enforced inside handler
	s.mux.Handle("/api/suppressions", any(s.handleSuppressions))    // POST enforced inside handler
	s.mux.Handle("/api/suppressions/", any(s.handleDeleteSuppression))
	s.mux.Handle("/api/notifications", any(s.handleNotifications))
	s.mux.Handle("/api/watch", any(s.handleWatch))           // GET=any; POST enforced as admin inside handler
	s.mux.Handle("/api/archive", any(s.handleArchive))       // GET=any; POST enforced as admin inside handler
	s.mux.Handle("/api/archive/run", any(s.handleArchiveRun))

	// User / auth API
	s.mux.Handle("/api/me", any(s.handleMe))
	s.mux.Handle("/api/users", any(s.handleUsersCollection))
	s.mux.Handle("/api/users/", admin(s.handleUserItem))

	// Threat intel — read=any
	s.mux.Handle("/api/ti/services", any(s.handleTIServices))

	// Export / Import — analyst+
	s.mux.Handle("/api/export/json", any(s.handleExportJSON))
	s.mux.Handle("/api/export/csv", any(s.handleExportCSV))
	s.mux.Handle("/api/import", write(s.handleImportJSON))
}

// handleFindingRouter dispatches /api/findings/{id} and /api/findings/{id}/escalate.
func (s *Server) handleFindingRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if len(path) > len("/api/findings/") {
		rest := path[len("/api/findings/"):]
		if len(rest) > 9 && rest[len(rest)-9:] == "/escalate" {
			s.handleEscalate(w, r)
			return
		}
		if len(rest) > 6 && rest[len(rest)-6:] == "/notes" {
			s.handleAddNote(w, r)
			return
		}
	}
	s.handleFinding(w, r)
}
