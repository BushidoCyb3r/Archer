package server

import (
	"context"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
	model "github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// unauthorizedAttemptRetention bounds how long unpinned unauthorized
// attempt rows stick around. 30 days matches how long an analyst is
// realistically going to investigate a stale row before forgetting; the
// pinned flag opts a row out of the auto-prune.
const unauthorizedAttemptRetention = 30 * 24 * time.Hour

// scoreExplanationsMap is a package-level copy for template/JS use.
var scoreExplanationsMap = model.ScoreExplanations

// Server holds all server dependencies.
type Server struct {
	store            *store.Store
	users            *store.UserStore
	broker           *Broker
	webDir           string
	logsDir          string
	authKeysPath     string
	mux              *http.ServeMux
	analyzerMu       sync.Mutex
	activeAnalyzer   *analysis.Analyzer
	watchMu          sync.Mutex
	watchCancel      context.CancelFunc
	feedWorkerCancel context.CancelFunc
	tlsFingerprint   string
	// Disk-usage cache: walking /logs and /data/archive can take seconds
	// on large deployments, so memoize the result and refresh on a short
	// TTL. The cache is invalidated implicitly by the timestamp check.
	diskCacheMu   sync.Mutex
	diskCacheAt   time.Time
	diskCacheData []byte

	// Per-sensor lastLogMTime cache. handleSensorsList originally walked
	// every sensor's log tree on every GET — O(sensors × files-per-day)
	// stat calls per UI tick. Fine for a homelab with a handful of
	// sensors but quadratic-ish for fleet scale. Audit 2026-05-10 LOW.
	// Invalidated implicitly by the per-entry TTL.
	sensorMtimeMu    sync.Mutex
	sensorMtimeCache map[string]sensorMtimeEntry

	// Rate limiter for unauthenticated endpoints (login, register,
	// quiver checkin). Prevents audit-log flood attacks from a
	// single source IP. v0.14.3 NEW-39.
	rateLimit *rateLimiter
}

type sensorMtimeEntry struct {
	mtime    int64
	cachedAt time.Time
}

// New creates and wires all routes, then starts the watch loop if configured.
func New(st *store.Store, us *store.UserStore, broker *Broker, webDir, logsDir, authKeysPath string) *Server {
	s := &Server{
		store: st, users: us, broker: broker,
		webDir: webDir, logsDir: logsDir, authKeysPath: authKeysPath,
		mux:       http.NewServeMux(),
		rateLimit: newRateLimiter(),
	}
	s.routes()
	s.startWatch() // no-op if watch is disabled or unconfigured
	s.startUnauthorizedPruneLoop()
	s.startSuppressionsPruneLoop()
	s.startBeaconHistoryPruneLoop()
	// Session prune was previously a goroutine wired from NewUserStore
	// (NEW-69 follow-up). Surfaced here so every TTL sweep is started
	// from one place; PruneExpiredSessions is a method value matching
	// the fn signature.
	startPruneLoop("sessions", time.Hour, s.users.PruneExpiredSessions)
	s.startSensorHeartbeatLoop()
	s.startFeedHealthLoop()
	s.startWatchHeartbeatLoop()
	// Idle-bucket eviction so a long-running flood from many source
	// IPs doesn't grow the rate-limit map without bound. v0.14.3
	// NEW-39. The done channel is never closed — eviction runs for
	// the process lifetime, same shape as the other prune loops.
	s.rateLimit.startEvictionLoop(make(chan struct{}))
	// Auto-cadence feed refresh is intentionally off. With large feeds
	// (100k+ MISP indicators) the periodic CPU cost of an unattended
	// fetch was visible in the dashboard. Feeds are now refreshed
	// synchronously at the start of every full-pass watch tick (see
	// triggerWatchAnalysis → refreshFeedsBeforeFullPass) so indicators
	// stay current without a separate background worker. Re-enable
	// here if a deployment wants the old per-feed cadence.
	// s.startFeedWorker()
	return s
}

// startFeedWorker runs the per-feed fetcher loop in a goroutine that
// outlives this call. Currently NOT called — see the comment in New
// above. Kept around so re-enabling is a one-line change.
func (s *Server) startFeedWorker() {
	w := feeds.NewWorker(s.store, s.buildFeedAdapter)
	ctx, cancel := context.WithCancel(context.Background())
	s.feedWorkerCancel = cancel
	go w.Run(ctx)
}

// startPruneLoop runs fn once immediately, then every interval, in a
// goroutine that lives for the process lifetime — process shutdown is
// the only termination, the contract every TTL/heartbeat sweep here
// has always had. The name is logged once at startup so the full set
// of background sweeps is greppable from the logs in one place; that
// discoverability gap (six near-identical hand-rolled loops, one of
// them wired from a different package) is what NEW-95 / TODO §1b
// flagged. Behavior is identical to the loops it replaces: same
// run-at-boot-then-tick shape, same no-graceful-shutdown contract.
func startPruneLoop(name string, interval time.Duration, fn func()) {
	log.Printf("server: prune loop %q started (interval %s)", name, interval)
	go func() {
		fn()
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			fn()
		}
	}()
}

// startUnauthorizedPruneLoop drops unpinned unauthorized_attempts rows
// older than unauthorizedAttemptRetention, hourly. Runs once at startup
// so a long-lived deployment with a stale backlog doesn't have to wait
// the full hour.
func (s *Server) startUnauthorizedPruneLoop() {
	startPruneLoop("unauthorized_attempts", time.Hour, func() {
		s.store.PruneUnauthorizedAttempts(unauthorizedAttemptRetention)
	})
}

// startSuppressionsPruneLoop sweeps expired suppression entries off the
// in-memory map and the suppressions table on a periodic cadence. The
// IsSuppressed read path used to do this lazily on every peek of an
// expired entry, taking a write lock and running per-row DELETEs;
// concurrent readers for the same expired IP both ran the DELETE
// idempotently. Audit 2026-05-10. The sweep moves cleanup off the hot
// read path: IsSuppressed is now a pure RLock read, and one bulk
// `DELETE … WHERE expiry <= now()` happens every five minutes.
// Five minutes is shorter than any realistic suppression duration
// (hours/days) so an expired entry never lingers in the admin UI for
// long. Boot time also runs `DELETE … WHERE expiry <= ?` in InitDB,
// so a long-stopped instance restarting with a stale backlog catches
// up immediately.
func (s *Server) startSuppressionsPruneLoop() {
	startPruneLoop("suppressions", 5*time.Minute, func() {
		s.store.PruneExpiredSuppressions()
	})
}

// startBeaconHistoryPruneLoop sweeps beacon_history rows older than
// BeaconHistoryRetentionDays on a daily cadence. Independent of the
// watch lifecycle — v0.16.2 piggybacked the sweep on the watch's
// first-tick-of-UTC-day branch, which silently broke retention for
// deployments running Archer in manual-analysis-only mode (watch
// disabled). NEW-86 from the twentieth audit round: matches the
// pattern startSuppressionsPruneLoop and startUnauthorizedPruneLoop
// already use, so retention enforcement is unconditional on the
// process lifecycle rather than on operator config.
//
// Runs once at startup (catches up a long-stopped instance) then
// every 24 hours. The sweep is idempotent and cheap (single DELETE
// keyed on day_utc), so the daily cadence has no cost concern even
// on dense histories.
func (s *Server) startBeaconHistoryPruneLoop() {
	startPruneLoop("beacon_history", 24*time.Hour, func() {
		s.store.PurgeBeaconHistory()
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The analyst workbench is a same-origin SPA — it is never
	// legitimately embedded in a frame. Deny framing outright to close
	// the clickjacking / UI-redress vector against its security-sensitive
	// actions (escalation, allowlist, user admin, admin backup). CSP is
	// scoped to frame-ancestors only: a script-src policy would break the
	// inline SCORE_EXPLANATIONS injection in index.html, and frame-ancestors
	// is the directive that actually governs embedding.
	//
	// HSTS is deliberately NOT set. Archer's TLS cert is self-signed and
	// regenerated on a TLS/volume reset; an HSTS pin would turn a
	// post-regen cert mismatch into a non-bypassable browser error and
	// lock analysts out. On an internal LAN with sensor cert-pinning the
	// SSL-strip benefit doesn't justify that failure mode. The
	// missing-HSTS scanner INFO is an accepted finding, not an oversight.
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
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

	// Favicon — browsers request /favicon.ico from the root path
	// even when the HTML carries an explicit <link rel="icon">.
	// Serve the SVG crosshairs from /static/img/ in both responses
	// so we don't paint 404s in access logs. Public, unauthenticated:
	// a favicon isn't a secret.
	s.mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(staticDir, "img", "favicon.svg"))
	})

	// Auth — no session required
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/register", s.handleRegister)
	s.mux.HandleFunc("/logout", s.handleLogout)

	// Version — unauthenticated diagnostic. Same surface tier as a future
	// /api/health: anyone reaching the listener can ask "what build is this?".
	s.mux.HandleFunc("/api/version", s.handleVersion)

	// Role-aware middleware helpers
	//   any(h)      — authenticated, any role
	//   write(h)    — authenticated, analyst or admin
	//   admin(h)    — authenticated, admin only
	any := func(h http.HandlerFunc) http.Handler { return s.requireAuth(http.HandlerFunc(h)) }
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
	s.mux.Handle("/api/logs/tree", any(s.handleLogsTree))

	// Analysis — analyst+
	s.mux.Handle("/api/analyze", write(s.handleAnalyze))
	s.mux.Handle("/api/analyze/status", any(s.handleAnalyzeStatus))
	s.mux.Handle("/api/analyze/cancel", write(s.handleAnalyzeCancel))
	s.mux.Handle("/api/analyze/pause", write(s.handleAnalyzePause))
	s.mux.Handle("/api/analyze/resume", write(s.handleAnalyzeResume))
	s.mux.Handle("/api/analyze/reset", any(s.handleAnalyzeReset)) // admin enforced inside handler

	// Findings — read=any, write=analyst+
	s.mux.Handle("/api/findings", any(s.handleFindings))
	s.mux.Handle("/api/findings/counts", any(s.handleFindingsCounts))
	s.mux.Handle("/api/findings/facets", any(s.handleFindingsFacets))
	s.mux.Handle("/api/findings/", any(s.handleFindingRouter)) // write checks done per-method inside

	// Config — read=any, write=admin only
	s.mux.Handle("/api/config", any(s.handleConfig)) // PUT enforced inside handler

	// Lists — read=any, write=analyst+
	s.mux.Handle("/api/allowlist", any(s.handleAllowlist))       // PUT enforced inside handler
	s.mux.Handle("/api/ioc", any(s.handleIOC))                   // PUT enforced inside handler
	s.mux.Handle("/api/suppressions", any(s.handleSuppressions)) // POST enforced inside handler
	s.mux.Handle("/api/suppressions/", any(s.handleDeleteSuppression))
	s.mux.Handle("/api/pair-allowlist", any(s.handlePairAllowlist))                // POST enforced inside handler
	s.mux.Handle("/api/pair-allowlist/suggested", any(s.handleSuggestedAllowlist)) // exact path before prefix
	s.mux.Handle("/api/pair-allowlist/", any(s.handleDeletePairAllow))             // DELETE enforced inside handler
	s.mux.Handle("/api/notifications", any(s.handleNotifications))
	s.mux.Handle("/api/watch", any(s.handleWatch))     // GET=any; POST enforced as admin inside handler
	s.mux.Handle("/api/archive", any(s.handleArchive)) // GET=any; POST enforced as admin inside handler
	s.mux.Handle("/api/archive/run", any(s.handleArchiveRun))
	s.mux.Handle("/api/archive/scan", any(s.handleArchiveScan)) // admin enforced inside handler — IOC/TI scan over /data/archive
	s.mux.Handle("/api/disk-usage", any(s.handleDiskUsage))     // any authenticated; /logs+archive sizes & free space

	// User / auth API
	s.mux.Handle("/api/me", any(s.handleMe))
	s.mux.Handle("/api/me/password", any(s.handleMePassword))
	s.mux.Handle("/api/users", any(s.handleUsersCollection))
	s.mux.Handle("/api/users/", admin(s.handleUserItem))

	// Admin DB backup — streams a VACUUM INTO snapshot of the live
	// SQLite database. Admin-only and audit-logged. The downloaded
	// file is forensic-grade (every finding, note, audit row, sensor
	// secret, etc.).
	s.mux.Handle("/api/admin/backup", admin(s.handleAdminBackup))

	// Threat intel — read=any
	s.mux.Handle("/api/ti/services", any(s.handleTIServices))

	// Feed integration (Phase 7) — read=any, mutate=admin enforced inside.
	// /api/feeds              GET (list) | POST (create, admin)
	// /api/feeds/{id}         PUT (update, admin) | DELETE (remove, admin)
	// /api/feeds/{id}/refresh POST (manual per-feed fetch, admin)
	// Automatic refreshes also run at every full-pass watch tick via
	// refreshFeedsBeforeFullPass; the manual endpoint is the on-demand
	// path admins use after configuring a new feed.
	s.mux.Handle("/api/feeds", any(s.handleFeeds))
	s.mux.Handle("/api/feeds/", any(s.handleFeedItem))

	// Quiver sensor-facing — no session auth required (sensors aren't
	// users; auth is the enrollment token + per-sensor HMAC).
	// Served on the same TLS listener as the rest of the API (v0.14.5
	// NEW-49 unified the listeners). install.sh is the curl-able
	// installer body; enroll/checkin are the only two endpoints a
	// sensor ever calls.
	s.mux.HandleFunc("/quiver/install.sh", s.handleQuiverInstallScript)
	s.mux.HandleFunc("/api/quiver/enroll", s.handleQuiverEnroll)
	s.mux.HandleFunc("/api/quiver/checkin", s.handleQuiverCheckin)

	// Sensors modal — read=any authenticated; admin-only writes enforced
	// inside each handler.
	s.mux.Handle("/api/sensors", any(s.handleSensorsList))
	s.mux.Handle("/api/sensors/health", any(s.handleSensorsHealth))
	s.mux.Handle("/api/sensors/info", any(s.handleSensorsInfo))
	s.mux.Handle("/api/sensors/host", any(s.handleSensorsHost))
	s.mux.Handle("/api/sensors/tokens", any(s.handleSensorsTokens))
	s.mux.Handle("/api/sensors/tokens/revoke", any(s.handleSensorsTokenRevoke))
	s.mux.Handle("/api/sensors/disenroll", any(s.handleSensorDisenroll))
	s.mux.Handle("/api/sensors/purge", any(s.handleSensorPurge))
	s.mux.Handle("/api/sensors/schedule", any(s.handleSensorSchedule))
	s.mux.Handle("/api/sensors/unauthorized", any(s.handleUnauthorizedList))
	s.mux.Handle("/api/sensors/unauthorized/dismiss", any(s.handleUnauthorizedDismiss))

	// Export / Import — analyst+
	s.mux.Handle("/api/export/json", any(s.handleExportJSON))
	s.mux.Handle("/api/export/csv", any(s.handleExportCSV))
	s.mux.Handle("/api/export/xlsx", any(s.handleExportXLSX))
	// /api/import is admin-only. The handler can wholly replace the
	// findings slice with attacker-supplied content (status, score,
	// type, detail) — granting that to analysts violates the
	// "findings come from the analyzer; analysts annotate" boundary
	// because an analyst could fabricate a Critical TI Hit on any
	// IP they wanted flagged. Admin-only matches the principle that
	// configuration changes (allowlist / IOC list, both also written
	// by /api/import) belong to admins. Audit 2026-05-10 NEW-14.
	s.mux.Handle("/api/import", admin(s.handleImportJSON))

	// Audit log — admin-only read endpoint. Covers every state-
	// changing admin action recorded post-v0.14.0. See audit.go for
	// the action naming convention and recordAudit() callers.
	s.mux.Handle("/api/audit-log", admin(s.handleAuditLog))
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
