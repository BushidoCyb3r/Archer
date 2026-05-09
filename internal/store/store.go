package store

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
	"github.com/BushidoCyb3r/Archer/internal/match"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Store is the thread-safe in-memory application state.
//
// allowlist and iocList are slices (not maps) so the operator-supplied
// order is preserved across a save/reload cycle. Maps would randomize
// iteration on each GetAllowlist/GetIOCList call, scattering any
// section-header comment lines or logical groupings the operator
// arranged in the textarea. The slice is the source of truth on disk
// too — InitDB reads with `ORDER BY rowid` and SetAllowlist/SetIOCList
// fully replace via DELETE+INSERT in slice order so SQLite rowids
// always reflect the current ordering.
type Store struct {
	mu            sync.RWMutex
	db            *sql.DB
	findings      []model.Finding
	allowlist     []string
	iocList       []string
	allowlistM    *match.Matcher           // cached compile of allowlist; rebuilt on Set
	iocM          *match.Matcher           // cached compile of iocList; rebuilt on Set
	feedMatchers  map[int64]*match.Matcher // per-feed cached compile; rebuilt on indicator write
	suppressions  map[string]suppressionEntry
	notifications []model.Notification
	notifCounter  int
	config        config.Config
	uploadedFiles []string
	analyzing     bool

	// Analyzer-side feed-bucket cache. EnabledFeedIndicators() rebuilds
	// the typed SourcedIndicators slice on every call — that's a
	// ListFeeds() + per-feed ListFeedIndicators() + CIDR-parse pass
	// that runs on every analyze tick and every TI-only incremental
	// pass. Holding the snapshot here cuts redundant DB work; feed
	// CRUD and indicator writes invalidate it.
	feedBucketsMu sync.Mutex
	feedBuckets   []feeds.SourcedIndicators
	feedBucketsOK bool
}

type suppressionEntry struct {
	Expiry time.Time
	Detail string
}

func New(cfg config.Config) *Store {
	return &Store{
		suppressions: make(map[string]suppressionEntry),
		feedMatchers: make(map[int64]*match.Matcher),
		config:       cfg,
	}
}

// sanitizeListEntries trims, strips inline `... # tail` comments from
// non-comment lines, drops empty lines, and dedupes while preserving
// first-seen order. Used by SetAllowlist, SetIOCList, and InitDB's load
// path so both fresh PUTs and existing-DB rollovers end up clean.
//
// Whole-line comments (lines whose first non-whitespace character is
// '#') pass through verbatim — operators use them as section headers
// and they round-trip through save/reload so the textarea preserves
// the operator's intended structure across sessions.
//
// Inline tails get stripped because the entry needs to be matchable —
// `1.2.3.4 # office` would otherwise be stored as a literal string
// that never matches any IP. '#' isn't legal in IPs, CIDRs, or DNS
// labels, so the strip is safe regardless of position.
func sanitizeListEntries(entries []string) []string {
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if e[0] != '#' {
			for i := 0; i < len(e)-1; i++ {
				if (e[i] == ' ' || e[i] == '\t') && e[i+1] == '#' {
					e = strings.TrimSpace(e[:i])
					break
				}
			}
		}
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// InitDB wires the store to the shared SQLite database and loads
// previously persisted state into memory. Schema creation is no longer
// done here — RunMigrations (called from NewUserStore on the same DB
// handle) brings every table to the current version before this method
// runs. InitDB is purely a "read existing state into memory" pass.
func (s *Store) InitDB(db *sql.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db

	loadOrdered := func(tbl string) []string {
		rows, err := db.Query(`SELECT entry FROM ` + tbl + ` ORDER BY rowid`)
		if err != nil {
			log.Printf("store: cannot load %s: %v", tbl, err)
			return nil
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var e string
			if rows.Scan(&e) == nil && e != "" {
				out = append(out, e)
			}
		}
		return out
	}
	// Sanitize on load so any pre-comment-strip junk from older Archer
	// installs gets cleaned automatically. If sanitize changes the slice,
	// re-persist so SQLite reflects the cleaned form on disk too.
	s.allowlist = loadOrdered("allowlist")
	if cleaned := sanitizeListEntries(s.allowlist); !slicesEqual(cleaned, s.allowlist) {
		s.allowlist = cleaned
		s.persistList("allowlist", s.allowlist)
	}
	s.iocList = loadOrdered("ioc_list")
	if cleaned := sanitizeListEntries(s.iocList); !slicesEqual(cleaned, s.iocList) {
		s.iocList = cleaned
		s.persistList("ioc_list", s.iocList)
	}

	// Compile the cached matchers once at load. Rebuilt only when
	// SetAllowlist/SetIOCList are called — what was previously rebuilt
	// per /api/findings request, costing 100-500ms on a hot list.
	s.allowlistM = match.Compile(s.allowlist)
	s.iocM = match.Compile(s.iocList)

	var cfgJSON string
	if err := db.QueryRow(`SELECT config FROM settings WHERE id = 1`).Scan(&cfgJSON); err == nil {
		if err := json.Unmarshal([]byte(cfgJSON), &s.config); err != nil {
			log.Printf("store: corrupt settings, using defaults: %v", err)
		}
	}

	now := time.Now().Unix()
	if _, err := db.Exec(`DELETE FROM suppressions WHERE expiry <= ?`, now); err != nil {
		log.Printf("store: prune suppressions: %v", err)
	}
	if rows, err := db.Query(`SELECT target, expiry, detail FROM suppressions`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var target, detail string
			var expUnix int64
			if rows.Scan(&target, &expUnix, &detail) == nil {
				s.suppressions[target] = suppressionEntry{Expiry: time.Unix(expUnix, 0), Detail: detail}
			}
		}
	}

	s.loadFindings()
}

// persistList replaces all rows in tbl with the current entries.
// Items are inserted in slice order so SQLite's rowid sequence reflects
// the operator's intended ordering — InitDB's `ORDER BY rowid` SELECT
// then reproduces the same order on next load. Caller must hold s.mu
// at least for reading (items is already a snapshot).
func (s *Store) persistList(tbl string, items []string) {
	if s.db == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: persist %s begin: %v", tbl, err)
		return
	}
	if _, err := tx.Exec(`DELETE FROM ` + tbl); err != nil {
		tx.Rollback()
		log.Printf("store: persist %s delete: %v", tbl, err)
		return
	}
	for _, e := range items {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO `+tbl+` (entry) VALUES (?)`, e); err != nil {
			tx.Rollback()
			log.Printf("store: persist %s insert: %v", tbl, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("store: persist %s commit: %v", tbl, err)
	}
}

// loadFindings reads persisted findings from SQLite into s.findings.
// Caller must hold s.mu (called from InitDB which holds it).
func (s *Store) loadFindings() {
	if s.db == nil {
		return
	}
	rows, err := s.db.Query(`SELECT id, type, severity, score, src_ip, dst_ip, dst_port, detail, timestamp, source_file, status, analyst, analyst_note, status_ts, ioc_match, is_new, sensor, intervals, ts_data, notes FROM findings ORDER BY id`)
	if err != nil {
		log.Printf("store: load findings: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var f model.Finding
		var iocMatch, isNew int
		var intervals, tsData, notes string
		if err := rows.Scan(&f.ID, &f.Type, &f.Severity, &f.Score, &f.SrcIP, &f.DstIP, &f.DstPort, &f.Detail, &f.Timestamp, &f.SourceFile, &f.Status, &f.Analyst, &f.AnalystNote, &f.StatusTS, &iocMatch, &isNew, &f.Sensor, &intervals, &tsData, &notes); err != nil {
			log.Printf("store: scan finding: %v", err)
			continue
		}
		f.IOCMatch = iocMatch == 1
		f.IsNew = isNew == 1
		if intervals != "" {
			if err := json.Unmarshal([]byte(intervals), &f.Intervals); err != nil {
				log.Printf("store: finding %d: corrupt intervals data: %v", f.ID, err)
			}
		}
		if tsData != "" {
			if err := json.Unmarshal([]byte(tsData), &f.TSData); err != nil {
				log.Printf("store: finding %d: corrupt ts_data: %v", f.ID, err)
			}
		}
		if notes != "" {
			if err := json.Unmarshal([]byte(notes), &f.Notes); err != nil {
				log.Printf("store: finding %d: corrupt notes: %v", f.ID, err)
			}
		}
		s.findings = append(s.findings, f)
	}
}

// saveFindings replaces all rows in the findings table with s.findings.
// Caller must hold s.mu.
func (s *Store) saveFindings() {
	if s.db == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: save findings begin: %v", err)
		return
	}
	if _, err := tx.Exec(`DELETE FROM findings`); err != nil {
		tx.Rollback()
		log.Printf("store: save findings delete: %v", err)
		return
	}
	for _, f := range s.findings {
		intervals, _ := json.Marshal(f.Intervals)
		tsData, _ := json.Marshal(f.TSData)
		notes, _ := json.Marshal(f.Notes)
		iocMatch, isNew := 0, 0
		if f.IOCMatch {
			iocMatch = 1
		}
		if f.IsNew {
			isNew = 1
		}
		_, err := tx.Exec(
			`INSERT INTO findings (id, type, severity, score, src_ip, dst_ip, dst_port, detail, timestamp, source_file, status, analyst, analyst_note, status_ts, ioc_match, is_new, sensor, intervals, ts_data, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			f.ID, f.Type, string(f.Severity), f.Score, f.SrcIP, f.DstIP, f.DstPort, f.Detail, f.Timestamp, f.SourceFile,
			string(f.Status), f.Analyst, f.AnalystNote, f.StatusTS, iocMatch, isNew, f.Sensor,
			string(intervals), string(tsData), string(notes),
		)
		if err != nil {
			tx.Rollback()
			log.Printf("store: save findings insert: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("store: save findings commit: %v", err)
	}
}

func (s *Store) GetFindings() []model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

// SetFindings merges new analysis results with existing findings, carries over
// analyst annotations for re-detected fingerprints, persists to SQLite, and
// returns any new notifications generated.
func (s *Store) SetFindings(findings []model.Finding) []model.Notification {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Index existing findings by fingerprint so we can carry over analyst work.
	existing := make(map[model.Fingerprint]model.Finding, len(s.findings))
	for _, f := range s.findings {
		existing[f.Fingerprint()] = f
	}

	newFPSet := make(map[model.Fingerprint]bool, len(findings))
	for i := range findings {
		fp := findings[i].Fingerprint()
		newFPSet[fp] = true
		if old, ok := existing[fp]; ok {
			findings[i].Status = old.Status
			findings[i].Analyst = old.Analyst
			findings[i].AnalystNote = old.AnalystNote
			findings[i].StatusTS = old.StatusTS
			findings[i].Notes = old.Notes
			findings[i].IsNew = false
		} else {
			findings[i].IsNew = true
		}
	}

	// Preserve all historical findings that weren't regenerated in this run.
	// A finding reflected a real observation at the time it was detected, and
	// remains valid even when its source logs are later archived or rotated
	// out of /logs. Removal is explicit-only — admin-driven via archive
	// pruning (PruneFindingsOnArchive) or manual deletion — never a side
	// effect of re-analysis.
	for fp, old := range existing {
		if !newFPSet[fp] {
			old.IsNew = false
			findings = append(findings, old)
		}
	}

	s.findings = findings
	s.analyzing = false
	s.saveFindings()

	var newNotifs []model.Notification
	for _, f := range findings {
		// Host Risk Score is an aggregate per-host roll-up that lives in
		// the Hosts tab, not a discrete network event. Suppress it from
		// the bell — the underlying network detections that pushed the
		// host's score over the line have already generated their own
		// notifications, and a "jump to finding" tap would land on a
		// row that the Findings tab no longer renders.
		if f.Type == "Host Risk Score" {
			continue
		}
		if f.IsNew && (f.Severity == model.SevCritical || model.IsThreatIntelType(f.Type)) {
			s.notifCounter++
			n := model.Notification{
				ID:        s.notifCounter,
				FindingID: f.ID,
				Severity:  string(f.Severity),
				Type:      f.Type,
				SrcIP:     f.SrcIP,
				DstIP:     f.DstIP,
				DstPort:   f.DstPort,
			}
			s.notifications = append(s.notifications, n)
			newNotifs = append(newNotifs, n)
		}
	}
	return newNotifs
}

func (s *Store) UpdateFinding(id int, status model.Status, analyst, note, statusTS string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.findings {
		if s.findings[i].ID == id {
			s.findings[i].Status = status
			s.findings[i].Analyst = analyst
			s.findings[i].AnalystNote = note
			s.findings[i].StatusTS = statusTS
			if s.db != nil {
				if _, err := s.db.Exec(`UPDATE findings SET status=?, analyst=?, analyst_note=?, status_ts=? WHERE id=?`,
					string(status), analyst, note, statusTS, id); err != nil {
					log.Printf("store: update finding %d: %v", id, err)
				}
			}
			return true
		}
	}
	return false
}

func (s *Store) GetFinding(id int) (model.Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, f := range s.findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

func (s *Store) AddNote(id int, note model.Note) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.findings {
		if s.findings[i].ID == id {
			s.findings[i].Notes = append(s.findings[i].Notes, note)
			if s.db != nil {
				notesJSON, _ := json.Marshal(s.findings[i].Notes)
				if _, err := s.db.Exec(`UPDATE findings SET notes=? WHERE id=?`, string(notesJSON), id); err != nil {
					log.Printf("store: add note to finding %d: %v", id, err)
				}
			}
			return true
		}
	}
	return false
}

func (s *Store) GetConfig() config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *Store) SetConfig(cfg config.Config) {
	s.mu.Lock()
	s.config = cfg
	if s.db != nil {
		cfgJSON, _ := json.Marshal(cfg)
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON)); err != nil {
			log.Printf("store: persist settings: %v", err)
		}
	}
	s.mu.Unlock()
}

func (s *Store) GetAllowlist() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.allowlist))
	copy(out, s.allowlist)
	return out
}

func (s *Store) SetAllowlist(entries []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowlist = sanitizeListEntries(entries)
	s.persistList("allowlist", s.allowlist)
	s.allowlistM = match.Compile(s.allowlist)
}

func (s *Store) GetIOCList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.iocList))
	copy(out, s.iocList)
	return out
}

func (s *Store) SetIOCList(entries []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.iocList = sanitizeListEntries(entries)
	s.persistList("ioc_list", s.iocList)
	s.iocM = match.Compile(s.iocList)
}

// AllowlistMatcher returns the cached compiled matcher. Safe to call
// concurrently — the Matcher value is immutable once compiled, so the
// pointer copy under the read lock is sufficient.
func (s *Store) AllowlistMatcher() *match.Matcher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowlistM
}

// SourcedMatcher pairs a compiled matcher with the human-readable
// label of the list it was compiled from. Returned by IOCSources()
// so /api/findings can short-circuit on the first hit and tag the
// finding with which list flagged it.
type SourcedMatcher struct {
	Source  string // "Operator IOC list" or "Feed: <feed name>"
	Matcher *match.Matcher
}

// IOCSources returns the operator IOC list matcher first, then one
// matcher per enabled feed in feed-id order. Disabled feeds are
// excluded so the operator can mute a noisy feed via the admin UI
// without deleting its indicators. Per-feed matchers are lazy-built
// the first time they're requested and cached; UpsertFeedIndicators,
// RemoveStaleIndicators, and DeleteFeed invalidate the cache for
// the affected feed.
func (s *Store) IOCSources() []SourcedMatcher {
	s.mu.RLock()
	iocM := s.iocM
	s.mu.RUnlock()

	out := []SourcedMatcher{
		{Source: "Operator IOC list", Matcher: iocM},
	}
	for _, f := range s.ListFeeds() {
		if !f.Enabled {
			continue
		}
		m := s.feedMatcher(f.ID)
		out = append(out, SourcedMatcher{
			Source:  "Feed: " + f.Name,
			Matcher: m,
		})
	}
	return out
}

// feedMatcher returns the compiled matcher for one feed, building +
// caching on first request and returning the cached value on
// subsequent calls. Invalidation is the responsibility of the write
// methods (UpsertFeedIndicators, RemoveStaleIndicators, DeleteFeed).
func (s *Store) feedMatcher(feedID int64) *match.Matcher {
	s.mu.RLock()
	if m, ok := s.feedMatchers[feedID]; ok {
		s.mu.RUnlock()
		return m
	}
	s.mu.RUnlock()

	// Read indicators outside the lock — ListFeedIndicators acquires
	// the DB but not s.mu, so this avoids holding s.mu across SQLite
	// I/O while rebuilding.
	inds := s.ListFeedIndicators(feedID)
	entries := make([]string, 0, len(inds))
	for _, ind := range inds {
		entries = append(entries, ind.Indicator)
	}
	m := match.Compile(entries)

	s.mu.Lock()
	// Double-check under write lock so a concurrent rebuild doesn't
	// drop a fresh entry.
	if existing, ok := s.feedMatchers[feedID]; ok {
		s.mu.Unlock()
		return existing
	}
	s.feedMatchers[feedID] = m
	s.mu.Unlock()
	return m
}

// invalidateFeedMatcher drops the cached matcher for a feed. The next
// IOCSources / feedMatcher call rebuilds from current indicators.
func (s *Store) invalidateFeedMatcher(feedID int64) {
	s.mu.Lock()
	delete(s.feedMatchers, feedID)
	s.mu.Unlock()
}

func (s *Store) AddSuppression(target string, expiry time.Time, detail string) {
	s.mu.Lock()
	s.suppressions[target] = suppressionEntry{Expiry: expiry, Detail: detail}
	if s.db != nil {
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO suppressions (target, expiry, detail) VALUES (?, ?, ?)`, target, expiry.Unix(), detail); err != nil {
			log.Printf("store: persist suppression: %v", err)
		}
	}
	s.mu.Unlock()
}

func (s *Store) RemoveSuppression(target string) {
	s.mu.Lock()
	delete(s.suppressions, target)
	if s.db != nil {
		if _, err := s.db.Exec(`DELETE FROM suppressions WHERE target = ?`, target); err != nil {
			log.Printf("store: remove suppression: %v", err)
		}
	}
	s.mu.Unlock()
}

func (s *Store) GetSuppressions() map[string]suppressionEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]suppressionEntry, len(s.suppressions))
	for k, v := range s.suppressions {
		out[k] = v
	}
	return out
}

func (s *Store) IsSuppressed(ip string) bool {
	s.mu.RLock()
	entry, ok := s.suppressions[ip]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(entry.Expiry) {
		s.mu.Lock()
		delete(s.suppressions, ip)
		if s.db != nil {
			s.db.Exec(`DELETE FROM suppressions WHERE target = ?`, ip)
		}
		s.mu.Unlock()
		return false
	}
	return true
}

func (s *Store) GetNotifications() []model.Notification {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Notification, len(s.notifications))
	copy(out, s.notifications)
	return out
}

func (s *Store) DismissNotification(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.notifications {
		if s.notifications[i].ID == id {
			s.notifications[i].Dismissed = true
			return
		}
	}
}

func (s *Store) DismissAllNotifications() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.notifications {
		s.notifications[i].Dismissed = true
	}
}

func (s *Store) SetUploadedFiles(paths []string) {
	s.mu.Lock()
	s.uploadedFiles = paths
	s.mu.Unlock()
}

func (s *Store) GetUploadedFiles() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.uploadedFiles))
	copy(out, s.uploadedFiles)
	return out
}

func (s *Store) AppendUploadedFile(path string) {
	s.mu.Lock()
	s.uploadedFiles = append(s.uploadedFiles, path)
	s.mu.Unlock()
}

// SetWatch persists watch state — note the new intervalHours parameter:
// 0 (or 24) means daily-at-HH:MM (legacy behavior), 1/4/6/12 turn the
// watch loop into a sub-daily ticker so analysis catches up with hourly
// Quiver shipments without waiting for the once-a-day window.
func (s *Store) SetWatch(watchTime, timezone string, enabled bool, intervalHours int) {
	s.mu.Lock()
	s.config.WatchTime = watchTime
	s.config.Timezone = timezone
	s.config.WatchEnabled = enabled
	s.config.WatchIntervalHours = intervalHours
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.mu.Unlock()
}

func (s *Store) GetWatch() (watchTime string, enabled bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.WatchTime, s.config.WatchEnabled
}

// GetTimezone returns the operator's IANA timezone, or "" when none is set.
// Callers should treat "" as UTC. Used by the watch scheduler to interpret
// WatchTime and by the off-hours detector to interpret OffHoursStart/End.
func (s *Store) GetTimezone() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Timezone
}

// GetWatchInterval returns the configured cadence in hours: 0 (default)
// means once-daily-at-HH:MM. Callers normalise 24 → 0 for the same
// effect.
func (s *Store) GetWatchInterval() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.WatchIntervalHours
}

// GetSensorFacingHost returns the admin-overridden hostname/IP that Quiver
// install one-liners should target, or "" when unset (caller falls back to
// the request Host header).
func (s *Store) GetSensorFacingHost() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.SensorFacingHost
}

// SetSensorFacingHost persists the admin-supplied sensor-facing hostname.
func (s *Store) SetSensorFacingHost(host string) {
	s.mu.Lock()
	s.config.SensorFacingHost = host
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.mu.Unlock()
}

// ArchiveSettings is the admin-editable archive config plus read-only
// telemetry from the most recent run. The last_* fields are only ever
// written by RecordArchiveRun — SetArchive ignores them.
type ArchiveSettings struct {
	Enabled                bool   `json:"enabled"`
	AfterDays              int    `json:"after_days"`
	PruneFindingsOnArchive bool   `json:"prune_findings_on_archive"`
	LastRunAt              string `json:"last_run_at,omitempty"`
	LastFilesArchived      int    `json:"last_files_archived,omitempty"`
	LastBytesArchived      int64  `json:"last_bytes_archived,omitempty"`
	LastFindingsPruned     int    `json:"last_findings_pruned,omitempty"`
	LastTriggeredBy        string `json:"last_triggered_by,omitempty"`
}

func (s *Store) SetArchive(settings ArchiveSettings) {
	s.mu.Lock()
	s.config.ArchiveEnabled = settings.Enabled
	if settings.AfterDays > 0 {
		s.config.ArchiveAfterDays = settings.AfterDays
	}
	s.config.PruneFindingsOnArchive = settings.PruneFindingsOnArchive
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.mu.Unlock()
}

func (s *Store) GetArchive() ArchiveSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ArchiveSettings{
		Enabled:                s.config.ArchiveEnabled,
		AfterDays:              s.config.ArchiveAfterDays,
		PruneFindingsOnArchive: s.config.PruneFindingsOnArchive,
		LastRunAt:              s.config.ArchiveLastRunAt,
		LastFilesArchived:      s.config.ArchiveLastFilesArchived,
		LastBytesArchived:      s.config.ArchiveLastBytesArchived,
		LastFindingsPruned:     s.config.ArchiveLastFindingsPruned,
		LastTriggeredBy:        s.config.ArchiveLastTriggeredBy,
	}
}

// RecordArchiveRun persists telemetry for the most recent archive run.
// triggeredBy should be the admin's display name/email for manual runs
// or "scheduled" when the watch tick fired it. Dry runs must not call
// this — the goal is to record only actual file movement.
func (s *Store) RecordArchiveRun(filesArchived int, bytesArchived int64, findingsPruned int, triggeredBy string) {
	s.mu.Lock()
	s.config.ArchiveLastRunAt = time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	s.config.ArchiveLastFilesArchived = filesArchived
	s.config.ArchiveLastBytesArchived = bytesArchived
	s.config.ArchiveLastFindingsPruned = findingsPruned
	s.config.ArchiveLastTriggeredBy = triggeredBy
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.mu.Unlock()
}

func (s *Store) GetLastAnalysisFingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.LastAnalysisFingerprint
}

func (s *Store) SetLastAnalysisFingerprint(fp string) {
	s.mu.Lock()
	s.config.LastAnalysisFingerprint = fp
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.mu.Unlock()
}

// GetLastFullAnalysisTime returns when the most recent full analysis run
// completed. Zero time means no full run has ever finished on this
// deployment — the watch loop treats that as "do a full run on the next
// tick" so a fresh box gets a baseline before any incremental ticks fire.
func (s *Store) GetLastFullAnalysisTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config.LastFullAnalysisUnix == 0 {
		return time.Time{}
	}
	return time.Unix(s.config.LastFullAnalysisUnix, 0).UTC()
}

// SetLastFullAnalysisTime records when a full run completed. Called by the
// full-analysis flow (manual "Discard & re-analyze" or the daily watch
// tick) on success — never by incremental runs, since they don't reset
// the "do a full today" gate.
func (s *Store) SetLastFullAnalysisTime(t time.Time) {
	s.mu.Lock()
	s.config.LastFullAnalysisUnix = t.UTC().Unix()
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.mu.Unlock()
}

// GetLastAnalysisTime returns when ANY analysis run (full or incremental)
// most recently completed. Used as the mtime cutoff for the next
// incremental tick's file filter — anything modified after this time is
// considered "new" and gets re-processed.
func (s *Store) GetLastAnalysisTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config.LastAnalysisUnix == 0 {
		return time.Time{}
	}
	return time.Unix(s.config.LastAnalysisUnix, 0).UTC()
}

// SetLastAnalysisTime records when any analysis run completed. Called by
// both full and incremental flows on success.
func (s *Store) SetLastAnalysisTime(t time.Time) {
	s.mu.Lock()
	s.config.LastAnalysisUnix = t.UTC().Unix()
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.mu.Unlock()
}

// ClearFindings removes every finding from the in-memory slice and persists
// the empty state. Notifications and analyst annotations tied to those
// findings are lost. Intended for admin-triggered "discard and re-analyze"
// flows after config changes that should produce a fresh baseline.
func (s *Store) ClearFindings() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.findings)
	s.findings = nil
	s.config.LastAnalysisFingerprint = ""
	if s.db != nil {
		cfgJSON, _ := json.Marshal(s.config)
		s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	}
	s.saveFindings()
	return n
}

// CountFindingsBefore returns how many findings PruneFindingsBefore would
// drop for the same cutoff, without mutating state. Used by the dry-run
// preview on Run Archive Now. Drop semantics must match
// PruneFindingsBefore exactly so the preview tells the truth.
func (s *Store) CountFindingsBefore(cutoff time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dropped := 0
	for _, f := range s.findings {
		if f.Timestamp == "" {
			dropped++
			continue
		}
		t, err := time.Parse("2006-01-02 15:04:05", f.Timestamp)
		if err != nil {
			dropped++
			continue
		}
		if t.Before(cutoff) {
			dropped++
		}
	}
	return dropped
}

// PruneFindingsBefore removes findings whose Timestamp parses to a time
// earlier than cutoff. Findings with empty or unparseable timestamps are
// also dropped — this function is only invoked from the explicitly opt-in
// "Also remove findings older than the archive cutoff (destructive)"
// toggle, so an aggressive default matches the user's intent. Returns the
// number of findings dropped.
func (s *Store) PruneFindingsBefore(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.findings[:0]
	dropped := 0
	for _, f := range s.findings {
		if f.Timestamp == "" {
			dropped++
			continue
		}
		t, err := time.Parse("2006-01-02 15:04:05", f.Timestamp)
		if err != nil {
			dropped++
			continue
		}
		if !t.Before(cutoff) {
			kept = append(kept, f)
			continue
		}
		dropped++
	}
	if dropped > 0 {
		s.findings = kept
		s.saveFindings()
	}
	return dropped
}

func (s *Store) SetAnalyzing(v bool) {
	s.mu.Lock()
	s.analyzing = v
	s.mu.Unlock()
}

func (s *Store) IsAnalyzing() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.analyzing
}
