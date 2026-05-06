package store

import (
	"database/sql"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Store is the thread-safe in-memory application state.
type Store struct {
	mu             sync.RWMutex
	db             *sql.DB
	findings       []model.Finding
	allowlist      map[string]bool
	iocList        map[string]bool
	suppressions   map[string]suppressionEntry
	notifications  []model.Notification
	notifCounter   int
	config         config.Config
	uploadedFiles  []string
	analyzing      bool
}

type suppressionEntry struct {
	Expiry time.Time
	Detail string
}

func New(cfg config.Config) *Store {
	return &Store{
		allowlist:    make(map[string]bool),
		iocList:      make(map[string]bool),
		suppressions: make(map[string]suppressionEntry),
		config:       cfg,
	}
}

// InitDB wires the store to a shared SQLite database, creates the necessary
// tables, and loads any previously saved allowlist / IOC list entries.
func (s *Store) InitDB(db *sql.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db

	for _, tbl := range []string{"allowlist", "ioc_list"} {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + tbl + ` (entry TEXT PRIMARY KEY)`); err != nil {
			log.Printf("store: cannot create %s table: %v", tbl, err)
		}
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS findings (
		id           INTEGER PRIMARY KEY,
		type         TEXT,
		severity     TEXT,
		score        INTEGER,
		src_ip       TEXT,
		dst_ip       TEXT,
		dst_port     TEXT,
		detail       TEXT,
		timestamp    TEXT,
		source_file  TEXT,
		status       TEXT,
		analyst      TEXT,
		analyst_note TEXT,
		status_ts    TEXT,
		ioc_match    INTEGER DEFAULT 0,
		is_new       INTEGER DEFAULT 0,
		sensor       TEXT,
		intervals    TEXT,
		ts_data      TEXT,
		notes        TEXT
	)`); err != nil {
		log.Printf("store: cannot create findings table: %v", err)
	}
	// Migration: pre-Quiver schemas had this column named "dataset". The rename
	// is one-way; once renamed the ALTER becomes a no-op (column already named
	// "sensor"), and the duplicate-column error is the all-clear signal.
	if _, err := db.Exec(`ALTER TABLE findings RENAME COLUMN dataset TO sensor`); err == nil {
		log.Printf("store: migrated findings.dataset → findings.sensor")
	}

	load := func(tbl string, dst map[string]bool) {
		rows, err := db.Query(`SELECT entry FROM ` + tbl)
		if err != nil {
			log.Printf("store: cannot load %s: %v", tbl, err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var e string
			if rows.Scan(&e) == nil && e != "" {
				dst[e] = true
			}
		}
	}
	load("allowlist", s.allowlist)
	load("ioc_list", s.iocList)

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, config TEXT NOT NULL)`); err != nil {
		log.Printf("store: cannot create settings table: %v", err)
	}
	var cfgJSON string
	if err := db.QueryRow(`SELECT config FROM settings WHERE id = 1`).Scan(&cfgJSON); err == nil {
		if err := json.Unmarshal([]byte(cfgJSON), &s.config); err != nil {
			log.Printf("store: corrupt settings, using defaults: %v", err)
		}
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS suppressions (target TEXT PRIMARY KEY, expiry INTEGER NOT NULL, detail TEXT DEFAULT '')`); err != nil {
		log.Printf("store: cannot create suppressions table: %v", err)
	}
	// Add detail column to existing tables that predate this schema change
	db.Exec(`ALTER TABLE suppressions ADD COLUMN detail TEXT DEFAULT ''`)
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

	s.InitSensorTables(db)
	s.loadFindings()
}

// persistList replaces all rows in tbl with the current entries.
// Caller must hold s.mu at least for reading (items is already a snapshot).
func (s *Store) persistList(tbl string, items map[string]bool) {
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
	for e := range items {
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
			findings[i].Status      = old.Status
			findings[i].Analyst     = old.Analyst
			findings[i].AnalystNote = old.AnalystNote
			findings[i].StatusTS    = old.StatusTS
			findings[i].Notes       = old.Notes
			findings[i].IsNew       = false
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
		if f.IsNew && (f.Severity == model.SevCritical || f.Type == "Threat Intel Hit" || f.Type == "Suspicious URL") {
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
	out := make([]string, 0, len(s.allowlist))
	for k := range s.allowlist {
		out = append(out, k)
	}
	return out
}

func (s *Store) SetAllowlist(entries []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowlist = make(map[string]bool, len(entries))
	for _, e := range entries {
		if e != "" {
			s.allowlist[e] = true
		}
	}
	s.persistList("allowlist", s.allowlist)
}

func (s *Store) GetIOCList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.iocList))
	for k := range s.iocList {
		out = append(out, k)
	}
	return out
}

func (s *Store) SetIOCList(entries []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.iocList = make(map[string]bool, len(entries))
	for _, e := range entries {
		if e != "" {
			s.iocList[e] = true
		}
	}
	s.persistList("ioc_list", s.iocList)
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
	s.config.WatchTimezone = timezone
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

// GetWatchTimezone returns the IANA name configured for the watch schedule,
// or "" when none is set. Callers should treat "" as UTC.
func (s *Store) GetWatchTimezone() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.WatchTimezone
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
