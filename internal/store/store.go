// Package store is Archer's persistence layer. The Store holds the canonical
// application state in memory (the findings slice plus its id→index map,
// allowlist/IOC/suppression lists, config, watch state) and uses SQLite purely
// as the durability tier — reads serve from memory, writes fan out to both.
// The central invariant lives in SetFindings: it is a fingerprint-merge, not a
// replace, so a re-analysis preserves analyst work (Status/Analyst/Notes/
// StatusTS) on fingerprint-matched findings and carries their IDs forward,
// assigning new IDs strictly above the existing max, while Score/Severity/
// Detail/Timestamp are refreshed from the new run. SQLite runs in WAL mode on a
// single shared connection; saveFindings rewrites the findings table inside one
// transaction and records a persistence-degraded flag (PersistenceError) on
// failure so a write error is operator-visible rather than silent.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
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
	mu sync.RWMutex
	db *sql.DB
	// findings is the canonical slice; findingsIdx is an id → slice-index
	// map maintained alongside it so GetFinding / UpdateFinding / AddNote
	// resolve in O(1) instead of scanning the whole slice. Pre-fix every
	// analyst note + status mutation walked all findings linearly; on a
	// long-running install with 5–10k preserved historical findings the
	// hot UI paths (analyst clicks "investigating", types a note) added
	// ~ms-scale jitter that the SSE stream amplified. The map MUST be
	// kept consistent with the slice — every place that assigns or
	// rebuilds s.findings must also rebuild s.findingsIdx through
	// rebuildFindingsIdx.
	findings       []model.Finding
	findingsIdx    map[int]int
	allowlist      []string
	iocList        []string
	iocFPList      []string                 // operator JA3/JA4 fingerprint IOCs; matched at analyze time, not read time
	allowlistM     *match.Matcher           // cached compile of allowlist; rebuilt on Set
	iocM           *match.Matcher           // cached compile of iocList; rebuilt on Set
	feedMatchers   map[int64]*match.Matcher // per-feed cached compile; rebuilt on indicator write
	feedMatcherGen map[int64]uint64         // invalidation generation counter; incremented on each cache drop
	findingsLoadOK bool                     // false if loadFindings encountered any scan/iteration error
	suppressions   map[string]SuppressionEntry
	pairAllow      []model.PairAllowEntry
	pairAllowIdx   map[string][]pairAllowRule // src\x00dst\x00port -> rules; sensor="" and ftype="" are wildcards
	pairAllowScan  []pairAllowScanRule        // ranged rules (a side is a CIDR or *.domain); scanned after the exact index misses
	fpAllow        []model.FingerprintAllowEntry
	fpAllowIdx     map[string]bool // kind\x00fingerprint -> allowlisted (benign TLS fingerprint)
	notifications  []model.Notification
	notifCounter   int
	config         config.Config
	analyzing      bool

	// persistErr holds the message from the most recent findings-save
	// failure, or "" when the last save succeeded. saveFindings logs
	// failures, but a log line dies with a container restart; this flag is
	// read by the server layer (analyze-status endpoint, SSE status event)
	// so a persistent write failure — disk full, DB locked — is visible to
	// the operator instead of silently diverging in-memory state from disk.
	// Guarded by mu.
	persistErr string

	// fpJA4 / fpJA3 are the latest per-fingerprint TLS prevalence snapshot,
	// pushed by the server after each full analysis (SetFingerprintPrevalence)
	// and consulted at read time by FingerprintConcern to colour the beacon
	// detail-pane fingerprint row. Transient like the sibling counts — empty
	// until the first full analysis after a restart repopulates them.
	fpJA4 map[string]model.FingerprintStat
	fpJA3 map[string]model.FingerprintStat

	// Analyzer-side feed-bucket cache. EnabledFeedIndicators() rebuilds
	// the typed SourcedIndicators slice on every call — that's a
	// ListFeeds() + per-feed ListFeedIndicators() + CIDR-parse pass
	// that runs on every analyze tick and every TI-only incremental
	// pass. Holding the snapshot here cuts redundant DB work; feed
	// CRUD and indicator writes invalidate it.
	//
	// enabledFeedList is a separate cache for IOCSources()'s ListFeeds()
	// call, which fires on every /api/findings request. Same invalidation
	// hook as feedBuckets — any feed CRUD path that calls
	// invalidateFeedBuckets() clears both.
	feedBucketsMu   sync.Mutex
	feedBuckets     []feeds.SourcedIndicators
	feedBucketsOK   bool
	enabledFeedList []feeds.Feed
	feedListOK      bool

	// Audit-log total-count cache. CountAuditLog runs a COUNT(*) on
	// every UI page-load; for a multi-million-row audit_log that's
	// seconds per load. TTL-cache makes the worst case one scan per
	// minute regardless of UI activity. v0.14.3 NEW-43.
	auditCountValue int64
	auditCountAt    time.Time
}

type SuppressionEntry struct {
	Expiry time.Time
	Detail string
}

func New(cfg config.Config) *Store {
	return &Store{
		suppressions:   make(map[string]SuppressionEntry),
		pairAllowIdx:   make(map[string][]pairAllowRule),
		fpAllowIdx:     make(map[string]bool),
		feedMatchers:   make(map[int64]*match.Matcher),
		feedMatcherGen: make(map[int64]uint64),
		findingsIdx:    make(map[int]int),
		config:         cfg,
	}
}

// rebuildFindingsIdx rewrites the id→slice-index map from the current
// s.findings slice. Caller must hold s.mu.Lock().
func (s *Store) rebuildFindingsIdx() {
	s.findingsIdx = make(map[int]int, len(s.findings))
	for i, f := range s.findings {
		s.findingsIdx[f.ID] = i
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

// sanitizeFingerprintEntries normalizes the JA3/JA4 IOC list. Unlike
// sanitizeListEntries it does NOT keep comment lines: the fingerprint list is
// machine state (the UI re-injects the built-in section on every open), so a
// persisted comment would accumulate duplicate header lines across saves. Each
// surviving entry is reduced to its first whitespace-delimited token (dropping
// any inline ` # label` the UI rendered next to a built-in) and lowercased, so
// it matches the lowercased ja3/ja4 the SSL analyzer reads from Zeek.
func sanitizeFingerprintEntries(entries []string) []string {
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" || e[0] == '#' {
			continue
		}
		if i := strings.IndexAny(e, " \t"); i >= 0 {
			e = e[:i]
		}
		e = strings.ToLower(e)
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

	// loadOrdered returns (entries, ok). ok is false if the read failed or
	// stopped mid-iteration (rows.Err) — distinct from a clean empty table.
	// Callers MUST NOT re-persist a !ok result: a truncated read followed by
	// the sanitize re-persist below would DELETE-then-reinsert only the rows
	// that were read, permanently dropping the unread tail of an
	// authoritative list (allowlist un-hides hosts, ioc_list misses IOCs).
	loadOrdered := func(tbl string) ([]string, bool) {
		// tbl is a table identifier (SQL placeholders cannot
		// parameterize identifiers) and loadOrdered is only ever
		// called with hardcoded literal table names — not reachable
		// from user input.
		rows, err := db.Query(`SELECT entry FROM ` + tbl + ` ORDER BY rowid`) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- constant table identifier, internal callers only
		if err != nil {
			slog.Warn("store: cannot load table", "table", tbl, "err", err)
			return nil, false
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var e string
			if rows.Scan(&e) == nil && e != "" {
				out = append(out, e)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("store: incomplete table load — refusing sanitize re-persist", "table", tbl, "err", err)
			return out, false
		}
		return out, true
	}
	// Sanitize on load so any pre-comment-strip junk from older Archer
	// installs gets cleaned automatically. If sanitize changes the slice,
	// re-persist so SQLite reflects the cleaned form on disk too — but only
	// when the load completed cleanly, so a partial read never overwrites the
	// authoritative list with a truncated copy.
	var allowOK, iocOK bool
	s.allowlist, allowOK = loadOrdered("allowlist")
	if allowOK {
		if cleaned := sanitizeListEntries(s.allowlist); !slicesEqual(cleaned, s.allowlist) {
			s.allowlist = cleaned
			s.persistList("allowlist", s.allowlist)
		}
	}
	s.iocList, iocOK = loadOrdered("ioc_list")
	if iocOK {
		if cleaned := sanitizeListEntries(s.iocList); !slicesEqual(cleaned, s.iocList) {
			s.iocList = cleaned
			s.persistList("ioc_list", s.iocList)
		}
	}
	var fpOK bool
	s.iocFPList, fpOK = loadOrdered("ioc_fp_list")
	if fpOK {
		if cleaned := sanitizeFingerprintEntries(s.iocFPList); !slicesEqual(cleaned, s.iocFPList) {
			s.iocFPList = cleaned
			s.persistList("ioc_fp_list", s.iocFPList)
		}
	}

	// Compile the cached matchers once at load. Rebuilt only when
	// SetAllowlist/SetIOCList are called — what was previously rebuilt
	// per /api/findings request, costing 100-500ms on a hot list.
	s.allowlistM = match.Compile(s.allowlist)
	s.iocM = match.Compile(s.iocList)

	var cfgJSON string
	if err := db.QueryRow(`SELECT config FROM settings WHERE id = 1`).Scan(&cfgJSON); err == nil {
		if err := json.Unmarshal([]byte(cfgJSON), &s.config); err != nil {
			slog.Warn("store: corrupt settings, using defaults", "err", err)
		}
	}

	now := time.Now().Unix()
	if _, err := db.Exec(`DELETE FROM suppressions WHERE expiry <= ?`, now); err != nil {
		slog.Warn("store: prune suppressions", "err", err)
	}
	if rows, err := db.Query(`SELECT target, expiry, detail FROM suppressions`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var target, detail string
			var expUnix int64
			if rows.Scan(&target, &expUnix, &detail) == nil {
				s.suppressions[target] = SuppressionEntry{Expiry: time.Unix(expUnix, 0), Detail: detail}
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("store: incomplete suppressions load — some suppressions may re-fire until next restart", "err", err)
		}
	}

	if rows, err := db.Query(`SELECT id, src, dst, port, finding_type, sensor, detail, created_by, created_at FROM pair_allowlist ORDER BY id`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var e model.PairAllowEntry
			if rows.Scan(&e.ID, &e.Src, &e.Dst, &e.Port, &e.FindingType, &e.Sensor, &e.Detail, &e.CreatedBy, &e.CreatedAt) == nil {
				s.pairAllow = append(s.pairAllow, e)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("store: incomplete pair_allowlist load — some pair allowlists missing until next restart", "err", err)
		}
	}
	s.rebuildPairAllowIdxLocked()

	if rows, err := db.Query(`SELECT id, kind, fingerprint, note, created_by, created_at FROM fingerprint_allowlist ORDER BY id`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var e model.FingerprintAllowEntry
			if rows.Scan(&e.ID, &e.Kind, &e.Fingerprint, &e.Note, &e.CreatedBy, &e.CreatedAt) == nil {
				s.fpAllow = append(s.fpAllow, e)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("store: incomplete fingerprint_allowlist load — some benign fingerprints missing until next restart", "err", err)
		}
	}
	s.rebuildFPAllowIdxLocked()

	s.loadFindings()
	s.loadNotifications()
}

// CheckIntegrity runs PRAGMA integrity_check and returns an error if
// SQLite reports any corruption. Called at startup so a corrupted
// volume (host crash, disk full during write) surfaces immediately
// rather than producing confusing runtime behavior.
func (s *Store) CheckIntegrity() error {
	rows, err := s.db.Query(`PRAGMA integrity_check`)
	if err != nil {
		return fmt.Errorf("integrity_check: %w", err)
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return fmt.Errorf("integrity_check scan: %w", err)
		}
		if msg != "ok" {
			problems = append(problems, msg)
		}
	}
	// A read that aborts mid-iteration must not be mistaken for a clean
	// "ok" result — that would let the startup gate report a corrupt
	// volume as healthy, defeating the whole purpose of the check.
	if err := rows.Err(); err != nil {
		return fmt.Errorf("integrity_check incomplete read: %w", err)
	}
	if len(problems) > 0 {
		return fmt.Errorf("database corruption detected:\n%s", strings.Join(problems, "\n"))
	}
	return nil
}

// loadNotifications rehydrates the in-memory notification queue from
// the persistent table. notifCounter is seeded from MAX(id) so the
// next AddAlarm or SetFindings bell emission assigns an ID strictly
// above every persisted row. Caller must hold s.mu (called from
// InitDB which holds it).
//
// Pre-fix (NEW-98 in the twenty-third audit round) notifications
// lived only in s.notifications + s.notifCounter, both in-memory.
// A server restart wiped every active alarm — finding-based bell
// alarms, sensor heartbeat alarms, feed health alarms. The
// operator's last surface for "what alerted today" disappeared on
// any redeploy. Persisting through SQLite matches the NEW-72
// pattern for Correlations.
func (s *Store) loadNotifications() {
	if s.db == nil {
		return
	}
	rows, err := s.db.Query(`SELECT id, kind, target, detail, finding_id,
	                                severity, type, src_ip, dst_ip, dst_port,
	                                sensor, dismissed
	                         FROM notifications ORDER BY id`)
	if err != nil {
		slog.Warn("store: cannot load notifications", "err", err)
		return
	}
	defer rows.Close()
	var maxID int
	for rows.Next() {
		var n model.Notification
		var dismissed int
		if err := rows.Scan(&n.ID, &n.Kind, &n.Target, &n.Detail, &n.FindingID,
			&n.Severity, &n.Type, &n.SrcIP, &n.DstIP, &n.DstPort, &n.Sensor, &dismissed); err != nil {
			continue
		}
		n.Dismissed = dismissed != 0
		s.notifications = append(s.notifications, n)
		if n.ID > maxID {
			maxID = n.ID
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("store: incomplete notifications load", "err", err)
	}
	s.notifCounter = maxID
}

// persistNotification writes a freshly-emitted notification row.
// Caller must hold s.mu and have already assigned the ID via
// notifCounter. Soft-failure (log + continue) matches the rest of
// the store's persistence pattern: an in-memory state ahead of disk
// is recoverable next time the table is touched; a hard failure on
// every alarm would convert a small reliability issue into a hard
// outage.
func (s *Store) persistNotification(n model.Notification) {
	if s.db == nil {
		return
	}
	_, err := s.db.Exec(`INSERT INTO notifications
		(id, kind, target, detail, finding_id, severity, type, src_ip, dst_ip, dst_port, sensor, dismissed, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		n.ID, n.Kind, n.Target, n.Detail, n.FindingID,
		n.Severity, n.Type, n.SrcIP, n.DstIP, n.DstPort, n.Sensor,
		time.Now().Unix(),
	)
	if err != nil {
		slog.Error("store: persist notification", "id", n.ID, "err", err)
	}
	s.recordPersist("notification", err)
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
		slog.Error("store: persist list begin", "table", tbl, "err", err)
		s.recordPersist("list "+tbl, err)
		return
	}
	if _, err := tx.Exec(`DELETE FROM ` + tbl); err != nil {
		tx.Rollback()
		slog.Error("store: persist list delete", "table", tbl, "err", err)
		s.recordPersist("list "+tbl, err)
		return
	}
	for _, e := range items {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO `+tbl+` (entry) VALUES (?)`, e); err != nil {
			tx.Rollback()
			slog.Error("store: persist list insert", "table", tbl, "err", err)
			s.recordPersist("list "+tbl, err)
			return
		}
	}
	cerr := tx.Commit()
	if cerr != nil {
		slog.Error("store: persist list commit", "table", tbl, "err", cerr)
	}
	s.recordPersist("list "+tbl, cerr)
}

// loadFindings reads persisted findings from SQLite into s.findings.
// Caller must hold s.mu (called from InitDB which holds it).
// Sets s.findingsLoadOK=false on any scan or iteration error so
// saveFindings refuses the destructive DELETE+reinsert on a partial load.
func (s *Store) loadFindings() {
	if s.db == nil {
		s.findingsLoadOK = true
		return
	}
	rows, err := s.db.Query(`SELECT id, type, severity, score, src_ip, dst_ip, dst_port, detail, timestamp, source_file, status, analyst, analyst_note, status_ts, ioc_match, is_new, detected_at, sensor, intervals, ts_data, notes, correlations, ts_score, ds_score, hist_score, dur_score, mean_interval, median_interval, jitter, sample_size, ja3, ja4, top_uris, ts_raw, ts_mm, ts_ent, spectral_rescued, spectral_period, channel, service, orig_bytes, resp_bytes FROM findings ORDER BY id`)
	if err != nil {
		// A query failure here means we can't establish the canonical
		// in-memory state. Starting with findingsLoadOK=false silently
		// disables saveFindings for the entire process lifetime — every
		// analyze run would produce findings that are never persisted.
		// Failing fast surfaces the problem immediately rather than
		// allowing Archer to run in a quietly broken state.
		slog.Error("store: loadFindings failed — cannot start with incomplete findings state", "err", err)
		os.Exit(1)
	}
	defer rows.Close()
	loadOK := true
	for rows.Next() {
		var f model.Finding
		var iocMatch, isNew, spectralRescued int
		var intervals, tsData, notes, correlations, topURIs string
		if err := rows.Scan(&f.ID, &f.Type, &f.Severity, &f.Score, &f.SrcIP, &f.DstIP, &f.DstPort, &f.Detail, &f.Timestamp, &f.SourceFile, &f.Status, &f.Analyst, &f.AnalystNote, &f.StatusTS, &iocMatch, &isNew, &f.DetectedAt, &f.Sensor, &intervals, &tsData, &notes, &correlations, &f.TSScore, &f.DSScore, &f.HistScore, &f.DurScore, &f.MeanInterval, &f.MedianInterval, &f.Jitter, &f.SampleSize, &f.JA3, &f.JA4, &topURIs, &f.TSRaw, &f.TSMultimodal, &f.TSEntropy, &spectralRescued, &f.SpectralPeriod, &f.Channel, &f.Service, &f.OrigBytes, &f.RespBytes); err != nil {
			slog.Error("store: scan finding", "err", err)
			loadOK = false
			continue
		}
		f.IOCMatch = iocMatch == 1
		f.IsNew = isNew == 1
		f.SpectralRescued = spectralRescued == 1
		if intervals != "" {
			if err := json.Unmarshal([]byte(intervals), &f.Intervals); err != nil {
				slog.Warn("store: corrupt finding intervals", "id", f.ID, "err", err)
			}
		}
		if tsData != "" {
			if err := json.Unmarshal([]byte(tsData), &f.TSData); err != nil {
				slog.Warn("store: corrupt finding ts_data", "id", f.ID, "err", err)
			}
		}
		if notes != "" {
			if err := json.Unmarshal([]byte(notes), &f.Notes); err != nil {
				slog.Warn("store: corrupt finding notes", "id", f.ID, "err", err)
			}
		}
		// NEW-72: Correlations persists across restarts so the "+N corr"
		// chip stays visible without requiring a fresh analysis run to
		// repopulate. Empty string (the schema default for pre-0010
		// rows) decodes to a nil slice — matches the pre-feature shape.
		if correlations != "" {
			if err := json.Unmarshal([]byte(correlations), &f.Correlations); err != nil {
				slog.Warn("store: corrupt finding correlations", "id", f.ID, "err", err)
			}
		}
		// top_uris (migration 0020): the HTTP-beacon path footprint.
		// Empty string (schema default for pre-0020 rows / non-HTTP
		// findings) decodes to a nil slice — the pre-feature shape.
		if topURIs != "" {
			if err := json.Unmarshal([]byte(topURIs), &f.TopURIs); err != nil {
				slog.Warn("store: corrupt finding top_uris", "id", f.ID, "err", err)
			}
		}
		s.findings = append(s.findings, f)
	}
	if err := rows.Err(); err != nil {
		slog.Error("store: load findings iteration error", "err", err)
		loadOK = false
	}
	s.findingsLoadOK = loadOK
	s.rebuildFindingsIdx()
}

// saveFindings replaces all rows in the findings table with s.findings.
// Caller must hold s.mu.
func (s *Store) saveFindings() {
	if s.db == nil {
		return
	}
	// Record (or clear) the persistence-degraded flag based on the outcome
	// of this save. perr stays nil only if the commit succeeds.
	var perr error
	defer func() {
		if perr != nil {
			s.persistErr = perr.Error()
		} else {
			s.persistErr = ""
		}
	}()
	if !s.findingsLoadOK {
		slog.Warn("store: saveFindings refused — initial load was incomplete; findings not overwritten")
		perr = fmt.Errorf("initial load incomplete; findings not overwritten")
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		slog.Error("store: save findings begin", "err", err)
		perr = fmt.Errorf("begin: %w", err)
		return
	}
	if _, err := tx.Exec(`DELETE FROM findings`); err != nil {
		tx.Rollback()
		slog.Error("store: save findings delete", "err", err)
		perr = fmt.Errorf("delete: %w", err)
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO findings (id, type, severity, score, src_ip, dst_ip, dst_port, detail, timestamp, source_file, status, analyst, analyst_note, status_ts, ioc_match, is_new, detected_at, sensor, intervals, ts_data, notes, correlations, ts_score, ds_score, hist_score, dur_score, mean_interval, median_interval, jitter, sample_size, ja3, ja4, top_uris, ts_raw, ts_mm, ts_ent, spectral_rescued, spectral_period, channel, service, orig_bytes, resp_bytes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		slog.Error("store: save findings prepare", "err", err)
		perr = fmt.Errorf("prepare: %w", err)
		return
	}
	defer stmt.Close()
	for _, f := range s.findings {
		intervals, _ := json.Marshal(f.Intervals)
		tsData, _ := json.Marshal(f.TSData)
		notes, _ := json.Marshal(f.Notes)
		// NEW-72: persist Correlations alongside the other in-memory
		// per-finding slices. A nil slice marshals to "null" which the
		// load path handles correctly (json.Unmarshal of "null" into
		// *[]int sets the slice to nil); an empty slice marshals to
		// "[]" which decodes back to an empty (non-nil) slice. Both
		// shapes are semantically equivalent for the chip-rendering
		// logic.
		correlations, _ := json.Marshal(f.Correlations)
		topURIs, _ := json.Marshal(f.TopURIs)
		iocMatch, isNew := 0, 0
		if f.IOCMatch {
			iocMatch = 1
		}
		if f.IsNew {
			isNew = 1
		}
		spectralRescued := 0
		if f.SpectralRescued {
			spectralRescued = 1
		}
		if _, err := stmt.Exec(
			f.ID, f.Type, string(f.Severity), f.Score, f.SrcIP, f.DstIP, f.DstPort, f.Detail, f.Timestamp, f.SourceFile,
			string(f.Status), f.Analyst, f.AnalystNote, f.StatusTS, iocMatch, isNew, f.DetectedAt, f.Sensor,
			string(intervals), string(tsData), string(notes), string(correlations),
			f.TSScore, f.DSScore, f.HistScore, f.DurScore, f.MeanInterval, f.MedianInterval, f.Jitter, f.SampleSize,
			f.JA3, f.JA4, string(topURIs),
			f.TSRaw, f.TSMultimodal, f.TSEntropy, spectralRescued, f.SpectralPeriod, f.Channel, f.Service,
			f.OrigBytes, f.RespBytes,
		); err != nil {
			tx.Rollback()
			slog.Error("store: save findings insert", "err", err)
			perr = fmt.Errorf("insert: %w", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		slog.Error("store: save findings commit", "err", err)
		perr = fmt.Errorf("commit: %w", err)
	}
}

// PersistenceError returns the message from the most recent authoritative-state
// write, or "" if the last one succeeded. The server layer surfaces this
// (analyze-status endpoint, SSE status event) so a persistent write failure
// is operator-visible rather than only living in a log line that a container
// restart discards.
func (s *Store) PersistenceError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistErr
}

// recordPersist sets or clears the persistence-degraded flag from the outcome
// of an authoritative-state write. saveFindings was the only path that surfaced
// its failures; the curated lists (allowlist/IOC), config, suppressions, and
// notifications logged-and-returned, so a failed write on any of them diverged
// in-memory state from disk silently — analyst-curated state that vanishes on
// the next restart with no signal. Every persist path now routes its result
// here. SQLite's single-file store fails all-or-nothing (disk full, DB
// locked/closed), so a success on any path is a reliable "writable again"
// signal that clears the flag. Caller holds s.mu (write).
func (s *Store) recordPersist(op string, err error) {
	if err != nil {
		s.persistErr = op + ": " + err.Error()
		return
	}
	s.persistErr = ""
}

func (s *Store) GetFindings() []model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

// bellExcludedTypes never generate notifications, whatever their score.
// See the gate in setFindingsImpl for the per-type rationale.
var bellExcludedTypes = map[string]bool{
	"Host Risk Score":          true,
	"Suspicious File Download": true,
	"Off-Hours Transfer":       true,
}

// SetFindings merges new analysis results with existing findings, carries over
// analyst annotations for re-detected fingerprints, persists to SQLite, and
// returns any new notifications generated. Use this for full-pipeline
// analyses — the manual Analyze button, watch's daily full pass, JSON
// import — where the rollup-regeneration phases (aggregateRisk,
// correlateFindings) have run and any preserved-but-not-regenerated
// rollup row is genuinely stale.
//
// For TI-only incrementals (watch's between-full ticks, the archive
// admin scan) use SetFindingsIncremental instead. Calling SetFindings
// on a TI-only input would silently purge every Correlated Activity
// and Host Risk Score row in the store, because the rollup phases
// didn't run this pass and their fingerprints are absent from the new
// set — the IsRollupType purge below treats absence as "the rollup is
// stale" rather than "the rollup wasn't re-evaluated."
func (s *Store) SetFindings(findings []model.Finding) []model.Notification {
	return s.setFindingsImpl(findings, true, true)
}

// SetFindingsIncremental is the partial-pipeline form of SetFindings.
// Same merge / ID / Correlations-translation semantics, but skips the
// IsRollupType purge — existing Correlated Activity and Host Risk
// Score findings are preserved through the call instead of dropped.
//
// Callers are paths that don't run the rollup-regeneration phases:
//   - watch's incremental TI tick (AnalyzeTIOnly between full passes)
//   - the admin archive scan endpoint (AnalyzeTIOnly over /data/archive)
//
// The rollup data may be stale relative to the just-emitted TI Hits
// (e.g., a CA's score reflects yesterday's contributor scores, not
// today's). That's acceptable: rollups refresh on the next full pass,
// and the analyst gets continuity between full passes instead of a
// rollup hole every 6 hours.
func (s *Store) SetFindingsIncremental(findings []model.Finding) []model.Notification {
	return s.setFindingsImpl(findings, false, true)
}

// setFindingsImpl is the shared body for both public entry points.
// purgeStaleRollups gates the IsRollupType branch in the historical-
// preserve loop — true for full passes (the original behavior), false
// for TI-only incrementals where rollup absence means "not evaluated
// this pass" rather than "no longer valid."
func (s *Store) setFindingsImpl(findings []model.Finding, purgeStaleRollups bool, emitNotifications bool) []model.Notification {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Defensive in-batch fingerprint dedup. Two findings emitted with
	// identical Fingerprint(Type, SrcIP, DstIP, DstPort) in a single
	// run represent the same logical detection — keeping both would
	// either persist as visually-duplicate rows (fp-not-in-DB case) or
	// blow up saveFindings with a UNIQUE primary-key collision
	// (fp-in-DB case, because the assignment loop below returns the
	// same old.ID for both). The TI Hit emit path is the documented
	// offender (multiple TI sources can flag the same dst), but this
	// guard catches any future detector that emits the same logical
	// finding twice without crashing the entire pipeline. Highest-
	// scored row wins; ties go to the first-seen index to keep
	// downstream ID assignment stable across re-runs on identical input.
	//
	// droppedToWinner maps a dropped finding's fresh ID to the winner's
	// fresh ID. After the main ID-assignment loop builds freshToPersisted,
	// we extend it with these mappings so Correlations references to
	// dropped findings resolve to the winner's persisted ID instead of
	// being silently dropped.
	var droppedToWinner map[int]int
	if len(findings) > 1 {
		bestByFP := make(map[model.Fingerprint]int, len(findings))
		for i := range findings {
			fp := findings[i].Fingerprint()
			if j, ok := bestByFP[fp]; ok && findings[j].Score >= findings[i].Score {
				continue
			}
			bestByFP[fp] = i
		}
		if len(bestByFP) < len(findings) {
			keep := make([]bool, len(findings))
			for _, i := range bestByFP {
				keep[i] = true
			}
			droppedToWinner = make(map[int]int)
			for i := range findings {
				if !keep[i] {
					fp := findings[i].Fingerprint()
					droppedToWinner[findings[i].ID] = findings[bestByFP[fp]].ID
				}
			}
			deduped := make([]model.Finding, 0, len(bestByFP))
			for i := range findings {
				if keep[i] {
					deduped = append(deduped, findings[i])
				}
			}
			findings = deduped
		}
	}

	// Index existing findings by fingerprint so we can carry over analyst work,
	// and track the highest existing ID so newly-fingerprinted findings can be
	// numbered above it. Without this guard, the analyzer's per-run sequential
	// IDs (1, 2, 3, …) collide with preserved historical findings that share
	// those low IDs — saveFindings then fails the UNIQUE constraint on the
	// findings.id primary key. The collision becomes pervasive whenever a
	// detection-semantics change (e.g. v0.7.0's TI Hit type split) means many
	// old fingerprints don't match any new finding and get preserved with
	// their original IDs.
	//
	// historicalIDs is the set of persisted IDs currently in s.findings.
	// Consulted by the Correlations translation pass (NEW-91) to
	// distinguish "this ID is already a valid persisted ID, leave it
	// alone" from "this ID is a fresh per-run ID, translate it." The
	// historical-union path in correlate.go puts persisted IDs into
	// this-run findings' Correlations slices (via findingsProvider);
	// without this set, NEW-71's freshToPersisted lookup would drop
	// every historical contributor reference.
	existing := make(map[model.Fingerprint]model.Finding, len(s.findings))
	historicalIDs := make(map[int]bool, len(s.findings))
	maxExistingID := 0
	for _, f := range s.findings {
		existing[f.Fingerprint()] = f
		historicalIDs[f.ID] = true
		if f.ID > maxExistingID {
			maxExistingID = f.ID
		}
	}

	// freshToPersisted maps the analyzer's per-run a.nextID++ IDs to
	// the IDs that survive this SetFindings call. correlate.go
	// populates Finding.Correlations with the per-run fresh IDs at
	// emit time — those references go stale the moment SetFindings
	// rewrites a finding's ID via fingerprint match. NEW-71: walk
	// once to assign IDs and build the map, then walk again to
	// translate every Correlations slice through it. Without this,
	// an analyst seeing a finding with correlations=[5,8] via /api/
	// findings has no way to follow those references — fresh IDs 5
	// and 8 either don't exist post-translation or, worse, collide
	// with unrelated findings from prior runs that happened to land
	// on the same low IDs.
	freshToPersisted := make(map[int]int, len(findings))

	// detectedNow stamps a fingerprint's first appearance in the store.
	// Carried forward unchanged on every later match (like the ID), so it
	// is the durable anchor for the per-user "new since you last looked"
	// count — independent of the per-run IsNew flag this loop overwrites.
	detectedNow := time.Now().Unix()
	// carryDetectedAt returns the old finding's first-detected time, or
	// detectedNow if it's missing (defensive — migration 0029 backfills
	// every existing row, so a zero here would only arise from a row that
	// somehow escaped it; treating it as new-now is the safe fallback).
	carryDetectedAt := func(old model.Finding) int64 {
		if old.DetectedAt > 0 {
			return old.DetectedAt
		}
		return detectedNow
	}

	newFPSet := make(map[model.Fingerprint]bool, len(findings))
	nextNewID := maxExistingID
	for i := range findings {
		fp := findings[i].Fingerprint()
		newFPSet[fp] = true
		freshID := findings[i].ID
		if old, ok := existing[fp]; ok {
			// Carry the stable ID forward along with analyst state — external
			// references (open browser tabs, copied PCAP-filter URLs, etc.)
			// stay valid across re-analyses.
			findings[i].ID = old.ID
			findings[i].Status = old.Status
			findings[i].Analyst = old.Analyst
			findings[i].AnalystNote = old.AnalystNote
			findings[i].StatusTS = old.StatusTS
			findings[i].Notes = old.Notes
			findings[i].IsNew = false
			findings[i].DetectedAt = carryDetectedAt(old)
		} else if fp.Type == "HTTP Beacon" && (fp.Hostname != "" || fp.URI != "") {
			// Upgrade-compat path for HTTP Beacon: Hostname and URI were
			// added to Fingerprint after Sensor was. Old rows fall into two
			// shapes depending on which version the operator is upgrading from:
			//   post-Sensor, pre-host/URI: {Type, SrcIP, DstIP, DstPort, Sensor, "", ""}
			//   pre-Sensor, pre-host/URI:  {Type, SrcIP, DstIP, DstPort, "", "", ""}
			// Try both. The first match wins; its row is marked consumed so it
			// isn't re-preserved as an orphan duplicate alongside the new row.
			noHostFP := fp
			noHostFP.Hostname = ""
			noHostFP.URI = ""
			noSensorFP := noHostFP
			noSensorFP.Sensor = ""
			var matched bool
			for _, tryFP := range [2]model.Fingerprint{noHostFP, noSensorFP} {
				if old, ok := existing[tryFP]; ok {
					findings[i].ID = old.ID
					findings[i].Status = old.Status
					findings[i].Analyst = old.Analyst
					findings[i].AnalystNote = old.AnalystNote
					findings[i].StatusTS = old.StatusTS
					findings[i].Notes = old.Notes
					findings[i].IsNew = false
					findings[i].DetectedAt = carryDetectedAt(old)
					newFPSet[tryFP] = true
					// Consume the legacy entry so a second new row for the
					// same src/dst/port/sensor but a different host/URI
					// doesn't inherit the same old ID and collide on INSERT.
					delete(existing, tryFP)
					matched = true
					break
				}
			}
			if !matched {
				nextNewID++
				findings[i].ID = nextNewID
				findings[i].IsNew = emitNotifications
				findings[i].DetectedAt = detectedNow
			}
		} else if fp.Sensor != "" {
			// Upgrade-compat path: a finding that previously had Sensor=""
			// (before sensor was included in Fingerprint) won't match the
			// new key. Try the zero-sensor variant so analyst notes carry
			// forward across the first analysis after upgrade and the old
			// row isn't preserved as an orphan duplicate.
			zeroFP := fp
			zeroFP.Sensor = ""
			if old, ok := existing[zeroFP]; ok {
				findings[i].ID = old.ID
				findings[i].Status = old.Status
				findings[i].Analyst = old.Analyst
				findings[i].AnalystNote = old.AnalystNote
				findings[i].StatusTS = old.StatusTS
				findings[i].Notes = old.Notes
				findings[i].IsNew = false
				findings[i].DetectedAt = carryDetectedAt(old)
				newFPSet[zeroFP] = true
				delete(existing, zeroFP) // prevent a second new row from inheriting the same old ID
			} else {
				nextNewID++
				findings[i].ID = nextNewID
				findings[i].IsNew = emitNotifications
				findings[i].DetectedAt = detectedNow
			}
		} else {
			// Truly new fingerprint — assign an ID guaranteed above any
			// preserved historical ID so the saveFindings INSERT can't
			// collide.
			nextNewID++
			findings[i].ID = nextNewID
			findings[i].IsNew = emitNotifications
			findings[i].DetectedAt = detectedNow
		}
		freshToPersisted[freshID] = findings[i].ID
	}

	// Extend freshToPersisted for findings dropped by the in-batch dedup
	// above. Without this, a Correlations reference to a dropped finding's
	// fresh ID is neither in freshToPersisted nor in historicalIDs, so the
	// translation pass silently drops it — the +N chip undercounts and the
	// sibling-jump lands nowhere. Map the dropped ID to its winner's
	// persisted ID so the reference survives translation.
	for droppedID, winnerFreshID := range droppedToWinner {
		if persistedID, ok := freshToPersisted[winnerFreshID]; ok {
			freshToPersisted[droppedID] = persistedID
		}
	}

	// Translate Correlations references on this-run findings. Two
	// classes of ID can appear here:
	//
	//  1. Fresh per-run IDs from a.nextID++ (this-run contributors).
	//     These need translation through freshToPersisted to recover
	//     the post-rewrite persisted ID. NEW-71.
	//
	//  2. Persisted IDs from the historical-union path (when
	//     correlate.go consulted findingsProvider, contributors that
	//     existed in s.findings but didn't re-fire this run end up
	//     in Correlations slices with their persisted IDs already in
	//     hand). These need pass-through, NOT translation —
	//     translating them via freshToPersisted either drops them
	//     silently (the common case, when the historical ID isn't in
	//     the small 1..n fresh-ID range) or maps them to an unrelated
	//     finding's persisted ID (the rarer collision case). NEW-91
	//     from the twenty-first audit round.
	//
	// historicalIDs is consulted as the secondary lookup so the two
	// classes can coexist in the same slice. An ID that's neither in
	// freshToPersisted nor in historicalIDs is dropped — defensive
	// against dangling references from a bugged caller.
	//
	// Preserved historical findings are NOT touched here: their
	// Correlations slices were translated by the SetFindings run
	// that originally persisted them and remain in terms of
	// persisted IDs already.
	for i := range findings {
		if len(findings[i].Correlations) == 0 {
			continue
		}
		translated := make([]int, 0, len(findings[i].Correlations))
		for _, id := range findings[i].Correlations {
			if id < 0 {
				// Negative sentinel from correlate.go: historical-only
				// contributor. Negate to recover the persisted ID (NEW-91
				// case B2 — positive historical IDs that equal a fresh ID
				// would be mis-translated via freshToPersisted without this
				// branch).
				absID := -id
				if historicalIDs[absID] {
					translated = append(translated, absID)
				}
			} else if persistedID, ok := freshToPersisted[id]; ok {
				translated = append(translated, persistedID)
			} else if historicalIDs[id] {
				translated = append(translated, id)
			}
		}
		findings[i].Correlations = translated
	}

	// Preserve all historical findings that weren't regenerated in this run.
	// A finding reflected a real observation at the time it was detected, and
	// remains valid even when its source logs are later archived or rotated
	// out of /logs. Removal is explicit-only — admin-driven via archive
	// pruning (PruneFindingsOnArchive) or manual deletion — never a side
	// effect of re-analysis.
	//
	// Roll-up types are the exception: Host Risk Score and Correlated
	// Activity have authoritative regeneration phases in the analyzer
	// (aggregateRisk, correlateFindings) and are derived from the other
	// findings. Preserving a roll-up whose contributors are all gone — or
	// whose contributor set no longer meets the roll-up's threshold —
	// leaves a stale row with no defensible source. The NEW-67 union fix
	// closed the common case for HRS (host quiet this run but historical
	// detections still in store), but the narrow case where every
	// contributor has been archived or deleted still left orphans. The
	// IsRollupType filter here closes both the HRS narrow case and the
	// same shape for Correlated Activity introduced alongside it.
	for fp, old := range existing {
		if newFPSet[fp] {
			continue
		}
		if purgeStaleRollups && model.IsRollupType(old.Type) {
			// Full pass that didn't regenerate this rollup — drop it.
			continue
		}
		old.IsNew = false
		findings = append(findings, old)
	}

	s.findings = findings
	s.rebuildFindingsIdx()
	s.saveFindings()
	s.saveBeaconHistory(findings, newFPSet)

	var newNotifs []model.Notification
	if !emitNotifications {
		return newNotifs
	}
	for _, f := range findings {
		// Bell-excluded types never notify regardless of score.
		// Host Risk Score is an aggregate per-host roll-up that lives in
		// the Hosts tab, not a discrete network event — the underlying
		// network detections that pushed the host's score over the line
		// have already generated their own notifications, and a "jump to
		// finding" tap would land on a row the Findings tab no longer
		// renders. Suspicious File Download and Off-Hours Transfer are
		// deliberately demoted: delivery-stage and exfil-timing context
		// for the hunt list, not bell-grade C2 conviction. Their scores
		// (72 / ≤78) sit under the 95 gate today; the explicit exclusion
		// keeps that demotion a contract a future score change can't
		// silently undo.
		if bellExcludedTypes[f.Type] {
			continue
		}
		// Bell threshold: f.Score >= 95. v0.17.0 first cut this at
		// `>= 99`, which over-corrected — the discrete-tier
		// detectors (URLhaus 96, Malicious JA3 95, FeodoTracker 97)
		// top out below 99 by design, so externally-validated
		// high-confidence indicators stayed silent. NEW-99 in the
		// twenty-third audit round: 95 captures the top of both the
		// discrete-tier population AND the computed-score
		// population (Beacon/Correlated Activity hit 95+ when
		// the underlying signal is strong) without arbitrary
		// compression of either. See CHANGELOG v0.17.1 for the
		// enumerated tier (which specific detectors ring vs don't);
		// the enumeration locks the contract so a future detector
		// score change can't silently shift bell semantics.
		// Sensor and feed alarms (Kind != "finding") bypass this
		// gate entirely via AddAlarm.
		if f.IsNew && f.Score >= 95 {
			// Don't fire the bell for findings the operator has chosen
			// to hide. filterFindings (findings_filter.go) excludes
			// allowlisted and currently-suppressed src/dst at read
			// time, so a notification for such a finding rings the
			// bell but the Jump button can't land on a row — every
			// list endpoint hides it. The operator sees an alert they
			// already told Archer not to surface. Same matcher used
			// at filter time, evaluated under the existing write lock.
			// NEW-111.
			if s.isHiddenLocked(f.SrcIP, f.DstIP) || s.isPairAllowedLocked(f.SrcIP, f.DstIP, f.DstPort, f.Type, f.Sensor) {
				continue
			}
			s.notifCounter++
			n := model.Notification{
				ID:        s.notifCounter,
				Kind:      "finding",
				FindingID: f.ID,
				Severity:  string(f.Severity),
				Type:      f.Type,
				SrcIP:     f.SrcIP,
				DstIP:     f.DstIP,
				DstPort:   f.DstPort,
				Sensor:    f.Sensor,
			}
			s.notifications = append(s.notifications, n)
			s.persistNotification(n)
			newNotifs = append(newNotifs, n)
		}
	}
	return newNotifs
}

// UpdateFinding mutates a finding's status/analyst/note/status_ts and
// returns the pre-mutation snapshot so callers writing an audit-log
// row can record the actual transition rather than a separate
// GetFinding-then-UpdateFinding pair (which races against concurrent
// PATCHes on the same finding — the on-disk state stays correct but
// the audit row's BeforeValue could otherwise reflect a stale read).
// The snapshot is taken under the same mutex as the mutation.
// Audit 2026-05-10 NEW-36.
func (s *Store) UpdateFinding(id int, status model.Status, analyst, note, statusTS string) (model.Finding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.findingsIdx[id]
	if !ok {
		return model.Finding{}, false, nil
	}
	before := s.findings[i]
	// Write to DB before updating in-memory so a crash between the two
	// leaves the DB as the authoritative state. On restart, loadFindings
	// reloads the DB value — if we updated memory first and then crashed,
	// the analyst's change would be silently lost.
	if s.db != nil {
		if _, err := s.db.Exec(`UPDATE findings SET status=?, analyst=?, analyst_note=?, status_ts=? WHERE id=?`,
			string(status), analyst, note, statusTS, id); err != nil {
			slog.Error("store: update finding", "id", id, "err", err)
			return model.Finding{}, true, err
		}
	}
	s.findings[i].Status = status
	s.findings[i].Analyst = analyst
	s.findings[i].AnalystNote = note
	s.findings[i].StatusTS = statusTS
	return before, true, nil
}

func (s *Store) GetFinding(id int) (model.Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.findingsIdx[id]
	if !ok {
		return model.Finding{}, false
	}
	return s.findings[i], true
}

// BulkUpdateStatus applies a status transition to many findings in one
// transaction under a single lock — the batched form of UpdateFinding, used by
// the bulk ack/escalate/dismiss endpoint. It keeps UpdateFinding's DB-before-
// memory ordering (a crash mid-update leaves the DB authoritative) but does one
// Begin/Commit and one lock acquisition instead of N round-trips. Findings that
// aren't present, or are already in the target status, are skipped. Returns the
// pre-change snapshots (so the handler can write an accurate audit row) and the
// count actually changed. On any DB failure nothing is applied in memory and
// the persistence-degraded flag is set.
func (s *Store) BulkUpdateStatus(ids []int, status model.Status, analyst, note, statusTS string) ([]model.Finding, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idxs := make([]int, 0, len(ids))
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		i, ok := s.findingsIdx[id]
		if !ok || seen[id] || s.findings[i].Status == status {
			continue
		}
		seen[id] = true
		idxs = append(idxs, i)
	}
	if len(idxs) == 0 {
		return nil, 0
	}

	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			slog.Error("store: bulk status begin", "err", err)
			s.recordPersist("bulk status", err)
			return nil, 0
		}
		stmt, err := tx.Prepare(`UPDATE findings SET status=?, analyst=?, analyst_note=?, status_ts=? WHERE id=?`)
		if err != nil {
			tx.Rollback()
			slog.Error("store: bulk status prepare", "err", err)
			s.recordPersist("bulk status", err)
			return nil, 0
		}
		defer stmt.Close()
		for _, i := range idxs {
			if _, err := stmt.Exec(string(status), analyst, note, statusTS, s.findings[i].ID); err != nil {
				tx.Rollback()
				slog.Error("store: bulk status exec", "id", s.findings[i].ID, "err", err)
				s.recordPersist("bulk status", err)
				return nil, 0
			}
		}
		if err := tx.Commit(); err != nil {
			slog.Error("store: bulk status commit", "err", err)
			s.recordPersist("bulk status", err)
			return nil, 0
		}
		s.recordPersist("bulk status", nil)
	}

	befores := make([]model.Finding, 0, len(idxs))
	for _, i := range idxs {
		befores = append(befores, s.findings[i])
		s.findings[i].Status = status
		s.findings[i].Analyst = analyst
		s.findings[i].AnalystNote = note
		s.findings[i].StatusTS = statusTS
	}
	return befores, len(befores)
}

// CountBeaconsWithJA3 returns how many beacon findings other than
// excludeID carry the same (non-empty) JA3 — the "matched N other
// beacons in this dataset" signal the detail pane renders. An empty
// ja3 returns 0 (no fingerprint, nothing to correlate). In-memory
// scan under the same RLock the rest of the read path uses; the
// finding set is already resident, so this is cheap relative to the
// per-request detail render that calls it.
// Fingerprint-concern thresholds. Global + documented in code (not per-deployment
// Settings), matching Archer's calibration-knob convention.
const (
	// fpRareDstFanoutMax: a TLS client fingerprint reaching this many distinct
	// destinations or fewer is "rare" — an implant phones a tiny C2 set, a
	// browser/SDK fingerprint reaches thousands.
	fpRareDstFanoutMax = 8
	// fpClusterMinSrcs: this many distinct internal hosts sharing one rare
	// fingerprint is the cross-host implant-family signal.
	fpClusterMinSrcs = 2
)

// SetFingerprintPrevalence stores the latest TLS-fingerprint prevalence snapshot
// from a full analysis pass. Called by the server right after Analyze; consulted
// by FingerprintConcern at read time.
func (s *Store) SetFingerprintPrevalence(ja4, ja3 map[string]model.FingerprintStat) {
	s.mu.Lock()
	s.fpJA4 = ja4
	s.fpJA3 = ja3
	s.mu.Unlock()
}

// FingerprintConcern derives the rarity/cross-host-cluster concern for a beacon's
// TLS client fingerprint from the prevalence snapshot. JA4 is preferred; a
// JA3-only match is capped one tier lower because generic Go/Python/Rust stacks
// collide on a single JA3. Returns a severity-style level
// ("critical"/"high"/"medium"/"low"/"none") for the detail-pane row colour and a
// human-readable summary. Both "" when no fingerprint resolves or the snapshot is
// empty (no analysis yet this process). Read under RLock like the sibling counts.
func (s *Store) FingerprintConcern(ja4, ja3 string) (level, detail string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stat model.FingerprintStat
	var kind string
	var ok bool
	if ja4 != "" {
		if stat, ok = s.fpJA4[ja4]; ok {
			kind = "ja4"
		}
	}
	if !ok && ja3 != "" {
		if stat, ok = s.fpJA3[ja3]; ok {
			kind = "ja3"
		}
	}
	if !ok {
		return "", ""
	}
	level, _, detail = fingerprintConcernLevel(kind, stat)
	return level, detail
}

// fingerprintConcernLevel derives the concern level and human summary for one
// TLS client fingerprint from its prevalence. kind is "ja4" or "ja3"; a JA3
// match is capped one tier lower than the equivalent JA4 because generic
// Go/Python/Rust stacks collide on a single JA3. Returns two strings: reason is
// the count-free qualitative judgment ("why it's flagged"); detail is the same
// judgment with the prevalence counts folded in. The TLS Fingerprints modal
// uses reason (it has its own Hosts/Dest/Conns columns, so repeating the counts
// in prose is noise); the finding detail-pane "FP rarity" badge uses detail
// (one text row, no columns, so it needs the numbers inline). Both come from
// the same branch so the two surfaces can't drift. Returns "none" for common
// shapes.
func fingerprintConcernLevel(kind string, stat model.FingerprintStat) (level, reason, detail string) {
	rare := stat.Dsts <= fpRareDstFanoutMax
	clustered := stat.SrcHosts >= fpClusterMinSrcs
	if !rare {
		return "none",
			"Common (browser/SDK shape)",
			fmt.Sprintf("common — %d conns across %d dsts (browser/SDK shape)", stat.Conns, stat.Dsts)
	}
	// Rare. Rank by JA4-vs-JA3 confidence and cross-host clustering.
	hostWord := "single host"
	if clustered {
		hostWord = fmt.Sprintf("shared by %d internal hosts", stat.SrcHosts)
	}
	detail = fmt.Sprintf("rare — %s · %d conns, %d dst(s)", hostWord, stat.Conns, stat.Dsts)
	switch {
	case kind == "ja4" && clustered:
		level, reason = "critical", "Rare client, clustered across hosts"
	case kind == "ja4":
		level, reason = "high", "Rare client, single host"
	case kind == "ja3" && clustered:
		level, reason = "medium", "Rare, clustered — JA3 only, collision possible"
		detail += " (JA3 only — generic-stack collision possible)"
	default: // ja3, single host
		level, reason = "low", "Rare, single host — JA3 only, lower confidence"
		detail += " (JA3 only — lower confidence)"
	}
	return level, reason, detail
}

// fpLevelRank maps a concern level to a sort/threshold weight (higher = more
// severe). The TLS Fingerprints inventory keeps only rows that rank medium or
// higher (or are known-bad) — common and low-confidence-single-host shapes are
// excluded so the surface stays a hunt list, not a full TLS census.
func fpLevelRank(level string) int {
	switch level {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

// FingerprintInventory returns the high-signal TLS client fingerprints from the
// latest prevalence snapshot, ranked by severity. A fingerprint qualifies if it
// matches a known-bad C2 list (badJA4/badJA3 — always ranked critical) or its
// rarity/cross-host concern reaches medium or higher. The known-bad maps are
// passed in (the analysis package's tables) so the store doesn't import
// analysis. FindingCount counts every resident finding carrying the
// fingerprint, so a known-bad row pivots onto its Malicious JA3/JA4 finding.
// The snapshot is in-memory and rebuilt each full analysis pass; before the
// first pass of a process it is empty and this returns no rows.
func (s *Store) FingerprintInventory(badJA4, badJA3 map[string]string) []model.FingerprintRow {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ja3Count := map[string]int{}
	ja4Count := map[string]int{}
	for i := range s.findings {
		f := &s.findings[i]
		if f.JA3 != "" {
			ja3Count[f.JA3]++
		}
		if f.JA4 != "" {
			ja4Count[f.JA4]++
		}
	}

	rows := make([]model.FingerprintRow, 0)
	build := func(kind string, snap map[string]model.FingerprintStat, bad map[string]string, counts map[string]int) {
		for fp, stat := range snap {
			level, reason, _ := fingerprintConcernLevel(kind, stat)
			label, isBad := bad[fp]
			if isBad {
				level = "critical"
				reason = "Known C2 fingerprint"
			} else if s.fpAllowIdx[fpAllowKey(kind, fp)] {
				// Analyst marked this benign — drop from the wall. Known-bad
				// is checked first above, so a C2 fingerprint can never be
				// hidden this way.
				continue
			} else if fpLevelRank(level) == 0 {
				continue
			}
			rows = append(rows, model.FingerprintRow{
				Fingerprint:  fp,
				Kind:         kind,
				Level:        level,
				KnownBad:     isBad,
				Label:        label,
				Conns:        stat.Conns,
				SrcHosts:     stat.SrcHosts,
				Dsts:         stat.Dsts,
				FindingCount: counts[fp],
				Detail:       reason,
			})
		}
	}
	build("ja4", s.fpJA4, badJA4, ja4Count)
	build("ja3", s.fpJA3, badJA3, ja3Count)

	sort.Slice(rows, func(i, j int) bool {
		if ri, rj := fpLevelRank(rows[i].Level), fpLevelRank(rows[j].Level); ri != rj {
			return ri > rj
		}
		if rows[i].SrcHosts != rows[j].SrcHosts {
			return rows[i].SrcHosts > rows[j].SrcHosts
		}
		if rows[i].Conns != rows[j].Conns {
			return rows[i].Conns > rows[j].Conns
		}
		return rows[i].Fingerprint < rows[j].Fingerprint
	})
	return rows
}

func (s *Store) CountBeaconsWithJA3(ja3 string, excludeID int) int {
	if ja3 == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for i := range s.findings {
		f := &s.findings[i]
		if f.ID != excludeID && f.JA3 == ja3 && model.IsBeaconType(f.Type) {
			n++
		}
	}
	return n
}

// CountBeaconsWithJA4 returns how many beacon findings other than
// excludeID carry the same (non-empty) JA4. Same semantics as
// CountBeaconsWithJA3; available when sensors run the Zeek JA4+ plugin.
func (s *Store) CountBeaconsWithJA4(ja4 string, excludeID int) int {
	if ja4 == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for i := range s.findings {
		f := &s.findings[i]
		if f.ID != excludeID && f.JA4 == ja4 && model.IsBeaconType(f.Type) {
			n++
		}
	}
	return n
}

func (s *Store) AddNote(id int, note model.Note) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.findingsIdx[id]
	if !ok {
		return false, nil
	}
	newNotes := append(s.findings[i].Notes, note)
	if s.db != nil {
		notesJSON, _ := json.Marshal(newNotes)
		if _, err := s.db.Exec(`UPDATE findings SET notes=? WHERE id=?`, string(notesJSON), id); err != nil {
			slog.Error("store: add note to finding", "id", id, "err", err)
			return true, err
		}
	}
	s.findings[i].Notes = newNotes
	return true, nil
}

// AddNoteIfAbsent appends note only if no existing note on the finding has
// the same Author and Text. It exists for idempotent system enrichment
// notes (TI cross-annotation) that re-fire across analysis runs: a new
// internal host first contacting an already-flagged dst is IsNew=true and
// re-enters the cross-note loop, which would otherwise stamp another copy
// of an identical note on every related finding. Timestamp is deliberately
// excluded from the comparison so a later run's note still dedups.
// Returns (found, added, err): found=finding exists, added=note appended.
func (s *Store) AddNoteIfAbsent(id int, note model.Note) (found, added bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.findingsIdx[id]
	if !ok {
		return false, false, nil
	}
	for _, n := range s.findings[i].Notes {
		if n.Author == note.Author && n.Text == note.Text {
			return true, false, nil
		}
	}
	newNotes := append(s.findings[i].Notes, note)
	if s.db != nil {
		notesJSON, _ := json.Marshal(newNotes)
		if _, err := s.db.Exec(`UPDATE findings SET notes=? WHERE id=?`, string(notesJSON), id); err != nil {
			slog.Error("store: add note to finding", "id", id, "err", err)
			return true, false, err
		}
	}
	s.findings[i].Notes = newNotes
	return true, true, nil
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
			slog.Error("store: persist settings", "err", err)
		}
	}
	s.mu.Unlock()
}

// SetConfigPreservingRuntime persists an admin-edited config while keeping the
// worker-owned runtime/telemetry fields (archive-run results, the two analysis
// timestamps, the dataset fingerprint) at their live values, and returns the
// merged config that was persisted.
//
// The admin Settings PUT does a read-decode-write: it reads the config, decodes
// the request body onto it, validates, then writes the whole struct back. Those
// telemetry fields are part of that struct but are not admin-editable — they're
// set by the background watch/archive workers. Without this merge, a worker that
// wrote a fresh LastAnalysisUnix (or an archive-run result) between the handler's
// read and its write would have that write clobbered by the stale snapshot the
// handler is about to persist — silently rolling back, e.g., the incremental
// watch mtime cutoff. Reading the live runtime fields here, under the same lock
// as the write, closes that window: the admin PUT can only ever overwrite the
// operator-editable fields.
func (s *Store) SetConfigPreservingRuntime(cfg config.Config) config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.ArchiveLastRunAt = s.config.ArchiveLastRunAt
	cfg.ArchiveLastFilesArchived = s.config.ArchiveLastFilesArchived
	cfg.ArchiveLastBytesArchived = s.config.ArchiveLastBytesArchived
	cfg.ArchiveLastFindingsPruned = s.config.ArchiveLastFindingsPruned
	cfg.ArchiveLastTriggeredBy = s.config.ArchiveLastTriggeredBy
	cfg.LastAnalysisFingerprint = s.config.LastAnalysisFingerprint
	cfg.LastFullAnalysisUnix = s.config.LastFullAnalysisUnix
	cfg.LastAnalysisUnix = s.config.LastAnalysisUnix
	s.config = cfg
	s.persistConfig()
	return s.config
}

// persistConfig writes s.config to the settings row. Caller must hold
// s.mu (any form). All one-field config mutations (SetWatch,
// SetSensorFacingHost, etc.) route through here so a failed DB write
// is logged rather than silently swallowed — a failed write leaves
// in-memory state ahead of disk, which the operator would observe as
// a config revert on the next restart.
func (s *Store) persistConfig() {
	if s.db == nil {
		return
	}
	cfgJSON, _ := json.Marshal(s.config)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON))
	if err != nil {
		slog.Error("store: persist settings", "err", err)
	}
	s.recordPersist("config", err)
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
	// Stale-notification cleanup: any active bell row whose finding is
	// now hidden by this allowlist would scroll-fail on Jump (the row
	// is filtered out of every listing). Dismiss them in lockstep with
	// the matcher update so the bell stays honest. NEW-111.
	s.dismissHiddenFindingNotificationsLocked()
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

// GetIOCFingerprints returns the operator-supplied JA3/JA4 fingerprint IOCs
// (lowercased, no comments). Built-in C2 fingerprints are NOT included — they
// live in the analysis package and are merged at analyze time.
func (s *Store) GetIOCFingerprints() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.iocFPList))
	copy(out, s.iocFPList)
	return out
}

// SetIOCFingerprints replaces the operator JA3/JA4 fingerprint IOC list.
// Entries are lowercased and de-commented by sanitizeFingerprintEntries.
func (s *Store) SetIOCFingerprints(entries []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.iocFPList = sanitizeFingerprintEntries(entries)
	s.persistList("ioc_fp_list", s.iocFPList)
}

// AddIOCFingerprint appends a single fingerprint (the "Mark malicious" path
// from the TLS Fingerprints wall) if not already present. Returns true if the
// list changed. The caller is responsible for rejecting built-in fingerprints
// before calling — those are always active and don't belong in the operator list.
func (s *Store) AddIOCFingerprint(fp string) bool {
	cleaned := sanitizeFingerprintEntries([]string{fp})
	if len(cleaned) == 0 {
		return false
	}
	fp = cleaned[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.iocFPList {
		if e == fp {
			return false
		}
	}
	s.iocFPList = append(s.iocFPList, fp)
	s.persistList("ioc_fp_list", s.iocFPList)
	return true
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

	// Use the cached feed list to avoid a live DB query on every
	// /api/findings request. invalidateFeedBuckets clears this cache
	// on every feed CRUD path, so it is always coherent with the DB.
	s.feedBucketsMu.Lock()
	if !s.feedListOK {
		s.enabledFeedList = s.ListFeeds()
		s.feedListOK = true
	}
	feedList := s.enabledFeedList
	s.feedBucketsMu.Unlock()

	out := []SourcedMatcher{
		{Source: "Operator IOC list", Matcher: iocM},
	}
	for _, f := range feedList {
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
	gen := s.feedMatcherGen[feedID]
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
	// If an invalidation ran while we were building (gen changed),
	// don't cache our stale result — return it for this call only;
	// the next caller will rebuild from current indicators.
	if s.feedMatcherGen[feedID] != gen {
		s.mu.Unlock()
		return m
	}
	s.feedMatchers[feedID] = m
	s.mu.Unlock()
	return m
}

// invalidateFeedMatcher drops the cached matcher for a feed. The next
// IOCSources / feedMatcher call rebuilds from current indicators.
func (s *Store) invalidateFeedMatcher(feedID int64) {
	s.mu.Lock()
	s.feedMatcherGen[feedID]++
	delete(s.feedMatchers, feedID)
	s.mu.Unlock()
}

func (s *Store) AddSuppression(target string, expiry time.Time, detail string) {
	s.mu.Lock()
	s.suppressions[target] = SuppressionEntry{Expiry: expiry, Detail: detail}
	if s.db != nil {
		_, err := s.db.Exec(`INSERT OR REPLACE INTO suppressions (target, expiry, detail) VALUES (?, ?, ?)`, target, expiry.Unix(), detail)
		if err != nil {
			slog.Error("store: persist suppression", "err", err)
		}
		s.recordPersist("suppression", err)
	}
	// Stale-notification cleanup — see SetAllowlist for rationale.
	// NEW-111.
	s.dismissHiddenFindingNotificationsLocked()
	s.mu.Unlock()
}

func (s *Store) RemoveSuppression(target string) {
	s.mu.Lock()
	delete(s.suppressions, target)
	if s.db != nil {
		_, err := s.db.Exec(`DELETE FROM suppressions WHERE target = ?`, target)
		if err != nil {
			slog.Error("store: remove suppression", "err", err)
		}
		s.recordPersist("suppression", err)
	}
	s.mu.Unlock()
}

// GetSuppressions returns the in-memory suppression set, filtering
// out expired entries so the admin UI never lists a stale row that
// the read-path treats as not-suppressed. Mutation (cleaning up
// the map and DB rows) is the periodic-sweep loop's job, not this
// function's.
func (s *Store) GetSuppressions() map[string]SuppressionEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make(map[string]SuppressionEntry, len(s.suppressions))
	for k, v := range s.suppressions {
		if now.After(v.Expiry) {
			continue
		}
		out[k] = v
	}
	return out
}

// IsSuppressed reports whether the given target is currently
// suppressed. Pure read — no map mutation, no DB write. Pre-fix the
// function lock-upgraded and ran a per-call DELETE on every expired
// entry it observed; two concurrent filter requests for the same
// expired IP both ran the DELETE (idempotent but wasted), and the
// hot read path took the writer lock unnecessarily often. Audit
// 2026-05-10. Cleanup is now the PruneExpiredSuppressions sweep
// loop's responsibility (see Server.startSuppressionsPruneLoop).
// An expired entry that the sweep hasn't seen yet returns false
// here — same observable behavior as before, without the writes.
func (s *Store) IsSuppressed(ip string) bool {
	s.mu.RLock()
	entry, ok := s.suppressions[ip]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	return !time.Now().After(entry.Expiry)
}

// ── Pair allowlist (tuple-scoped view filter) ─────────────────────────────

// pairAllowRule is one entry in the in-memory pair-allow index. The key
// is (src,dst,port); sensor and ftype each act as wildcards when empty.
type pairAllowRule struct{ sensor, ftype string }

// pairAllowScanRule is a ranged rule: at least one of Src/Dst was written
// as a CIDR or a *.domain wildcard, so the exact (src,dst,port) hash key
// can't represent it. Per side, exactly one of net/suffix is set — or
// neither, meaning an exact string compare (same semantics as the exact
// index); port/sensor/ftype behave exactly as there too. The ruleset is
// operator-curated and tiny, so a linear scan after the exact-index miss
// costs nothing on the hot path.
type pairAllowScanRule struct {
	srcNet               *net.IPNet
	dstNet               *net.IPNet
	srcSuffix, dstSuffix string // ".skype.com" for a *.skype.com side; matches the apex too
	src, dst             string
	port, sensor, ftype  string
}

// sideMatches applies one side of a scan rule. Wildcard sides are
// case-insensitive (DNS names are; the detectors lowercase, but x509
// subjects and hand-fed values may not be).
func sideMatches(ipnet *net.IPNet, suffix, exact, v string) bool {
	switch {
	case ipnet != nil:
		ip := net.ParseIP(v)
		return ip != nil && ipnet.Contains(ip)
	case suffix != "":
		lc := strings.ToLower(v)
		return strings.HasSuffix(lc, suffix) || lc == suffix[1:]
	default:
		return exact == v
	}
}

func (r pairAllowScanRule) matches(src, dst, port, ftype, sensor string) bool {
	if r.port != port {
		return false
	}
	if r.sensor != "" && r.sensor != sensor {
		return false
	}
	if r.ftype != "" && r.ftype != ftype {
		return false
	}
	return sideMatches(r.srcNet, r.srcSuffix, r.src, src) &&
		sideMatches(r.dstNet, r.dstSuffix, r.dst, dst)
}

func pairAllowKey(src, dst, port string) string {
	return src + "\x00" + dst + "\x00" + port
}

// rebuildPairAllowIdxLocked recomputes the (src,dst,port) → rule slice
// index and the ranged-rule slice from the rule list. Both are replaced
// wholesale, never edited in place — FilterSnapshot relies on that
// copy-on-write contract. Caller serialises access (write lock, or
// startup before goroutines start). A ranged rule whose CIDR or wildcard
// fails to parse is dropped here (the API validates on create, so only a
// hand-edited DB row can produce one) — better an inert rule than one
// that silently hides nothing while looking active, and the manager UI
// still lists it for the operator to fix or delete.
func (s *Store) rebuildPairAllowIdxLocked() {
	idx := make(map[string][]pairAllowRule, len(s.pairAllow))
	var ranged []pairAllowScanRule
	isRanged := func(v string) bool { return strings.Contains(v, "/") || strings.HasPrefix(v, "*.") }
	for _, e := range s.pairAllow {
		if isRanged(e.Src) || isRanged(e.Dst) {
			r := pairAllowScanRule{src: e.Src, dst: e.Dst, port: e.Port, sensor: e.Sensor, ftype: e.FindingType}
			ok := true
			for _, side := range []struct {
				v      string
				ipnet  **net.IPNet
				suffix *string
			}{{e.Src, &r.srcNet, &r.srcSuffix}, {e.Dst, &r.dstNet, &r.dstSuffix}} {
				switch {
				case strings.Contains(side.v, "/"):
					if _, ipnet, err := net.ParseCIDR(side.v); err == nil {
						*side.ipnet = ipnet
					} else {
						ok = false
					}
				case strings.HasPrefix(side.v, "*."):
					if len(side.v) > 2 {
						*side.suffix = strings.ToLower(side.v[1:])
					} else {
						ok = false
					}
				}
			}
			if ok {
				ranged = append(ranged, r)
			} else {
				slog.Warn("pair-allow rule has an unparseable CIDR or wildcard; rule inert", "src", e.Src, "dst", e.Dst, "id", e.ID)
			}
			continue
		}
		k := pairAllowKey(e.Src, e.Dst, e.Port)
		idx[k] = append(idx[k], pairAllowRule{e.Sensor, e.FindingType})
	}
	s.pairAllowIdx = idx
	s.pairAllowScan = ranged
}

// isPairAllowedLocked reports whether a pair rule hides a finding with
// this (src,dst,port,type,sensor). An empty rule FindingType matches
// every type on the tuple; an empty rule Sensor matches every sensor.
// Exact rules resolve via the hash index; ranged (CIDR / *.domain)
// rules scan.
// Caller holds s.mu (read or write).
func (s *Store) isPairAllowedLocked(src, dst, port, ftype, sensor string) bool {
	for _, r := range s.pairAllowIdx[pairAllowKey(src, dst, port)] {
		if (r.sensor == "" || r.sensor == sensor) && (r.ftype == "" || r.ftype == ftype) {
			return true
		}
	}
	for _, r := range s.pairAllowScan {
		if r.matches(src, dst, port, ftype, sensor) {
			return true
		}
	}
	return false
}

// IsPairAllowed is the read-path entry used by findings_filter.go.
func (s *Store) IsPairAllowed(src, dst, port, ftype, sensor string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isPairAllowedLocked(src, dst, port, ftype, sensor)
}

// FilterSnapshot is an immutable view of the suppression + pair-allow
// state captured once under the store read-lock. The findings filter
// evaluates every row against it without re-locking. Pre-snapshot the
// hot /api/findings path took s.mu three times per finding (IsSuppressed
// on src, IsSuppressed on dst, IsPairAllowed) — on a large result set the
// lock traffic, not the predicate work, dominated the request. A snapshot
// reflects state at capture time: a suppression or pair-allow edit landing
// mid-filter is simply not reflected until the next fetch, which is the
// same eventual consistency the per-row locking already had (a row could
// be tested against a suppression removed microseconds later).
type FilterSnapshot struct {
	suppressions  map[string]time.Time
	pairAllowIdx  map[string][]pairAllowRule
	pairAllowScan []pairAllowScanRule
	now           time.Time
}

// NewFilterSnapshot freezes the current suppression/pair-allow state. The
// suppressions map is copied because writers mutate it in place; the
// pair-allow index is held by reference because it is copy-on-write
// (rebuildPairAllowIdxLocked replaces the whole map, never edits in
// place), so a captured reference can never observe a torn write.
func (s *Store) NewFilterSnapshot() FilterSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sup := make(map[string]time.Time, len(s.suppressions))
	for k, v := range s.suppressions {
		sup[k] = v.Expiry
	}
	return FilterSnapshot{
		suppressions:  sup,
		pairAllowIdx:  s.pairAllowIdx,
		pairAllowScan: s.pairAllowScan,
		now:           time.Now(),
	}
}

// IsSuppressed reports whether ip has an unexpired suppression as of the
// snapshot's capture time.
func (fs FilterSnapshot) IsSuppressed(ip string) bool {
	exp, ok := fs.suppressions[ip]
	if !ok {
		return false
	}
	return !fs.now.After(exp)
}

// IsPairAllowed mirrors Store.isPairAllowedLocked against the frozen index.
func (fs FilterSnapshot) IsPairAllowed(src, dst, port, ftype, sensor string) bool {
	for _, r := range fs.pairAllowIdx[pairAllowKey(src, dst, port)] {
		if (r.sensor == "" || r.sensor == sensor) && (r.ftype == "" || r.ftype == ftype) {
			return true
		}
	}
	for _, r := range fs.pairAllowScan {
		if r.matches(src, dst, port, ftype, sensor) {
			return true
		}
	}
	return false
}

// ListPairAllowlist returns every rule, id-ordered, for the manager UI.
func (s *Store) ListPairAllowlist() []model.PairAllowEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.PairAllowEntry, len(s.pairAllow))
	copy(out, s.pairAllow)
	return out
}

// AddPairAllow inserts a rule and returns its id. Idempotent on the
// (src,dst,port,finding_type) unique index: re-adding an identical
// rule returns the existing id without creating a duplicate or
// re-running the notification sweep.
func (s *Store) AddPairAllow(e model.PairAllowEntry) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("store: db not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO pair_allowlist (src, dst, port, finding_type, sensor, detail, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Src, e.Dst, e.Port, e.FindingType, e.Sensor, e.Detail, e.CreatedBy, e.CreatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("store: add pair allow: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Duplicate — rule already present. Return the existing id.
		var id int64
		_ = s.db.QueryRow(
			`SELECT id FROM pair_allowlist WHERE src=? AND dst=? AND port=? AND finding_type=? AND sensor=?`,
			e.Src, e.Dst, e.Port, e.FindingType, e.Sensor,
		).Scan(&id)
		return id, nil
	}
	id, _ := res.LastInsertId()
	e.ID = id
	s.pairAllow = append(s.pairAllow, e)
	s.rebuildPairAllowIdxLocked()
	// A just-allowlisted pair shouldn't keep ringing the bell — same
	// stale-notification cleanup AddSuppression / SetAllowlist run.
	s.dismissHiddenFindingNotificationsLocked()
	return id, nil
}

// RemovePairAllow deletes a rule by id. The matching findings were
// never dropped from the store, so they reappear on the next
// /api/findings fetch with no re-analysis.
func (s *Store) RemovePairAllow(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		if _, err := s.db.Exec(`DELETE FROM pair_allowlist WHERE id = ?`, id); err != nil {
			slog.Error("store: remove pair allow", "id", id, "err", err)
			s.recordPersist("pair_allowlist", err)
			return
		}
		s.recordPersist("pair_allowlist", nil)
	}
	for i := range s.pairAllow {
		if s.pairAllow[i].ID == id {
			s.pairAllow = append(s.pairAllow[:i], s.pairAllow[i+1:]...)
			break
		}
	}
	s.rebuildPairAllowIdxLocked()
}

func fpAllowKey(kind, fingerprint string) string { return kind + "\x00" + fingerprint }

// rebuildFPAllowIdxLocked refreshes the (kind,fingerprint)->true lookup from
// the in-memory slice. Caller holds s.mu.
func (s *Store) rebuildFPAllowIdxLocked() {
	idx := make(map[string]bool, len(s.fpAllow))
	for _, e := range s.fpAllow {
		idx[fpAllowKey(e.Kind, e.Fingerprint)] = true
	}
	s.fpAllowIdx = idx
}

// IsFingerprintAllowed reports whether (kind, fingerprint) has been marked
// benign. Read under RLock.
func (s *Store) IsFingerprintAllowed(kind, fingerprint string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fpAllowIdx[fpAllowKey(kind, fingerprint)]
}

// FingerprintAllowSnapshot copies the benign-fingerprint index once under a
// single read lock and returns a lock-free lookup closure over the copy. The
// findings filter calls this once per request and stamps each finding's
// TLSAllowlisted with it — avoiding the per-finding RLock churn that calling
// IsFingerprintAllowed inside the filter loop would incur (the PERF-2 lesson).
// The empty fingerprint (non-TLS findings) short-circuits to false.
func (s *Store) FingerprintAllowSnapshot() func(kind, fingerprint string) bool {
	s.mu.RLock()
	idx := make(map[string]bool, len(s.fpAllowIdx))
	for k, v := range s.fpAllowIdx {
		idx[k] = v
	}
	s.mu.RUnlock()
	return func(kind, fingerprint string) bool {
		if fingerprint == "" {
			return false
		}
		return idx[fpAllowKey(kind, fingerprint)]
	}
}

// ListFingerprintAllowlist returns every benign-fingerprint entry, id-ordered,
// for the modal's "Benign" section.
func (s *Store) ListFingerprintAllowlist() []model.FingerprintAllowEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.FingerprintAllowEntry, len(s.fpAllow))
	copy(out, s.fpAllow)
	return out
}

// AddFingerprintAllow marks a fingerprint benign and returns its id. Idempotent
// on the (kind, fingerprint) unique index: re-adding an identical entry returns
// the existing id without creating a duplicate.
func (s *Store) AddFingerprintAllow(e model.FingerprintAllowEntry) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("store: db not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO fingerprint_allowlist (kind, fingerprint, note, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		e.Kind, e.Fingerprint, e.Note, e.CreatedBy, e.CreatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("store: add fingerprint allow: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var id int64
		_ = s.db.QueryRow(
			`SELECT id FROM fingerprint_allowlist WHERE kind=? AND fingerprint=?`,
			e.Kind, e.Fingerprint,
		).Scan(&id)
		return id, nil
	}
	id, _ := res.LastInsertId()
	e.ID = id
	s.fpAllow = append(s.fpAllow, e)
	s.rebuildFPAllowIdxLocked()
	return id, nil
}

// RemoveFingerprintAllow deletes a benign-fingerprint entry by id. The
// fingerprint returns to the TLS Fingerprints inventory on the next fetch.
func (s *Store) RemoveFingerprintAllow(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		if _, err := s.db.Exec(`DELETE FROM fingerprint_allowlist WHERE id = ?`, id); err != nil {
			slog.Error("store: remove fingerprint allow", "id", id, "err", err)
			return
		}
	}
	for i := range s.fpAllow {
		if s.fpAllow[i].ID == id {
			s.fpAllow = append(s.fpAllow[:i], s.fpAllow[i+1:]...)
			break
		}
	}
	s.rebuildFPAllowIdxLocked()
}

// isHiddenLocked reports whether either of the two IPs is currently
// hidden by the allowlist or the (unexpired) suppression set. Mirrors
// the filterFindings exclusion check at findings_filter.go:107-112 so
// SetFindings's bell-emit path and the dismiss-on-list-update path
// share a single source of truth for "would the analyst see this in
// the table?". Caller must hold s.mu (write or read). NEW-111.
func (s *Store) isHiddenLocked(srcIP, dstIP string) bool {
	if s.allowlistM != nil {
		if s.allowlistM.Matches(srcIP) || s.allowlistM.Matches(dstIP) {
			return true
		}
	}
	now := time.Now()
	if entry, ok := s.suppressions[srcIP]; ok && !now.After(entry.Expiry) {
		return true
	}
	if entry, ok := s.suppressions[dstIP]; ok && !now.After(entry.Expiry) {
		return true
	}
	return false
}

// dismissHiddenFindingNotificationsLocked walks active finding
// notifications and dismisses any whose Src or Dst is now hidden by
// the allowlist or suppression set. Called from SetAllowlist and
// AddSuppression after the underlying matcher has been updated, so
// existing bell entries don't outlive the row they reference. Sensor
// and feed alarms have no Src/Dst IPs and pass through unchanged.
// Caller must hold s.mu (write lock). NEW-111.
func (s *Store) dismissHiddenFindingNotificationsLocked() {
	var dismissedIDs []int
	for i := range s.notifications {
		n := &s.notifications[i]
		if n.Dismissed {
			continue
		}
		// Empty Kind reads as "finding" (pre-v0.17.0 persisted rows).
		if n.Kind != "" && n.Kind != "finding" {
			continue
		}
		if s.isHiddenLocked(n.SrcIP, n.DstIP) || s.isPairAllowedLocked(n.SrcIP, n.DstIP, n.DstPort, n.Type, n.Sensor) {
			n.Dismissed = true
			dismissedIDs = append(dismissedIDs, n.ID)
		}
	}
	if s.db != nil && len(dismissedIDs) > 0 {
		ph := strings.Repeat("?,", len(dismissedIDs))
		args := make([]any, len(dismissedIDs))
		for i, id := range dismissedIDs {
			args[i] = id
		}
		if _, err := s.db.Exec(`UPDATE notifications SET dismissed = 1 WHERE id IN (`+ph[:len(ph)-1]+`)`, args...); err != nil {
			slog.Error("store: persist dismiss-on-hidden notifications", "count", len(dismissedIDs), "err", err)
		}
	}
}

// dismissOrphanedFindingNotificationsLocked walks active finding-kind
// notifications and dismisses any whose FindingID is no longer present in
// findingsIdx. Must be called after rebuildFindingsIdx under the write lock.
func (s *Store) dismissOrphanedFindingNotificationsLocked() {
	var dismissedIDs []int
	for i := range s.notifications {
		n := &s.notifications[i]
		if n.Dismissed {
			continue
		}
		if n.Kind != "" && n.Kind != "finding" {
			continue
		}
		if _, ok := s.findingsIdx[n.FindingID]; !ok {
			n.Dismissed = true
			dismissedIDs = append(dismissedIDs, n.ID)
		}
	}
	if s.db != nil && len(dismissedIDs) > 0 {
		ph := strings.Repeat("?,", len(dismissedIDs))
		args := make([]any, len(dismissedIDs))
		for i, id := range dismissedIDs {
			args[i] = id
		}
		if _, err := s.db.Exec(`UPDATE notifications SET dismissed = 1 WHERE id IN (`+ph[:len(ph)-1]+`)`, args...); err != nil {
			slog.Warn("store: dismiss orphaned notifications", "count", len(dismissedIDs), "err", err)
		}
	}
}

// SetFindingsForImport is like SetFindings but suppresses notification
// creation and forces IsNew=false on all imported findings. Imported
// findings are restored state, not newly detected events — they must not
// ring the bell or appear as new in Delta mode.
func (s *Store) SetFindingsForImport(findings []model.Finding) {
	s.setFindingsImpl(findings, true, false)
}

// PruneExpiredSuppressions deletes every expired suppression in one
// pass — single DELETE round trip plus one map walk under the write
// lock. Called periodically from the server's sweep loop; safe to
// call concurrently with reads (RLock readers see expired entries
// as "not suppressed" already).
func (s *Store) PruneExpiredSuppressions() int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	pruned := 0
	for k, v := range s.suppressions {
		if now.After(v.Expiry) {
			delete(s.suppressions, k)
			pruned++
		}
	}
	if pruned > 0 && s.db != nil {
		if _, err := s.db.Exec(`DELETE FROM suppressions WHERE expiry <= ?`, now.Unix()); err != nil {
			slog.Warn("store: prune expired suppressions", "err", err)
		}
	}
	return pruned
}

func (s *Store) GetNotifications() []model.Notification {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Notification, len(s.notifications))
	copy(out, s.notifications)
	return out
}

// AddAlarm appends a non-finding notification (Kind=sensor or
// Kind=feed) and returns it with the auto-assigned ID. Unlike the
// finding-emit path inside SetFindings, this is for out-of-band
// alarms that aren't anchored to a finding row — sensor staleness
// and feed health, today. Caller is responsible for deciding when
// to emit (e.g. transition detection in a heartbeat goroutine) so
// the operator isn't re-alarmed every tick while the condition
// persists.
func (s *Store) AddAlarm(n model.Notification) model.Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifCounter++
	n.ID = s.notifCounter
	s.notifications = append(s.notifications, n)
	s.persistNotification(n)
	return n
}

func (s *Store) DismissNotification(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.notifications {
		if s.notifications[i].ID == id {
			s.notifications[i].Dismissed = true
			if s.db != nil {
				if _, err := s.db.Exec(`UPDATE notifications SET dismissed = 1 WHERE id = ?`, id); err != nil {
					slog.Error("store: persist dismiss notification", "id", id, "err", err)
				}
			}
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
	if s.db != nil {
		if _, err := s.db.Exec(`UPDATE notifications SET dismissed = 1 WHERE dismissed = 0`); err != nil {
			slog.Error("store: persist dismiss all notifications", "err", err)
		}
	}
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
	s.persistConfig()
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
	s.persistConfig()
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
	s.persistConfig()
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
	s.persistConfig()
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
	s.persistConfig()
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
	s.persistConfig()
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
	s.persistConfig()
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
	s.rebuildFindingsIdx()
	s.dismissOrphanedFindingNotificationsLocked()
	s.config.LastAnalysisFingerprint = ""
	s.persistConfig()
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
		s.rebuildFindingsIdx()
		s.dismissOrphanedFindingNotificationsLocked()
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

// TryStartAnalysis atomically claims the "analysis in flight" slot.
// Returns true on success (caller now owns the slot and must call
// SetAnalyzing(false) when done); returns false if another analysis is
// already running.
//
// Pre-NEW-31 callers did `if !IsAnalyzing() { ...; SetAnalyzing(true) }`
// with a TOCTOU window between the two calls. The window was small but
// real: two near-simultaneous triggers (watch tick fires while the
// user clicks "Analyze sensor logs", or two watch ticks fire in quick
// succession when an analysis takes longer than the watch interval)
// could both pass the IsAnalyzing check, both spawn analyzer
// goroutines, and stomp s.activeAnalyzer. Cancel-button semantics
// broke (only the second goroutine stopped, the first ran to
// completion regardless), SSE progress events interleaved, memory
// doubled. Audit 2026-05-10 NEW-31.
func (s *Store) TryStartAnalysis() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.analyzing {
		return false
	}
	s.analyzing = true
	return true
}

// CountNewFindings returns the number of findings currently marked
// is_new=1 in the DB. Used to populate the done-event new_count so
// the analysis-complete modal always matches what the delta button shows
// — including is_new findings from the previous full pass that an
// incremental run didn't regenerate and therefore didn't count.
func (s *Store) CountNewFindings() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return 0
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE is_new=1`).Scan(&n)
	return n
}

// CountUnseen returns how many findings were first detected after `since`
// (epoch seconds), excluding roll-up types (Host Risk Score / Correlated
// Activity) — those are derived summaries, not new events, and the bell
// already suppresses their notifications. This is the per-user "new since
// you last looked" count: callers pass the viewer's findings_seen_at
// marker. Unlike CountNewFindings (the volatile per-run is_new flag), it
// rests on detected_at, which survives re-analysis, so it accumulates
// across the hourly watch passes between one analyst login and the next.
// Total is every finding regardless of detection time, for the "· M total"
// half of the modal.
func (s *Store) CountUnseen(since int64) (unseen, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return 0, 0
	}
	s.db.QueryRow(
		`SELECT COUNT(*) FROM findings WHERE detected_at > ? AND type NOT IN (?, ?)`,
		since, model.TypeHostRiskScore, model.TypeCorrelatedActivity,
	).Scan(&unseen)
	s.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&total)
	return unseen, total
}

// RecordSpectralBlocked persists the total count of fully-blocked spectral
// rescues from the completed analysis run. A "fully-blocked" rescue is a
// pair where the plausibility gate rejected the only strong periodogram
// peak — the pair still emits a beacon finding at reduced score, but the
// spectral evidence was suppressed. Stored in analysis_stats so the corpus
// spot-check script can flag cumulative under-detection without relying on
// log lines.
func (s *Store) RecordSpectralBlocked(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	if _, err := s.db.Exec(
		`INSERT INTO analysis_stats (run_at, spectral_blocked) VALUES (?, ?)`,
		time.Now().Unix(), count,
	); err != nil {
		slog.Error("store: record spectral blocked", "err", err)
	}
}
