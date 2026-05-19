package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
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
	findings      []model.Finding
	findingsIdx   map[int]int
	allowlist     []string
	iocList       []string
	allowlistM    *match.Matcher           // cached compile of allowlist; rebuilt on Set
	iocM          *match.Matcher           // cached compile of iocList; rebuilt on Set
	feedMatchers  map[int64]*match.Matcher // per-feed cached compile; rebuilt on indicator write
	suppressions  map[string]suppressionEntry
	pairAllow     []model.PairAllowEntry
	pairAllowIdx  map[string][]string // src\x00dst\x00port -> finding_types ("" = all)
	notifications []model.Notification
	notifCounter  int
	config        config.Config
	analyzing     bool

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

type suppressionEntry struct {
	Expiry time.Time
	Detail string
}

func New(cfg config.Config) *Store {
	return &Store{
		suppressions: make(map[string]suppressionEntry),
		pairAllowIdx: make(map[string][]string),
		feedMatchers: make(map[int64]*match.Matcher),
		findingsIdx:  make(map[int]int),
		config:       cfg,
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
		// tbl is a table identifier (SQL placeholders cannot
		// parameterize identifiers) and loadOrdered is only ever
		// called with hardcoded literal table names — not reachable
		// from user input.
		rows, err := db.Query(`SELECT entry FROM ` + tbl + ` ORDER BY rowid`) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- constant table identifier, internal callers only
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

	if rows, err := db.Query(`SELECT id, src, dst, port, finding_type, detail, created_by, created_at FROM pair_allowlist ORDER BY id`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var e model.PairAllowEntry
			if rows.Scan(&e.ID, &e.Src, &e.Dst, &e.Port, &e.FindingType, &e.Detail, &e.CreatedBy, &e.CreatedAt) == nil {
				s.pairAllow = append(s.pairAllow, e)
			}
		}
	}
	s.rebuildPairAllowIdxLocked()

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
	                                dismissed
	                         FROM notifications ORDER BY id`)
	if err != nil {
		log.Printf("store: cannot load notifications: %v", err)
		return
	}
	defer rows.Close()
	var maxID int
	for rows.Next() {
		var n model.Notification
		var dismissed int
		if err := rows.Scan(&n.ID, &n.Kind, &n.Target, &n.Detail, &n.FindingID,
			&n.Severity, &n.Type, &n.SrcIP, &n.DstIP, &n.DstPort, &dismissed); err != nil {
			continue
		}
		n.Dismissed = dismissed != 0
		s.notifications = append(s.notifications, n)
		if n.ID > maxID {
			maxID = n.ID
		}
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
		(id, kind, target, detail, finding_id, severity, type, src_ip, dst_ip, dst_port, dismissed, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		n.ID, n.Kind, n.Target, n.Detail, n.FindingID,
		n.Severity, n.Type, n.SrcIP, n.DstIP, n.DstPort,
		time.Now().Unix(),
	)
	if err != nil {
		log.Printf("store: persist notification %d: %v", n.ID, err)
	}
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
	rows, err := s.db.Query(`SELECT id, type, severity, score, src_ip, dst_ip, dst_port, detail, timestamp, source_file, status, analyst, analyst_note, status_ts, ioc_match, is_new, sensor, intervals, ts_data, notes, correlations, ts_score, ds_score, hist_score, dur_score, mean_interval, median_interval, jitter, sample_size, ja3, ja4, top_uris FROM findings ORDER BY id`)
	if err != nil {
		log.Printf("store: load findings: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var f model.Finding
		var iocMatch, isNew int
		var intervals, tsData, notes, correlations, topURIs string
		if err := rows.Scan(&f.ID, &f.Type, &f.Severity, &f.Score, &f.SrcIP, &f.DstIP, &f.DstPort, &f.Detail, &f.Timestamp, &f.SourceFile, &f.Status, &f.Analyst, &f.AnalystNote, &f.StatusTS, &iocMatch, &isNew, &f.Sensor, &intervals, &tsData, &notes, &correlations, &f.TSScore, &f.DSScore, &f.HistScore, &f.DurScore, &f.MeanInterval, &f.MedianInterval, &f.Jitter, &f.SampleSize, &f.JA3, &f.JA4, &topURIs); err != nil {
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
		// NEW-72: Correlations persists across restarts so the "+N corr"
		// chip stays visible without requiring a fresh analysis run to
		// repopulate. Empty string (the schema default for pre-0010
		// rows) decodes to a nil slice — matches the pre-feature shape.
		if correlations != "" {
			if err := json.Unmarshal([]byte(correlations), &f.Correlations); err != nil {
				log.Printf("store: finding %d: corrupt correlations: %v", f.ID, err)
			}
		}
		// top_uris (migration 0020): the HTTP-beacon path footprint.
		// Empty string (schema default for pre-0020 rows / non-HTTP
		// findings) decodes to a nil slice — the pre-feature shape.
		if topURIs != "" {
			if err := json.Unmarshal([]byte(topURIs), &f.TopURIs); err != nil {
				log.Printf("store: finding %d: corrupt top_uris: %v", f.ID, err)
			}
		}
		s.findings = append(s.findings, f)
	}
	s.rebuildFindingsIdx()
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
	stmt, err := tx.Prepare(`INSERT INTO findings (id, type, severity, score, src_ip, dst_ip, dst_port, detail, timestamp, source_file, status, analyst, analyst_note, status_ts, ioc_match, is_new, sensor, intervals, ts_data, notes, correlations, ts_score, ds_score, hist_score, dur_score, mean_interval, median_interval, jitter, sample_size, ja3, ja4, top_uris) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		log.Printf("store: save findings prepare: %v", err)
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
		if _, err := stmt.Exec(
			f.ID, f.Type, string(f.Severity), f.Score, f.SrcIP, f.DstIP, f.DstPort, f.Detail, f.Timestamp, f.SourceFile,
			string(f.Status), f.Analyst, f.AnalystNote, f.StatusTS, iocMatch, isNew, f.Sensor,
			string(intervals), string(tsData), string(notes), string(correlations),
			f.TSScore, f.DSScore, f.HistScore, f.DurScore, f.MeanInterval, f.MedianInterval, f.Jitter, f.SampleSize,
			f.JA3, f.JA4, string(topURIs),
		); err != nil {
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
	return s.setFindingsImpl(findings, true)
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
	return s.setFindingsImpl(findings, false)
}

// setFindingsImpl is the shared body for both public entry points.
// purgeStaleRollups gates the IsRollupType branch in the historical-
// preserve loop — true for full passes (the original behavior), false
// for TI-only incrementals where rollup absence means "not evaluated
// this pass" rather than "no longer valid."
func (s *Store) setFindingsImpl(findings []model.Finding, purgeStaleRollups bool) []model.Notification {
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
		} else {
			// Truly new fingerprint — assign an ID guaranteed above any
			// preserved historical ID so the saveFindings INSERT can't
			// collide.
			nextNewID++
			findings[i].ID = nextNewID
			findings[i].IsNew = true
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
	s.analyzing = false
	s.saveFindings()
	s.saveBeaconHistory(findings, newFPSet)

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
		// Bell threshold: f.Score >= 95. v0.17.0 first cut this at
		// `>= 99`, which over-corrected — the discrete-tier
		// detectors (URLhaus 96, Malicious JA3 95, FeodoTracker 97)
		// top out below 99 by design, so externally-validated
		// high-confidence indicators stayed silent. NEW-99 in the
		// twenty-third audit round: 95 captures the top of both the
		// discrete-tier population AND the computed-score
		// population (Beaconing/Correlated Activity hit 95+ when
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
			if s.isHiddenLocked(f.SrcIP, f.DstIP) || s.isPairAllowedLocked(f.SrcIP, f.DstIP, f.DstPort, f.Type) {
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
func (s *Store) UpdateFinding(id int, status model.Status, analyst, note, statusTS string) (model.Finding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.findingsIdx[id]
	if !ok {
		return model.Finding{}, false
	}
	before := s.findings[i]
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
	return before, true
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

// CountBeaconsWithJA3 returns how many beacon findings other than
// excludeID carry the same (non-empty) JA3 — the "matched N other
// beacons in this dataset" signal the detail pane renders. An empty
// ja3 returns 0 (no fingerprint, nothing to correlate). In-memory
// scan under the same RLock the rest of the read path uses; the
// finding set is already resident, so this is cheap relative to the
// per-request detail render that calls it.
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

func (s *Store) AddNote(id int, note model.Note) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.findingsIdx[id]
	if !ok {
		return false
	}
	s.findings[i].Notes = append(s.findings[i].Notes, note)
	if s.db != nil {
		notesJSON, _ := json.Marshal(s.findings[i].Notes)
		if _, err := s.db.Exec(`UPDATE findings SET notes=? WHERE id=?`, string(notesJSON), id); err != nil {
			log.Printf("store: add note to finding %d: %v", id, err)
		}
	}
	return true
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
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO settings (id, config) VALUES (1, ?)`, string(cfgJSON)); err != nil {
		log.Printf("store: persist settings: %v", err)
	}
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
	// Stale-notification cleanup — see SetAllowlist for rationale.
	// NEW-111.
	s.dismissHiddenFindingNotificationsLocked()
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

// GetSuppressions returns the in-memory suppression set, filtering
// out expired entries so the admin UI never lists a stale row that
// the read-path treats as not-suppressed. Mutation (cleaning up
// the map and DB rows) is the periodic-sweep loop's job, not this
// function's.
func (s *Store) GetSuppressions() map[string]suppressionEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make(map[string]suppressionEntry, len(s.suppressions))
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

func pairAllowKey(src, dst, port string) string {
	return src + "\x00" + dst + "\x00" + port
}

// rebuildPairAllowIdxLocked recomputes the (src,dst,port) → finding-type
// index from the rule slice. Mirrors the allowlistM-rebuild-on-Set
// pattern so the hot read path (IsPairAllowed, once per finding per
// /api/findings request) is an O(1) map probe, not a slice scan.
// Caller serialises access (write lock, or startup before goroutines).
func (s *Store) rebuildPairAllowIdxLocked() {
	idx := make(map[string][]string, len(s.pairAllow))
	for _, e := range s.pairAllow {
		k := pairAllowKey(e.Src, e.Dst, e.Port)
		idx[k] = append(idx[k], e.FindingType)
	}
	s.pairAllowIdx = idx
}

// isPairAllowedLocked reports whether a pair rule hides a finding with
// this (src,dst,port,type). An empty rule FindingType matches every
// type on the tuple; a set one matches only that type. Caller holds
// s.mu (read or write).
func (s *Store) isPairAllowedLocked(src, dst, port, ftype string) bool {
	types, ok := s.pairAllowIdx[pairAllowKey(src, dst, port)]
	if !ok {
		return false
	}
	for _, t := range types {
		if t == "" || t == ftype {
			return true
		}
	}
	return false
}

// IsPairAllowed is the read-path entry used by findings_filter.go.
func (s *Store) IsPairAllowed(src, dst, port, ftype string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isPairAllowedLocked(src, dst, port, ftype)
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
		`INSERT OR IGNORE INTO pair_allowlist (src, dst, port, finding_type, detail, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Src, e.Dst, e.Port, e.FindingType, e.Detail, e.CreatedBy, e.CreatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("store: add pair allow: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Duplicate — rule already present. Return the existing id.
		var id int64
		_ = s.db.QueryRow(
			`SELECT id FROM pair_allowlist WHERE src=? AND dst=? AND port=? AND finding_type=?`,
			e.Src, e.Dst, e.Port, e.FindingType,
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
			log.Printf("store: remove pair allow %d: %v", id, err)
			return
		}
	}
	for i := range s.pairAllow {
		if s.pairAllow[i].ID == id {
			s.pairAllow = append(s.pairAllow[:i], s.pairAllow[i+1:]...)
			break
		}
	}
	s.rebuildPairAllowIdxLocked()
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
		if s.isHiddenLocked(n.SrcIP, n.DstIP) || s.isPairAllowedLocked(n.SrcIP, n.DstIP, n.DstPort, n.Type) {
			n.Dismissed = true
			dismissedIDs = append(dismissedIDs, n.ID)
		}
	}
	if s.db != nil && len(dismissedIDs) > 0 {
		for _, id := range dismissedIDs {
			if _, err := s.db.Exec(`UPDATE notifications SET dismissed = 1 WHERE id = ?`, id); err != nil {
				log.Printf("store: persist dismiss-on-hidden notification %d: %v", id, err)
			}
		}
	}
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
			log.Printf("store: prune expired suppressions: %v", err)
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
					log.Printf("store: persist dismiss notification %d: %v", id, err)
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
			log.Printf("store: persist dismiss all notifications: %v", err)
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
