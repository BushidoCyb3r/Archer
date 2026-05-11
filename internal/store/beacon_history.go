package store

import (
	"database/sql"
	"log"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// beaconHistoryRetentionDays is the rolling window for beacon_history
// rows. Const, not config — the SPA's evolution chart range is also
// 30 days, so longer retention is invisible until the chart range
// grows. Promote to config.Config when an operator asks for it; the
// migration is a five-line change.
const beaconHistoryRetentionDays = 30

// BeaconHistoryRow is the SPA-facing projection of one row in the
// beacon_history table. Matches the JSON shape /api/findings/{id}/history
// returns; consumed by the detail-pane evolution chart.
type BeaconHistoryRow struct {
	DayUTC    string  `json:"day_utc"`
	Score     int     `json:"score"`
	Severity  string  `json:"severity"`
	TSScore   float64 `json:"ts_score"`
	DSScore   float64 `json:"ds_score"`
	HistScore float64 `json:"hist_score"`
	DurScore  float64 `json:"dur_score"`
}

// saveBeaconHistory writes one beacon_history row per this-run
// Beaconing / HTTP Beaconing finding. Called from SetFindings after
// saveFindings completes — beacon_history is independent of the
// findings table (its key is self-describing via BeaconHistoryKey),
// so the order doesn't matter for crash consistency, but doing it
// after saveFindings keeps the failure modes simple to reason about.
//
// "First pass of the UTC day wins" semantics: the PRIMARY KEY
// (fingerprint, day_utc) + INSERT … ON CONFLICT DO NOTHING means a
// re-analysis later the same day leaves the morning's snapshot in
// place. That's deliberate — the morning pass sees the day's earlier
// logs and is the more representative score; a noon re-run with
// only partial logs would otherwise overwrite it.
//
// newFPSet filters the input to only this-run's emits: preserved
// historical findings (the SetFindings preserve-loop appends them
// to the same slice with IsNew=false) didn't actually emit today
// and must not generate a history row.
func (s *Store) saveBeaconHistory(findings []model.Finding, newFPSet map[model.Fingerprint]bool) {
	if s.db == nil {
		return
	}
	dayUTC := time.Now().UTC().Format("2006-01-02")
	createdAt := time.Now().Unix()

	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: beacon_history begin tx: %v", err)
		return
	}
	stmt, err := tx.Prepare(`
        INSERT INTO beacon_history
            (fingerprint, day_utc, finding_type, src_ip, dst_ip, dst_port,
             host, uri, score, severity,
             ts_score, ds_score, hist_score, dur_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint, day_utc) DO NOTHING
    `)
	if err != nil {
		_ = tx.Rollback()
		log.Printf("store: beacon_history prepare: %v", err)
		return
	}
	defer stmt.Close()

	var wrote int
	for _, f := range findings {
		if f.Type != "Beaconing" && f.Type != "HTTP Beaconing" {
			continue
		}
		if !newFPSet[f.Fingerprint()] {
			continue
		}
		_, err := stmt.Exec(
			f.BeaconHistoryKey(),
			dayUTC,
			f.Type,
			f.SrcIP,
			f.DstIP,
			f.DstPort,
			f.Hostname,
			f.URI,
			f.Score,
			string(f.Severity),
			f.TSScore,
			f.DSScore,
			f.HistScore,
			f.DurScore,
			createdAt,
		)
		if err != nil {
			log.Printf("store: beacon_history insert: %v", err)
			continue
		}
		wrote++
	}
	if err := tx.Commit(); err != nil {
		log.Printf("store: beacon_history commit: %v", err)
	}
}

// BeaconHistory returns every history row for the given key sorted
// ascending by day_utc. Empty slice when no rows match (caller treats
// that as "no history yet" rather than an error). Caller derives the
// key from a finding via Finding.BeaconHistoryKey().
func (s *Store) BeaconHistory(key string) []BeaconHistoryRow {
	if s.db == nil || key == "" {
		return nil
	}
	rows, err := s.db.Query(`
        SELECT day_utc, score, severity, ts_score, ds_score, hist_score, dur_score
        FROM beacon_history
        WHERE fingerprint = ?
        ORDER BY day_utc ASC
    `, key)
	if err != nil {
		log.Printf("store: beacon_history query: %v", err)
		return nil
	}
	defer rows.Close()
	var out []BeaconHistoryRow
	for rows.Next() {
		var r BeaconHistoryRow
		if err := rows.Scan(&r.DayUTC, &r.Score, &r.Severity, &r.TSScore, &r.DSScore, &r.HistScore, &r.DurScore); err != nil {
			log.Printf("store: beacon_history scan: %v", err)
			continue
		}
		out = append(out, r)
	}
	return out
}

// PurgeBeaconHistory deletes rows whose day_utc is older than the
// retention window. Called from the watch's first-tick-of-UTC-day
// branch so the sweep happens exactly once per day regardless of
// how many analyze passes run. Returns the number of rows removed
// for the operator-visible status line.
func (s *Store) PurgeBeaconHistory() int64 {
	if s.db == nil {
		return 0
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -beaconHistoryRetentionDays).Format("2006-01-02")
	res, err := s.db.Exec(`DELETE FROM beacon_history WHERE day_utc < ?`, cutoff)
	if err != nil {
		log.Printf("store: beacon_history purge: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// hasBeaconHistoryRow is a test helper exposed via the unexported
// type for store_test.go assertions. Returns the persisted score for
// the (key, day) tuple, or -1 if no row exists. Lives here (not in
// _test.go) because store_test.go is in package store and can reach
// it directly; an exported helper would litter the public API.
func (s *Store) hasBeaconHistoryRow(key, day string) (int, bool) {
	if s.db == nil {
		return 0, false
	}
	var score int
	err := s.db.QueryRow(`SELECT score FROM beacon_history WHERE fingerprint=? AND day_utc=?`, key, day).Scan(&score)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		log.Printf("store: beacon_history lookup: %v", err)
		return 0, false
	}
	return score, true
}
