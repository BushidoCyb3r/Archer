package store

import (
	"database/sql"
	"log"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// BeaconHistoryRetentionDays is the rolling window for beacon_history
// rows. Const, not config — the SPA's evolution chart range is also
// 30 days, so longer retention is invisible until the chart range
// grows. Promote to config.Config when an operator asks for it; the
// migration is a five-line change.
//
// Exported so callers that surface the retention in user-facing
// strings (watch.go's purge status SSE, future Settings UI labels)
// reference one source of truth rather than duplicating the literal.
// NEW-82 from the nineteenth audit round closed the watch.go
// duplication.
const BeaconHistoryRetentionDays = 30

// BeaconHistoryRow is the SPA-facing projection of one row in the
// beacon_history table. Matches the JSON shape /api/findings/{id}/history
// returns; consumed by the detail-pane evolution chart.
//
// MaxScore is the highest composite score observed for this beacon
// on this UTC day across every analyze pass that ran. The chart
// renders MaxScore because the spike is the trajectory-meaningful
// number an analyst cares about — a beacon that hit 88 at noon and
// fell back to 60 by evening is a different story from one that
// held steady at 60 all day, and the chart should distinguish them.
//
// LastScore is the most recent score written for this beacon on
// this UTC day. Exposed for forensic / per-pass detail but not
// currently rendered on the chart. The TSScore / DSScore /
// HistScore / DurScore fields track the *max-score* write
// (sub-axis explanation for the high day), not the last-score
// write.
type BeaconHistoryRow struct {
	DayUTC      string  `json:"day_utc"`
	MaxScore    int     `json:"max_score"`
	MaxScoreAt  int64   `json:"max_score_at"`
	LastScore   int     `json:"last_score"`
	LastScoreAt int64   `json:"last_score_at"`
	Severity    string  `json:"severity"`
	TSScore     float64 `json:"ts_score"`
	DSScore     float64 `json:"ds_score"`
	HistScore   float64 `json:"hist_score"`
	DurScore    float64 `json:"dur_score"`
}

// saveBeaconHistory writes one beacon_history row per this-run
// Beaconing / HTTP Beaconing finding. Called from SetFindings after
// saveFindings completes — beacon_history is independent of the
// findings table (its key is self-describing via BeaconHistoryKey),
// so the order doesn't matter for crash consistency, but doing it
// after saveFindings keeps the failure modes simple to reason about.
//
// UPSERT semantics: when a beacon's row already exists for today's
// UTC day, the conflict-resolution branch runs in two parts. (a)
// last_score / last_score_at always update to reflect the most
// recent pass's reading. (b) max_score / max_score_at / severity /
// sub-axis scores only update when the new score exceeds the
// existing max. The net effect: a single row per beacon per day
// carries both "the spike" and "the most recent reading."
//
// Why both numbers matter: under sub-daily watch cadence (or
// admin-triggered re-analysis), a noon spike followed by an evening
// fallback can be the signal an analyst needs to see. Pre-v0.16.1
// shipped INSERT … ON CONFLICT DO NOTHING with a comment claiming
// "morning's snapshot is the more representative score" — that was
// factually wrong (the analyzer scores against the accumulated
// reservoir window, not "today's logs") and the resulting
// silent-drop hid the exact adversarial-tuning pattern the chart
// is supposed to surface. NEW-76 from the eighteenth audit round
// drove the redesign.
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
	now := time.Now().Unix()

	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: beacon_history begin tx: %v", err)
		return
	}
	// Known edge case (NEW-84): the severity branch fires only when
	// excluded.max_score > max_score (strict). If a beacon already at
	// score 99 has its severity bumped a step by the DGA augmentation
	// in a later same-day pass (one-step severity upgrade applies
	// even when score is already at the cap of 99), the history row
	// keeps the earlier pass's severity. Realistic but rare —
	// requires two same-day passes both producing the same numeric
	// max, with the later pass having a different severity. Document
	// here; restructure to a separate severity-tracking column only
	// if operators see this in practice.
	stmt, err := tx.Prepare(`
        INSERT INTO beacon_history
            (fingerprint, day_utc, finding_type, src_ip, dst_ip, dst_port,
             host, uri,
             max_score, max_score_at, last_score, last_score_at,
             severity, ts_score, ds_score, hist_score, dur_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint, day_utc) DO UPDATE SET
            last_score    = excluded.last_score,
            last_score_at = excluded.last_score_at,
            max_score     = CASE WHEN excluded.max_score > max_score THEN excluded.max_score    ELSE max_score    END,
            max_score_at  = CASE WHEN excluded.max_score > max_score THEN excluded.max_score_at ELSE max_score_at END,
            severity      = CASE WHEN excluded.max_score > max_score THEN excluded.severity     ELSE severity     END,
            ts_score      = CASE WHEN excluded.max_score > max_score THEN excluded.ts_score     ELSE ts_score     END,
            ds_score      = CASE WHEN excluded.max_score > max_score THEN excluded.ds_score     ELSE ds_score     END,
            hist_score    = CASE WHEN excluded.max_score > max_score THEN excluded.hist_score   ELSE hist_score   END,
            dur_score     = CASE WHEN excluded.max_score > max_score THEN excluded.dur_score    ELSE dur_score    END
    `)
	if err != nil {
		_ = tx.Rollback()
		log.Printf("store: beacon_history prepare: %v", err)
		return
	}
	defer stmt.Close()

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
			f.Score, // max_score (first-write value; UPSERT decides whether to keep)
			now,     // max_score_at
			f.Score, // last_score (always replaced on conflict)
			now,     // last_score_at
			string(f.Severity),
			f.TSScore,
			f.DSScore,
			f.HistScore,
			f.DurScore,
			now,
		)
		if err != nil {
			log.Printf("store: beacon_history insert: %v", err)
			continue
		}
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
        SELECT day_utc, max_score, max_score_at, last_score, last_score_at,
               severity, ts_score, ds_score, hist_score, dur_score
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
		if err := rows.Scan(
			&r.DayUTC,
			&r.MaxScore, &r.MaxScoreAt,
			&r.LastScore, &r.LastScoreAt,
			&r.Severity,
			&r.TSScore, &r.DSScore, &r.HistScore, &r.DurScore,
		); err != nil {
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
	cutoff := time.Now().UTC().AddDate(0, 0, -BeaconHistoryRetentionDays).Format("2006-01-02")
	res, err := s.db.Exec(`DELETE FROM beacon_history WHERE day_utc < ?`, cutoff)
	if err != nil {
		log.Printf("store: beacon_history purge: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// beaconHistoryRowSnapshot is a test helper exposed via the unexported
// type for store_test.go assertions. Returns the persisted max_score
// + last_score for the (key, day) tuple, or `ok=false` if no row
// exists. Lives here (not in _test.go) because store_test.go is in
// package store and can reach it directly; an exported helper would
// litter the public API.
func (s *Store) beaconHistoryRowSnapshot(key, day string) (maxScore int, lastScore int, ok bool) {
	if s.db == nil {
		return 0, 0, false
	}
	err := s.db.QueryRow(
		`SELECT max_score, last_score FROM beacon_history WHERE fingerprint=? AND day_utc=?`,
		key, day,
	).Scan(&maxScore, &lastScore)
	if err == sql.ErrNoRows {
		return 0, 0, false
	}
	if err != nil {
		log.Printf("store: beacon_history lookup: %v", err)
		return 0, 0, false
	}
	return maxScore, lastScore, true
}
