package store

import (
	"database/sql"
	"log/slog"
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
	DayUTC          string  `json:"day_utc"`
	MaxScore        int     `json:"max_score"`
	MaxScoreAt      int64   `json:"max_score_at"`
	LastScore       int     `json:"last_score"`
	LastScoreAt     int64   `json:"last_score_at"`
	Severity        string  `json:"severity"`
	TSScore         float64 `json:"ts_score"`
	DSScore         float64 `json:"ds_score"`
	HistScore       float64 `json:"hist_score"`
	DurScore        float64 `json:"dur_score"`
	SpectralRescued bool    `json:"spectral_rescued"`
	SpectralPeriod  float64 `json:"spectral_period,omitempty"`
	TSRaw           float64 `json:"ts_raw"`
	TSMultimodal    float64 `json:"ts_mm"`
	TSEntropy       float64 `json:"ts_ent"`
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
		slog.Error("store: beacon_history begin tx", "err", err)
		return
	}
	// NEW-84 fixed here. The reachable case: the DGA augmentation
	// upgrades severity one step (High -> Critical) whenever the
	// destination looks algorithmic, *including* when the +15 score
	// bump leaves the score still below the 80 Critical threshold
	// (e.g. raw 64 -> 79, severity forced High -> Critical). If an
	// earlier same-day pass for the same beacon recorded that same
	// numeric score (79) without DGA — High — a strict
	// `excluded.max_score > max_score` gate never fires on the later
	// equal-score pass, so the row stays High while the beacon is
	// really Critical and the analyst's chart/severity is wrong.
	//
	// Fix: max_score / max_score_at stay strict-greater so the peak
	// value and the time it was first reached are unchanged (NEW-76
	// semantics preserved). The peak-characterization columns
	// (severity + the four sub-scores) additionally update when the
	// score ties but the new pass is strictly more severe — compared
	// via an explicit severity rank since the column is TEXT and
	// lexical order is not severity order. A tie with equal-or-lower
	// severity still holds, so a later benign pass can't downgrade
	// the recorded peak.
	sevRank := func(col string) string {
		return `(CASE ` + col + ` WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 WHEN 'INFO' THEN 1 ELSE 0 END)`
	}
	peakWin := `excluded.max_score > max_score OR (excluded.max_score = max_score AND ` +
		sevRank("excluded.severity") + ` > ` + sevRank("severity") + `)`
	stmt, err := tx.Prepare(`
        INSERT INTO beacon_history
            (fingerprint, day_utc, finding_type, src_ip, dst_ip, dst_port,
             host, uri, sensor,
             max_score, max_score_at, last_score, last_score_at,
             severity, ts_score, ds_score, hist_score, dur_score,
             spectral_rescued, spectral_period,
             ts_raw, ts_mm, ts_ent,
             created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint, day_utc) DO UPDATE SET
            last_score       = excluded.last_score,
            last_score_at    = excluded.last_score_at,
            max_score        = CASE WHEN excluded.max_score > max_score THEN excluded.max_score    ELSE max_score    END,
            max_score_at     = CASE WHEN excluded.max_score > max_score THEN excluded.max_score_at ELSE max_score_at END,
            severity         = CASE WHEN ` + peakWin + ` THEN excluded.severity        ELSE severity        END,
            ts_score         = CASE WHEN ` + peakWin + ` THEN excluded.ts_score        ELSE ts_score        END,
            ds_score         = CASE WHEN ` + peakWin + ` THEN excluded.ds_score        ELSE ds_score        END,
            hist_score       = CASE WHEN ` + peakWin + ` THEN excluded.hist_score      ELSE hist_score      END,
            dur_score        = CASE WHEN ` + peakWin + ` THEN excluded.dur_score       ELSE dur_score       END,
            spectral_rescued = CASE WHEN ` + peakWin + ` THEN excluded.spectral_rescued ELSE spectral_rescued END,
            spectral_period  = CASE WHEN ` + peakWin + ` THEN excluded.spectral_period  ELSE spectral_period  END,
            ts_raw           = CASE WHEN ` + peakWin + ` THEN excluded.ts_raw           ELSE ts_raw           END,
            ts_mm            = CASE WHEN ` + peakWin + ` THEN excluded.ts_mm            ELSE ts_mm            END,
            ts_ent           = CASE WHEN ` + peakWin + ` THEN excluded.ts_ent           ELSE ts_ent           END
    `)
	if err != nil {
		_ = tx.Rollback()
		slog.Error("store: beacon_history prepare", "err", err)
		return
	}
	defer stmt.Close()

	for _, f := range findings {
		if f.Type != "Beaconing" && f.Type != "HTTP Beaconing" && f.Type != "DNS Beaconing" {
			continue
		}
		if !newFPSet[f.Fingerprint()] {
			continue
		}
		spectralRescued := 0
		if f.SpectralRescued {
			spectralRescued = 1
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
			f.Sensor,
			f.Score, // max_score (first-write value; UPSERT decides whether to keep)
			now,     // max_score_at
			f.Score, // last_score (always replaced on conflict)
			now,     // last_score_at
			string(f.Severity),
			f.TSScore,
			f.DSScore,
			f.HistScore,
			f.DurScore,
			spectralRescued,
			f.SpectralPeriod,
			f.TSRaw,
			f.TSMultimodal,
			f.TSEntropy,
			now,
		)
		if err != nil {
			slog.Error("store: beacon_history insert", "err", err)
			continue
		}
	}
	if err := tx.Commit(); err != nil {
		slog.Error("store: beacon_history commit", "err", err)
	}
}

// BeaconHistory returns history rows for the given key sorted
// ascending by day_utc, capped to the retention window. Empty slice
// when no rows match (caller treats that as "no history yet" rather
// than an error). Caller derives the key from a finding via
// Finding.BeaconHistoryKey().
//
// The day_utc >= cutoff filter is defense-in-depth against three
// failure modes the retention store-side enforcement alone doesn't
// cover: (a) PurgeBeaconHistory hasn't run yet on a fresh boot, (b)
// a future operator promotes retention to 365 days but the chart
// still wants 30, (c) a malformed manual SQL insert with a date in
// the distant past or future would otherwise distort the chart's
// x-axis scale. NEW-88 from the twentieth audit round.
func (s *Store) BeaconHistory(key string) []BeaconHistoryRow {
	if s.db == nil || key == "" {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -BeaconHistoryRetentionDays).Format("2006-01-02")
	rows, err := s.db.Query(`
        SELECT day_utc, max_score, max_score_at, last_score, last_score_at,
               severity, ts_score, ds_score, hist_score, dur_score,
               spectral_rescued, spectral_period,
               ts_raw, ts_mm, ts_ent
        FROM beacon_history
        WHERE fingerprint = ?
          AND day_utc >= ?
        ORDER BY day_utc ASC
    `, key, cutoff)
	if err != nil {
		slog.Error("store: beacon_history query", "err", err)
		return nil
	}
	defer rows.Close()
	var out []BeaconHistoryRow
	for rows.Next() {
		var r BeaconHistoryRow
		var spectralRescued int
		if err := rows.Scan(
			&r.DayUTC,
			&r.MaxScore, &r.MaxScoreAt,
			&r.LastScore, &r.LastScoreAt,
			&r.Severity,
			&r.TSScore, &r.DSScore, &r.HistScore, &r.DurScore,
			&spectralRescued, &r.SpectralPeriod,
			&r.TSRaw, &r.TSMultimodal, &r.TSEntropy,
		); err != nil {
			slog.Error("store: beacon_history scan", "err", err)
			continue
		}
		r.SpectralRescued = spectralRescued != 0
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
		slog.Error("store: beacon_history purge", "err", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// SuggestMinDays is the minimum number of distinct UTC days a beacon must
// appear in beacon_history before it qualifies as a suggestion. 14 days
// is deliberately conservative — a patient-C2 that beaconed for two weeks
// and then went quiet should not be suggested; two weeks of acknowledged
// repetition is the floor where cloud sync / OS update confidence is high.
const SuggestMinDays = 14

// SuggestedPairAllowlist returns beacon identities that satisfy both gates:
// (1) the identity appears in beacon_history across SuggestMinDays+ distinct
// UTC days, and (2) a current finding for that identity has status=acknowledged.
// Identities already covered by a pair_allowlist rule are excluded.
//
// Each returned entry is a single exact beacon identity (type, src, dst, port,
// host, uri, sensor) — no outer collapse. This preserves the exact evidence
// that qualified the suggestion and prevents mixed stats across distinct beacons
// that share an IP:port.
//
// The findings JOIN includes a sensor fallback so pre-migration history rows
// (sensor='') remain matchable by any sensor's acknowledged finding.
func (s *Store) SuggestedPairAllowlist() []model.SuggestedAllowEntry {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`
        SELECT
            bh.finding_type, bh.src_ip, bh.dst_ip, bh.dst_port,
            bh.host, bh.uri, bh.sensor,
            COUNT(DISTINCT bh.day_utc)   AS day_count,
            MIN(bh.day_utc)              AS first_seen,
            MAX(bh.day_utc)              AS last_seen,
            MAX(bh.max_score)            AS peak_score,
            COALESCE(MAX(f.analyst), '') AS acked_by
        FROM beacon_history bh
        INNER JOIN findings f
            ON  f.src_ip   = bh.src_ip
            AND f.dst_ip   = bh.dst_ip
            AND f.dst_port = bh.dst_port
            AND f.type     = bh.finding_type
            AND (bh.sensor = '' OR COALESCE(f.sensor, '') = bh.sensor)
            AND f.status   = 'acknowledged'
        WHERE NOT EXISTS (
            SELECT 1 FROM pair_allowlist pa
            WHERE pa.src  = bh.src_ip
              AND pa.dst  = bh.dst_ip
              AND pa.port = bh.dst_port
              AND (pa.finding_type = '' OR pa.finding_type = bh.finding_type)
              AND (pa.sensor       = '' OR pa.sensor       = bh.sensor)
        )
        GROUP BY bh.finding_type, bh.src_ip, bh.dst_ip, bh.dst_port,
                 bh.host, bh.uri, bh.sensor
        HAVING COUNT(DISTINCT bh.day_utc) >= ?
        ORDER BY day_count DESC, peak_score DESC
    `, SuggestMinDays)
	if err != nil {
		slog.Error("store: suggested pair allowlist", "err", err)
		return nil
	}
	defer rows.Close()
	var out []model.SuggestedAllowEntry
	for rows.Next() {
		var e model.SuggestedAllowEntry
		if err := rows.Scan(
			&e.FindingType, &e.SrcIP, &e.DstIP, &e.DstPort,
			&e.Host, &e.URI, &e.Sensor,
			&e.DayCount, &e.FirstSeen, &e.LastSeen, &e.PeakScore, &e.AckedBy,
		); err != nil {
			slog.Error("store: suggested pair allowlist scan", "err", err)
			continue
		}
		out = append(out, e)
	}
	return out
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
		slog.Error("store: beacon_history lookup", "err", err)
		return 0, 0, false
	}
	return maxScore, lastScore, true
}
