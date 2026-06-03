package server

// Detector-activity health signal: per-type counts of newly-detected
// findings over the last 7 days and the prior 7 days. The point is to
// catch a capture-side regression — a sensor that stopped shipping a log
// type, a Zeek policy that fell out — before an analyst notices the
// silence. A detector that produced new findings last week and zero this
// week is "dropped" and gets highlighted in the UI.
//
// Counts are over DetectedAt (durable first-seen), so this measures *new*
// detections per window, not active findings: a long-lived beacon first
// seen a month ago doesn't keep counting. That's the right signal — a
// healthy detector keeps surfacing new pairs; a dark sensor stops.
//
// Roll-up types (Host Risk Score, Correlated Activity) are excluded: they
// are derived from the network detectors, so their activity just mirrors
// the detectors already on the tile.

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

const detectorActivityWindowDays = 7

type detectorActivity struct {
	Type       string `json:"type"`
	Count7d    int    `json:"count_7d"`
	CountPrior int    `json:"count_prior_7d"`
	Total      int    `json:"total"`
	Dropped    bool   `json:"dropped"`
}

type detectorActivityResp struct {
	WindowDays  int                `json:"window_days"`
	GeneratedAt string             `json:"generated_at"`
	Detectors   []detectorActivity `json:"detectors"`
}

// handleDetectorActivity returns per-type new-detection counts for the last
// two 7-day windows plus an all-time total. Read-only operations data;
// analyst+ can see it. Only types that have ever fired are listed — a
// detector that has never produced a finding on this network isn't a
// regression, just absent traffic.
func (s *Server) handleDetectorActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := detectorActivityResp{
		WindowDays:  detectorActivityWindowDays,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Detectors:   computeDetectorActivity(s.store.GetFindings(), time.Now().Unix()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// computeDetectorActivity buckets findings by type into the last
// detectorActivityWindowDays-day window and the prior one, relative to now
// (epoch seconds). Roll-up types are excluded. A type with new findings in
// the prior window but none in the recent one is flagged Dropped — the
// capture-regression alarm. Result is sorted dropped-first, then by recent
// count descending, then by type. Pure so the windowing is testable without
// the clock or the store.
func computeDetectorActivity(findings []model.Finding, now int64) []detectorActivity {
	win := int64(detectorActivityWindowDays) * 86400
	recentCut := now - win
	priorCut := now - 2*win

	type counts struct{ recent, prior, total int }
	byType := make(map[string]*counts)
	for _, f := range findings {
		if model.IsRollupType(f.Type) {
			continue
		}
		c := byType[f.Type]
		if c == nil {
			c = &counts{}
			byType[f.Type] = c
		}
		c.total++
		if f.DetectedAt >= recentCut {
			c.recent++
		} else if f.DetectedAt >= priorCut {
			c.prior++
		}
	}

	out := make([]detectorActivity, 0, len(byType))
	for t, c := range byType {
		out = append(out, detectorActivity{
			Type:       t,
			Count7d:    c.recent,
			CountPrior: c.prior,
			Total:      c.total,
			// Dropped: fired last week, silent this week. Detectors that are
			// normally quieter than weekly have prior==0 and don't false-flag.
			Dropped: c.recent == 0 && c.prior > 0,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Dropped != b.Dropped {
			return a.Dropped
		}
		if a.Count7d != b.Count7d {
			return a.Count7d > b.Count7d
		}
		return a.Type < b.Type
	})
	return out
}
