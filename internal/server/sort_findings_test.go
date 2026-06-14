package server

import (
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestSortFindings_StrictWeakOrderingWithTiebreak is the LG-4 regression. The
// descending comparator returned `!less`, which for equal keys reports a<b AND
// b<a — not a strict weak ordering, so tie order was undefined and could differ
// between the listing and position endpoints (breaking Jump's landing page).
// Score is the default sort and heavily tied. The comparator now breaks ties
// on ID, giving a deterministic total order in both directions.
func TestSortFindings_StrictWeakOrderingWithTiebreak(t *testing.T) {
	mk := func(id, score int) model.Finding { return model.Finding{ID: id, Score: score} }
	ids := func(fs []model.Finding) []int {
		out := make([]int, len(fs))
		for i, f := range fs {
			out[i] = f.ID
		}
		return out
	}

	// All tied on score: the tiebreak imposes a deterministic ID-ascending
	// order regardless of direction and input permutation.
	for _, dir := range []string{"asc", "desc"} {
		in := []model.Finding{mk(3, 50), mk(1, 50), mk(2, 50)}
		sortFindings(in, "score", dir)
		if got, want := ids(in), []int{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("tied scores dir=%s: ids=%v, want %v", dir, got, want)
		}
	}

	// Mixed scores descending: score desc, ties broken by ID ascending.
	in := []model.Finding{mk(5, 90), mk(2, 99), mk(7, 90), mk(1, 99)}
	sortFindings(in, "score", "desc")
	if got, want := ids(in), []int{1, 2, 5, 7}; !reflect.DeepEqual(got, want) {
		t.Errorf("mixed desc: ids=%v, want %v (99s by id, then 90s by id)", got, want)
	}

	// Two different permutations of the same set must sort identically — the
	// total-order property the position endpoint depends on so the listing and
	// "where is finding X" answers agree.
	a := []model.Finding{mk(1, 50), mk(2, 50), mk(3, 80), mk(4, 80), mk(5, 10)}
	b := []model.Finding{mk(5, 10), mk(3, 80), mk(1, 50), mk(4, 80), mk(2, 50)}
	sortFindings(a, "score", "desc")
	sortFindings(b, "score", "desc")
	if !reflect.DeepEqual(ids(a), ids(b)) {
		t.Errorf("permutations sorted differently: %v vs %v — not a total order", ids(a), ids(b))
	}
}

// TestSortFindings_EverySortableClientColumn asserts the server orders by every
// column the findings table lets the analyst click — score, severity, type,
// src_ip, dst_ip, dst_port, timestamp, status, sensor — and falls back to score
// for an unknown column. The client now defers sorting to the server entirely
// (it renders /api/findings in the order received); a column the server doesn't
// recognize would silently collapse to score and mislead the analyst, so each
// one is pinned here. Ties break on ID ascending in every case.
func TestSortFindings_EverySortableClientColumn(t *testing.T) {
	ids := func(fs []model.Finding) []int {
		out := make([]int, len(fs))
		for i, f := range fs {
			out[i] = f.ID
		}
		return out
	}

	cases := []struct {
		col  string
		dir  string
		in   []model.Finding
		want []int
	}{
		{
			col: "severity", dir: "asc",
			in: []model.Finding{
				{ID: 1, Severity: model.SevLow},
				{ID: 2, Severity: model.SevCritical},
				{ID: 3, Severity: model.SevMedium},
			},
			want: []int{1, 3, 2}, // asc by severityOrder: LOW(1) < MEDIUM(2) < CRITICAL(4)
		},
		{
			col: "type", dir: "asc",
			in: []model.Finding{
				{ID: 1, Type: "Strobe"},
				{ID: 2, Type: "Beacon"},
				{ID: 3, Type: "DNS Tunneling"},
			},
			want: []int{2, 3, 1},
		},
		{
			col: "src_ip", dir: "asc",
			in: []model.Finding{
				{ID: 1, SrcIP: "10.0.0.9"},
				{ID: 2, SrcIP: "10.0.0.1"},
			},
			want: []int{2, 1},
		},
		{
			col: "dst_ip", dir: "asc",
			in: []model.Finding{
				{ID: 1, DstIP: "203.0.113.9"},
				{ID: 2, DstIP: "203.0.113.1"},
			},
			want: []int{2, 1},
		},
		{
			// DstPort is a string — lexicographic, so "443" sorts before "80".
			col: "dst_port", dir: "asc",
			in: []model.Finding{
				{ID: 1, DstPort: "80"},
				{ID: 2, DstPort: "443"},
			},
			want: []int{2, 1},
		},
		{
			col: "timestamp", dir: "asc",
			in: []model.Finding{
				{ID: 1, Timestamp: "2026-06-14T10:00:00Z"},
				{ID: 2, Timestamp: "2026-06-14T09:00:00Z"},
			},
			want: []int{2, 1},
		},
		{
			col: "status", dir: "asc",
			in: []model.Finding{
				{ID: 1, Status: model.StatusEscalated},
				{ID: 2, Status: model.StatusAcknowledged},
			},
			want: []int{2, 1},
		},
		{
			col: "sensor", dir: "asc",
			in: []model.Finding{
				{ID: 1, Sensor: "sensor-west"},
				{ID: 2, Sensor: "sensor-east"},
			},
			want: []int{2, 1},
		},
		{
			// Tied keys break on ID ascending, exercised here on sensor.
			col: "sensor", dir: "desc",
			in: []model.Finding{
				{ID: 3, Sensor: "s"},
				{ID: 1, Sensor: "s"},
				{ID: 2, Sensor: "s"},
			},
			want: []int{1, 2, 3},
		},
		{
			// Unknown column falls back to score (default branch).
			col: "bogus", dir: "desc",
			in: []model.Finding{
				{ID: 1, Score: 10},
				{ID: 2, Score: 90},
				{ID: 3, Score: 50},
			},
			want: []int{2, 3, 1},
		},
	}

	for _, tc := range cases {
		sortFindings(tc.in, tc.col, tc.dir)
		if got := ids(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("sort col=%q dir=%q: ids=%v, want %v", tc.col, tc.dir, got, tc.want)
		}
	}
}
