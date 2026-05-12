package server

import (
	"net/url"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestFilterFindings_DismissedHiddenByDefault codifies the v0.18.0
// Dismissed semantic. The invariant: a Dismissed finding is invisible
// to every default-shaped query (Findings/Ack/Esc/IOC tabs all
// exclude it), and visible only when the caller explicitly requests
// it — either via `status=dismissed` (Dismissed tab) or via
// `include_dismissed=true` (counts endpoint).
//
// Articulating the invariant rather than the failure case: the
// previous filter applied no special-case to dismissed, so a future
// addition of the status would have surfaced rows in the IOC tab
// (which doesn't set a status filter) without anyone noticing. The
// test pins the contract so a future refactor of the status check
// can't silently regress this.
func TestFilterFindings_DismissedHiddenByDefault(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-12 09:00:00"},
		{ID: 2, Type: "TI Hit (IP)", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 96, Status: model.StatusAcknowledged, Timestamp: "2026-05-12 09:01:00"},
		{ID: 3, Type: "Suspicious URL", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 97, Status: model.StatusEscalated, Timestamp: "2026-05-12 09:02:00"},
		{ID: 4, Type: "TI Hit (IP)", SrcIP: "10.0.0.4", DstIP: "4.4.4.4", Score: 96, Status: model.StatusDismissed, Timestamp: "2026-05-12 09:03:00"},
		{ID: 5, Type: "Beaconing", SrcIP: "10.0.0.5", DstIP: "5.5.5.5", Score: 70, Status: model.StatusDismissed, Timestamp: "2026-05-12 09:04:00"},
	}

	cases := []struct {
		name    string
		query   url.Values
		wantIDs []int
	}{
		{
			name:    "default findings tab (status=open) excludes dismissed",
			query:   url.Values{"status": []string{"open"}},
			wantIDs: []int{1},
		},
		{
			name:    "ack tab excludes dismissed",
			query:   url.Values{"status": []string{"acknowledged"}},
			wantIDs: []int{2},
		},
		{
			name:    "esc tab excludes dismissed",
			query:   url.Values{"status": []string{"escalated"}},
			wantIDs: []int{3},
		},
		{
			name:    "ioc tab (no status, ioc_only) excludes dismissed even when dismissed row is an IOC type",
			query:   url.Values{"ioc_only": []string{"true"}},
			wantIDs: []int{2, 3},
		},
		{
			name:    "no status filter at all excludes dismissed",
			query:   url.Values{},
			wantIDs: []int{1, 2, 3},
		},
		{
			name:    "status=dismissed shows only dismissed",
			query:   url.Values{"status": []string{"dismissed"}},
			wantIDs: []int{4, 5},
		},
		{
			name:    "include_dismissed=true keeps dismissed in the result (counts endpoint path)",
			query:   url.Values{"include_dismissed": []string{"true"}},
			wantIDs: []int{1, 2, 3, 4, 5},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.filterFindings(append([]model.Finding{}, findings...), c.query)
			gotIDs := []int{}
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
			}
			if !sameIntSlice(gotIDs, c.wantIDs) {
				t.Errorf("query=%v: got IDs %v, want %v", c.query, gotIDs, c.wantIDs)
			}
		})
	}
}

func sameIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[int]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, v := range seen {
		if v != 0 {
			return false
		}
	}
	return true
}
