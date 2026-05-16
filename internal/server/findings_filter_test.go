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

// TestFilterFindings_PairAllowlist codifies the pair-allowlist
// invariant end-to-end through the real filter path:
//
//  1. A rule scoped to (src,dst,port,type) hides exactly the findings
//     matching all four — not a different port, not a different dst,
//     not a different type on the same pair.
//  2. The type-scope is the beacon-hunter safety property: muting
//     "Beaconing" on a known-good DNS pair must leave "DNS Tunneling"
//     on that same pair visible (real tradecraft to a legit resolver
//     still surfaces). An empty FindingType is the deliberate broaden
//     that hides every type on the tuple.
//  3. It is a pure view filter: removing the rule restores the
//     finding on the very next filter pass over the same unchanged
//     finding slice — no re-analysis, nothing regenerated.
//
// Asserting the invariant (precision + type-scope safety + reversible)
// rather than a single failure case: a future refactor of the tuple
// key or the type-scope check can't silently regress any one axis
// without a wantIDs mismatch here.
func TestFilterFindings_PairAllowlist(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-16 09:00:00"},
		{ID: 2, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53", Score: 90, Status: model.StatusOpen, Timestamp: "2026-05-16 09:01:00"},
		{ID: 3, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-16 09:02:00"},
		{ID: 4, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "9.9.9.9", DstPort: "53", Score: 80, Status: model.StatusOpen, Timestamp: "2026-05-16 09:03:00"},
		{ID: 5, Type: "Beaconing", SrcIP: "10.0.0.9", DstIP: "8.8.8.8", DstPort: "53", Score: 75, Status: model.StatusOpen, Timestamp: "2026-05-16 09:04:00"},
		{ID: 6, Type: "TI Hit (IP)", SrcIP: "10.0.0.9", DstIP: "8.8.8.8", DstPort: "53", Score: 96, Status: model.StatusOpen, Timestamp: "2026-05-16 09:05:00"},
	}
	filterIDs := func() []int {
		got := s.filterFindings(append([]model.Finding{}, findings...), url.Values{})
		ids := []int{}
		for _, f := range got {
			ids = append(ids, f.ID)
		}
		return ids
	}

	if got := filterIDs(); !sameIntSlice(got, []int{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("baseline: got %v, want all 6 visible", got)
	}

	// Scoped rule: only "Beaconing" on the exact DNS tuple.
	scopedID, err := s.store.AddPairAllow(model.PairAllowEntry{
		Src: "10.0.0.1", Dst: "1.1.1.1", Port: "53", FindingType: "Beaconing",
	})
	if err != nil {
		t.Fatalf("AddPairAllow scoped: %v", err)
	}
	if got := filterIDs(); !sameIntSlice(got, []int{2, 3, 4, 5, 6}) {
		t.Errorf("scoped rule: got %v, want {2,3,4,5,6} (only ID 1 hidden; DNS Tunneling on the same pair must stay visible)", got)
	}

	// All-types rule on a second pair.
	if _, err := s.store.AddPairAllow(model.PairAllowEntry{
		Src: "10.0.0.9", Dst: "8.8.8.8", Port: "53", FindingType: "",
	}); err != nil {
		t.Fatalf("AddPairAllow all-types: %v", err)
	}
	if got := filterIDs(); !sameIntSlice(got, []int{2, 3, 4}) {
		t.Errorf("all-types rule: got %v, want {2,3,4} (both types on the 2nd pair hidden)", got)
	}

	// Remove the scoped rule — ID 1 must come straight back on the
	// same finding slice; the all-types rule still hides 5 and 6.
	s.store.RemovePairAllow(scopedID)
	if got := filterIDs(); !sameIntSlice(got, []int{1, 2, 3, 4}) {
		t.Errorf("after remove: got %v, want {1,2,3,4} (ID 1 restored with no re-analysis)", got)
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
