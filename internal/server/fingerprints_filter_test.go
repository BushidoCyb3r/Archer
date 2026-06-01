package server

import (
	"net/url"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestFilterFindings_TLSPivotIncludesMaliciousFindings pins the pivot half of
// the TLS Fingerprints feature. The invariant: filtering by a JA3 (or JA4)
// fingerprint returns every finding carrying it — beacons AND the Malicious
// JA3/JA4 finding for that fingerprint — so clicking a known-bad row in the
// inventory lands on the C2 detection rather than an empty list. Before the
// fingerprint fields were populated on Malicious findings, the ja3/ja4 filter
// silently excluded them (empty JA3 field), so the most important pivot target
// was unreachable. The case set also covers a non-matching fingerprint
// (excluded) and case-insensitive matching of a pasted fingerprint.
func TestFilterFindings_TLSPivotIncludesMaliciousFindings(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80,
			Status: model.StatusOpen, Timestamp: "2026-05-18 09:00:00", JA3: "aabb"},
		{ID: 2, Type: "Malicious JA3", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 95,
			Status: model.StatusOpen, Timestamp: "2026-05-18 09:01:00", JA3: "aabb"},
		{ID: 3, Type: "Beaconing", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Score: 70,
			Status: model.StatusOpen, Timestamp: "2026-05-18 09:02:00", JA3: "ccdd"},
		{ID: 4, Type: "Malicious JA4", SrcIP: "10.0.0.4", DstIP: "4.4.4.4", Score: 95,
			Status: model.StatusOpen, Timestamp: "2026-05-18 09:03:00", JA4: "t13d_ja4"},
	}

	cases := []struct {
		name    string
		query   url.Values
		wantIDs map[int]bool
	}{
		{
			name:    "ja3 pivot returns beacon and Malicious JA3 sharing the fingerprint",
			query:   url.Values{"ja3": []string{"aabb"}},
			wantIDs: map[int]bool{1: true, 2: true},
		},
		{
			name:    "ja3 pivot is case-insensitive on pasted fingerprint",
			query:   url.Values{"ja3": []string{"AABB"}},
			wantIDs: map[int]bool{1: true, 2: true},
		},
		{
			name:    "ja4 pivot returns the Malicious JA4 finding",
			query:   url.Values{"ja4": []string{"t13d_ja4"}},
			wantIDs: map[int]bool{4: true},
		},
		{
			name:    "non-matching fingerprint returns nothing",
			query:   url.Values{"ja3": []string{"nope"}},
			wantIDs: map[int]bool{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.filterFindings(append([]model.Finding{}, findings...), c.query, 0)
			if len(got) != len(c.wantIDs) {
				t.Fatalf("got %d findings, want %d: %+v", len(got), len(c.wantIDs), got)
			}
			for _, f := range got {
				if !c.wantIDs[f.ID] {
					t.Errorf("unexpected finding ID %d in result", f.ID)
				}
			}
		})
	}
}
