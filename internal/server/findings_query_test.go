package server

import (
	"net/url"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestFilterFindings_Query pins the Lucene-style `q` parameter contract: when
// present, q is ANDed on top of the always-on exclusions and view scoping, and
// a malformed q is a reported error rather than a silent match-all or
// match-nothing.
func TestFilterFindings_Query(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443", Score: 98, Severity: model.SevCritical, Status: model.StatusOpen, Timestamp: "2026-05-12 09:00:00"},
		{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", DstPort: "53", Score: 70, Severity: model.SevMedium, Status: model.StatusOpen, Timestamp: "2026-05-12 09:01:00"},
		{ID: 3, Type: "DNS Tunneling", SrcIP: "192.168.1.5", DstIP: "3.3.3.3", DstPort: "53", Score: 95, Severity: model.SevHigh, Status: model.StatusOpen, Timestamp: "2026-05-12 09:02:00"},
		{ID: 4, Type: "Beacon", SrcIP: "10.0.0.9", DstIP: "4.4.4.4", DstPort: "8080", Score: 92, Severity: model.SevHigh, Status: model.StatusOpen, Timestamp: "2026-05-12 09:03:00"},
	}

	cases := []struct {
		name    string
		q       string
		wantIDs []int
	}{
		{"type and score", "type:Beacon AND score:>=90", []int{1, 4}},
		{"src cidr", "src:10.0.0.0/24", []int{1, 2, 4}},
		{"port set", "port:53", []int{2, 3}},
		{"boolean or with grouping", "(type:Beacon OR type:\"DNS Tunneling\") AND score:>95", []int{1}},
		{"bare term", "192.168.1.5", []int{3}},
		{"empty q matches all", "", []int{1, 2, 3, 4}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := url.Values{}
			if c.q != "" {
				q.Set("q", c.q)
			}
			got, err := s.filterFindings(append([]model.Finding{}, findings...), q, 0)
			if err != nil {
				t.Fatalf("q=%q unexpected error: %v", c.q, err)
			}
			gotIDs := []int{}
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
			}
			if !sameIntSlice(gotIDs, c.wantIDs) {
				t.Errorf("q=%q: got IDs %v, want %v", c.q, gotIDs, c.wantIDs)
			}
		})
	}
}

func TestFilterFindings_BadQueryErrors(t *testing.T) {
	s := newAuditTestServer(t)
	findings := []model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 98, Status: model.StatusOpen, Timestamp: "2026-05-12 09:00:00"},
	}
	for _, bad := range []string{"type:", "(type:Beacon", "bogus:value"} {
		q := url.Values{"q": []string{bad}}
		if _, err := s.filterFindings(append([]model.Finding{}, findings...), q, 0); err == nil {
			t.Errorf("q=%q: expected error, got nil", bad)
		}
	}
}
