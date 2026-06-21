package server

import (
	"net/url"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestSpectralOnlyFilter_MatchesStructuredFlag pins the spectral_only filter
// contract. Spectral is annotation-only (the 2026-06-21 timing-axis
// validation demoted the score boost to a hint), and the filter now selects
// findings by the structured SpectralRescued flag rather than a Detail
// substring. This replaces the old marker-string lockstep test: the filter no
// longer greps Detail, so a wording change to the annotation can't silently
// break it — but a regression that drops the flag check, or reverts to a
// substring match the emitters no longer produce, fails here.
//
// The SPA's "Spectral signal only" chip and the `spectral:true` query token
// both resolve to this server-side flag check, so this is the single contract
// guarding all three surfaces.
func TestSpectralOnlyFilter_MatchesStructuredFlag(t *testing.T) {
	s := newAuditTestServer(t)

	findings := []model.Finding{
		// Flag set, but the Detail carries the new wording (no "rescued"
		// substring) — proving the filter keys on the flag, not the text.
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443", Score: 80, Timestamp: "2026-05-12 09:00:00",
			SpectralRescued: true, Detail: "Spectral signal (informational, unscored): period 3600s"},
		// No spectral signal.
		{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", DstPort: "443", Score: 80, Timestamp: "2026-05-12 09:01:00"},
		// A finding whose Detail happens to mention spectral words but whose
		// flag is false must NOT match — the flag is authoritative.
		{ID: 3, Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "3.3.3.3", DstPort: "443", Score: 80, Timestamp: "2026-05-12 09:02:00",
			Detail: "no spectral signal here"},
	}

	q := url.Values{}
	q.Set("spectral_only", "true")
	got, err := s.filterFindings(findings, q, 0)
	if err != nil {
		t.Fatalf("filterFindings: %v", err)
	}
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("spectral_only should return exactly the flagged finding (id 1); got %v", idsOf(got))
	}
}
