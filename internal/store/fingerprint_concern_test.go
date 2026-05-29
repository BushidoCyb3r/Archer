package store

import (
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestFingerprintConcern covers the read-time rarity/cluster classification that
// colours the beacon detail-pane fingerprint row. The invariant: a rare TLS
// client fingerprint (few destinations) escalates by JA4-vs-JA3 confidence and
// cross-host clustering, a common (browser/SDK) fingerprint never escalates, and
// an unknown fingerprint yields no row at all. This is enrichment, so the level
// must be empty only when nothing resolves — never empty for a known fingerprint.
func TestFingerprintConcern(t *testing.T) {
	s := New(config.Default())
	s.SetFingerprintPrevalence(
		map[string]model.FingerprintStat{
			// implant shape: rare (1 dst), clustered across 3 internal hosts
			"t13i131000_aaaa_bbbb": {Conns: 43, SrcHosts: 3, Dsts: 1},
			// browser shape: common (thousands of dsts)
			"t13d130200_cccc_dddd": {Conns: 600000, SrcHosts: 2, Dsts: 2000},
			// rare but a single host (no cross-host cluster)
			"t13i200000_eeee_ffff": {Conns: 20, SrcHosts: 1, Dsts: 1},
		},
		map[string]model.FingerprintStat{
			// rare JA3 shared by two hosts
			"deadbeef": {Conns: 30, SrcHosts: 2, Dsts: 1},
			// rare JA3 single host
			"cafef00d": {Conns: 12, SrcHosts: 1, Dsts: 1},
		},
	)

	cases := []struct {
		name        string
		ja4, ja3    string
		wantLevel   string
		wantSubstrs []string
		wantAbsent  []string
	}{
		{
			name: "rare clustered JA4 is critical", ja4: "t13i131000_aaaa_bbbb",
			wantLevel:   "critical",
			wantSubstrs: []string{"rare", "shared by 3 internal hosts", "43 conns", "1 dst"},
		},
		{
			name: "rare single-host JA4 is high", ja4: "t13i200000_eeee_ffff",
			wantLevel:   "high",
			wantSubstrs: []string{"rare", "single host"},
			wantAbsent:  []string{"shared by"},
		},
		{
			name: "common JA4 is none, no cluster note", ja4: "t13d130200_cccc_dddd",
			wantLevel:   "none",
			wantSubstrs: []string{"common"},
			wantAbsent:  []string{"shared by", "rare"},
		},
		{
			name: "rare clustered JA3 is medium with collision warning", ja3: "deadbeef",
			wantLevel:   "medium",
			wantSubstrs: []string{"rare", "shared by 2 internal hosts", "JA3 only"},
		},
		{
			name: "rare single-host JA3 is low", ja3: "cafef00d",
			wantLevel:   "low",
			wantSubstrs: []string{"rare", "single host", "JA3 only"},
			wantAbsent:  []string{"shared by"},
		},
		{
			name: "JA4 wins when both present", ja4: "t13i131000_aaaa_bbbb", ja3: "deadbeef",
			wantLevel:  "critical",
			wantAbsent: []string{"JA3 only"},
		},
		{
			name: "unknown fingerprint yields no row", ja4: "nope", ja3: "nope",
			wantLevel: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level, detail := s.FingerprintConcern(tc.ja4, tc.ja3)
			if level != tc.wantLevel {
				t.Errorf("level = %q, want %q (detail=%q)", level, tc.wantLevel, detail)
			}
			if tc.wantLevel == "" && detail != "" {
				t.Errorf("expected empty detail for unresolved fingerprint, got %q", detail)
			}
			for _, want := range tc.wantSubstrs {
				if !strings.Contains(detail, want) {
					t.Errorf("detail %q missing %q", detail, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(detail, absent) {
					t.Errorf("detail %q must not contain %q", detail, absent)
				}
			}
		})
	}

	t.Run("empty snapshot yields no row", func(t *testing.T) {
		fresh := New(config.Default())
		if level, detail := fresh.FingerprintConcern("t13i131000_aaaa_bbbb", ""); level != "" || detail != "" {
			t.Errorf("expected empty result with no snapshot, got %q / %q", level, detail)
		}
	})
}
