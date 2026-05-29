package analysis

import "strings"

import "testing"

// TestFingerprintRarityTag covers the enrichment note that surfaces a beacon's
// TLS-fingerprint rarity + cross-host cluster — the signal the emitted-beacons-
// only JA3/JA4 sibling count cannot provide. Enrichment only: it must never be
// empty when a known fingerprint resolves, and must label rare-vs-common and
// the cross-host cluster correctly.
func TestFingerprintRarityTag(t *testing.T) {
	mkStat := func(conns int, srcs, dsts []string) *fpStat {
		s := &fpStat{conns: conns, srcs: map[string]struct{}{}, dsts: map[string]struct{}{}}
		for _, x := range srcs {
			s.srcs[x] = struct{}{}
		}
		for _, x := range dsts {
			s.dsts[x] = struct{}{}
		}
		return s
	}

	a := &Analyzer{
		fpJA4: map[string]*fpStat{
			// implant shape: rare (1 dst), clustered across 3 hosts
			"t13i131000_aaaa_bbbb": mkStat(43, []string{"10.0.0.12", "10.0.0.22", "10.0.0.79"}, []string{"172.104.94.174"}),
			// browser shape: common (many dsts)
			"t13d130200_cccc_dddd": mkStat(600000, []string{"10.0.0.5", "10.0.0.6"}, manyDsts(2000)),
			// rare but single host (no cluster)
			"t13i200000_eeee_ffff": mkStat(20, []string{"10.0.0.9"}, []string{"203.0.113.7"}),
		},
		fpJA3: map[string]*fpStat{
			"deadbeef": mkStat(30, []string{"10.0.0.12", "10.0.0.22"}, []string{"172.104.94.174"}),
		},
	}

	t.Run("rare clustered JA4", func(t *testing.T) {
		tag := a.fingerprintRarityTag("t13i131000_aaaa_bbbb", "")
		for _, want := range []string{"ja4=", "rare", "43 conns", "3 src hosts", "1 dsts", "shared by 3 internal hosts"} {
			if !strings.Contains(tag, want) {
				t.Errorf("tag %q missing %q", tag, want)
			}
		}
	})

	t.Run("common JA4 not flagged as cluster", func(t *testing.T) {
		tag := a.fingerprintRarityTag("t13d130200_cccc_dddd", "")
		if !strings.Contains(tag, "common") {
			t.Errorf("expected common, got %q", tag)
		}
		if strings.Contains(tag, "shared by") {
			t.Errorf("common fingerprint must not get the cross-host cluster note: %q", tag)
		}
	})

	t.Run("rare single host has no cluster note", func(t *testing.T) {
		tag := a.fingerprintRarityTag("t13i200000_eeee_ffff", "")
		if !strings.Contains(tag, "rare") || strings.Contains(tag, "shared by") {
			t.Errorf("rare-but-single-host shape wrong: %q", tag)
		}
	})

	t.Run("JA3 fallback flagged lower confidence", func(t *testing.T) {
		tag := a.fingerprintRarityTag("", "deadbeef")
		if !strings.Contains(tag, "ja3 fallback") {
			t.Errorf("JA3-only match must be flagged lower-confidence: %q", tag)
		}
	})

	t.Run("JA4 preferred over JA3 when both present", func(t *testing.T) {
		tag := a.fingerprintRarityTag("t13i131000_aaaa_bbbb", "deadbeef")
		if !strings.Contains(tag, "ja4=") || strings.Contains(tag, "ja3 fallback") {
			t.Errorf("JA4 should win when present: %q", tag)
		}
	})

	t.Run("unknown fingerprint yields empty", func(t *testing.T) {
		if tag := a.fingerprintRarityTag("nope", "nope"); tag != "" {
			t.Errorf("expected empty tag for unknown fingerprint, got %q", tag)
		}
	})
}

func manyDsts(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = "d" + itoaFast(i)
	}
	return out
}

func itoaFast(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
