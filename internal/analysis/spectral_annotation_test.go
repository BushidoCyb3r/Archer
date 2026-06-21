package analysis

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// writeSpectralFiringConn writes a conn.log for one (src,dst) pair whose
// arrivals cluster around a fixed period with irregular within-cluster gaps.
// This is the one regime that drives the spectral path to *decide*: the
// Bowley/MAD (raw), multimodal, and entropy timing layers all score below the
// 0.5 rescue gate (the clustering wrecks interval regularity and the median
// sits far below the true period), yet a Lomb-Scargle peak survives at the
// cluster cadence. A clean fixed-cadence beacon never reaches here — raw
// already scores ~1.0 and the gate stays shut (see jittered_beacon/README).
// Deterministic: math/rand with a fixed seed is stable under the Go
// compatibility promise.
func writeSpectralFiringConn(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "conn.log")

	rng := rand.New(rand.NewSource(42))
	const (
		period = 7200.0 // 2h cluster cadence
		cycles = 40
		spread = 1200.0 // within-cluster jitter window
	)
	base := 1705320000.0
	var ts []float64
	for c := 0; c < cycles; c++ {
		burst := 2 + rng.Intn(6) // 2..7 arrivals per cluster
		for k := 0; k < burst; k++ {
			ts = append(ts, base+float64(c)*period+rng.Float64()*spread)
		}
	}
	sort.Float64s(ts)

	var b strings.Builder
	for i, tv := range ts {
		fmt.Fprintf(&b, `{"ts": %.3f, "uid": "B%07d", "id.orig_h": "192.168.1.50", "id.orig_p": 40000, "id.resp_h": "198.51.100.77", "id.resp_p": 443, "proto": "tcp", "duration": 0.3, "orig_bytes": 400, "resp_bytes": 800, "orig_ip_bytes": 440, "resp_ip_bytes": 840, "conn_state": "SF"}`+"\n", tv, i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func beaconTo(findings []model.Finding, dst string) *model.Finding {
	for i := range findings {
		if findings[i].Type == "Beacon" && findings[i].DstIP == dst {
			return &findings[i]
		}
	}
	return nil
}

// TestSpectralIsAnnotationOnly is the invariant guarding the 2026-06-21
// timing-axis validation outcome: the spectral path may flag a finding (so an
// analyst can see the possible jittered periodicity) but must NEVER change the
// finding's score or severity. The validation showed the spectral rescue
// decided 0 true positives and inflated 400+ benign clustered findings to
// CRITICAL on a live-C2 corpus, and the period gate that would suppress them
// was deliberately removed for burst-connect beacons — so the boost was
// demoted to an annotation.
//
// The test runs the same spectral-firing fixture with SpectralEnabled true and
// false. It asserts (1) spectral genuinely fired on the enabled run — without
// this the test would pass vacuously on any fixture — and (2) enabling it left
// the score and severity untouched. On the pre-change code the enabled run
// lifts tsScore from ~0.37 to ~1.0 (the LS power is far above the FAP
// threshold), so the score jumps from HIGH to CRITICAL and this test fails.
func TestSpectralIsAnnotationOnly(t *testing.T) {
	path := writeSpectralFiringConn(t)
	const dst = "198.51.100.77"

	score := func(spectral bool) (*model.Finding, string) {
		cfg := config.Default()
		cfg.SpectralEnabled = spectral
		status := make(chan string, 64)
		a := New(cfg, "", nil, status)
		a.feodoIPs = map[string]bool{}
		a.urlhausIPs = map[string]bool{}
		a.urlhausHosts = map[string]bool{}
		f := beaconTo(a.Analyze([]string{path}), dst)
		if f == nil {
			t.Fatalf("no Beacon finding to %s (spectral=%v)", dst, spectral)
		}
		return f, f.Detail
	}

	on, onDetail := score(true)
	off, offDetail := score(false)

	// (1) The test is only meaningful if spectral actually fired on the
	// enabled run — otherwise on==off proves nothing.
	if !on.SpectralRescued {
		t.Fatalf("fixture no longer fires the spectral path (SpectralRescued=false); the invariant is untested — adjust the fixture")
	}
	if !strings.Contains(onDetail, "Spectral signal") {
		t.Errorf("spectral fired but the analyst-facing annotation is missing from Detail: %q", onDetail)
	}
	if strings.Contains(offDetail, "Spectral") {
		t.Errorf("spectral disabled but Detail still carries a spectral annotation: %q", offDetail)
	}

	// (2) The invariant: enabling spectral must not move score or severity.
	if on.Score != off.Score {
		t.Errorf("spectral changed the score: enabled=%d disabled=%d — spectral must be annotation-only, not a score driver", on.Score, off.Score)
	}
	if on.Severity != off.Severity {
		t.Errorf("spectral changed the severity: enabled=%s disabled=%s", on.Severity, off.Severity)
	}
}
