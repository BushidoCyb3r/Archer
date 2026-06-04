package analysis

import (
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// countFindingType returns how many findings carry the given Type.
func countFindingType(findings []model.Finding, typ string) int {
	n := 0
	for i := range findings {
		if findings[i].Type == typ {
			n++
		}
	}
	return n
}

// TestConfigThresholdsGate closes the config-tunability gap the standing golden
// fixtures leave open: they all run at default config and assert the resulting
// findings, so a threshold that silently does nothing (the v0.8.0 dead-config
// bug class) would pass every one of them. This test asserts the invariant that
// matters for a tunable knob — *it actually gates* — by running a fixture twice
// across the boundary: at a config that should emit the finding, and at a
// config whose threshold is raised just past the fixture's value, which must
// suppress it. A knob wired to nothing fails the suppress side.
//
// The emit side uses config.Default() (the fixture was built to fire at default)
// except where the knob's emit value is the point of the case; the suppress side
// raises exactly one knob past the fixture's observed value, leaving the rest at
// their defaults so the test isolates that one threshold.
func TestConfigThresholdsGate(t *testing.T) {
	cases := []struct {
		name        string
		scenario    string
		findingType string
		emit        func(c config.Config) config.Config
		suppress    func(c config.Config) config.Config
	}{
		{
			// beacon_url: 100 connections. At the default floor (4) the pair
			// clears the gate and scores; at 101 it falls one short and no
			// Beacon is scored at all. (The emit side stays at the default
			// rather than 100, because beaconConfMod bottoms out the confidence
			// when n == BeaconMinConnections, which is a separate effect from
			// the hard gate this case isolates.)
			name: "beacon_min_connections", scenario: "beacon_url", findingType: "Beacon",
			emit:     func(c config.Config) config.Config { return c },
			suppress: func(c config.Config) config.Config { c.BeaconMinConnections = 101; return c },
		},
		{
			// strobe: exactly 1000 connections. Raising the count floor past
			// 1000 drops the pair below the gate.
			name: "strobe_min_connections", scenario: "strobe", findingType: "Strobe",
			emit:     func(c config.Config) config.Config { return c },
			suppress: func(c config.Config) config.Config { c.StrobeMinConnections = 1001; return c },
		},
		{
			// strobe: rate ~1.83/s. Raising the rate gate above it leaves the
			// count satisfied but the rate gate unmet, so Strobe doesn't fire.
			name: "strobe_min_rate_per_sec", scenario: "strobe", findingType: "Strobe",
			emit:     func(c config.Config) config.Config { return c },
			suppress: func(c config.Config) config.Config { c.StrobeMinRatePerSec = 5.0; return c },
		},
		{
			// exfil: 7.5 MB outbound. Raising the byte floor above it suppresses.
			name: "exfil_min_bytes_mb", scenario: "exfil", findingType: "Data Exfiltration",
			emit:     func(c config.Config) config.Config { return c },
			suppress: func(c config.Config) config.Config { c.ExfilMinBytesMB = 8.0; return c },
		},
		{
			// dns_nxdomain_flood: 250 NXDOMAIN responses. Raising the threshold
			// past 250 suppresses the flood finding.
			name: "dns_nxdomain_threshold", scenario: "dns_nxdomain_flood", findingType: "DNS NXDOMAIN Flood",
			emit:     func(c config.Config) config.Config { return c },
			suppress: func(c config.Config) config.Config { c.DNSNXDomainThreshold = 300; return c },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := collectFixtureLogs(t, filepath.Join("testdata", "zeek", c.scenario))
			if len(files) == 0 {
				t.Fatalf("no fixtures for scenario %q", c.scenario)
			}

			// Emit side: the finding must be present.
			emitA := New(c.emit(config.Default()), "", nil, nil)
			if n := countFindingType(emitA.Analyze(files), c.findingType); n == 0 {
				t.Errorf("emit config produced 0 %q findings; want >= 1 (the knob's emitting side is broken)", c.findingType)
			}

			// Suppress side: raising the one threshold past the fixture's value
			// must drop the finding. A knob wired to nothing leaves it present.
			supA := New(c.suppress(config.Default()), "", nil, nil)
			if n := countFindingType(supA.Analyze(files), c.findingType); n != 0 {
				t.Errorf("raising the threshold past the fixture's value left %d %q finding(s); the knob does not gate", n, c.findingType)
			}
		})
	}
}
