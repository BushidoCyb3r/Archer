package analysis

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// updateGolden regenerates the expected-findings JSON instead of asserting
// against it. Use after a CHANGELOG-acknowledged detection change:
//
//	go test ./internal/analysis/... -run TestGoldenZeek -update
//
// Then commit the new expected_findings.json files (one per scenario subdir)
// in the same commit that landed the detection change.
var updateGolden = flag.Bool("update", false, "regenerate golden expected_findings.json files from current analyzer output")

// goldenFinding is the comparison projection of model.Finding. Fields excluded:
//   - ID: sequential and depends on goroutine scheduling, never stable.
//   - Status, Analyst, Notes, AnalystNote, StatusTS: post-analysis mutations.
//   - SourceFile: contains absolute paths, varies by checkout location.
//   - TSData: reservoir-sampled chart data; not part of user-visible finding
//     identity, and reservoir randomness can shuffle order under cap.
//   - IsNew: SetFindings-merge state, not analyzer output.
type goldenFinding struct {
	Type      string         `json:"type"`
	Severity  model.Severity `json:"severity"`
	Score     int            `json:"score"`
	SrcIP     string         `json:"src_ip"`
	DstIP     string         `json:"dst_ip"`
	DstPort   string         `json:"dst_port,omitempty"`
	Detail    string         `json:"detail"`
	Timestamp string         `json:"timestamp"`
}

// projectFindings strips non-deterministic fields and sorts for stable diffing.
func projectFindings(findings []model.Finding) []goldenFinding {
	out := make([]goldenFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, goldenFinding{
			Type:      f.Type,
			Severity:  f.Severity,
			Score:     f.Score,
			SrcIP:     f.SrcIP,
			DstIP:     f.DstIP,
			DstPort:   f.DstPort,
			Detail:    f.Detail,
			Timestamp: f.Timestamp,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.SrcIP != b.SrcIP {
			return a.SrcIP < b.SrcIP
		}
		if a.DstIP != b.DstIP {
			return a.DstIP < b.DstIP
		}
		if a.DstPort != b.DstPort {
			return a.DstPort < b.DstPort
		}
		if a.Timestamp != b.Timestamp {
			return a.Timestamp < b.Timestamp
		}
		return a.Detail < b.Detail
	})
	return out
}

// collectFixtureLogs returns every *.log file in dir (non-recursive).
func collectFixtureLogs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".log" {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	sort.Strings(files)
	return files
}

// scenarioFeeds matches the optional feeds.json that scenarios can use to
// override the default TI-feed injection. Any field omitted falls back to
// the default below — empty map for *_ips and a single "malware.test" entry
// for hosts (so the original beacon_url scenario keeps working without
// needing its own feeds.json).
//
// MISPFeeds carries one or more stub MISP/OpenCTI feed snapshots. The
// analyzer treats both source types identically (both normalize to the
// same SourcedIndicators bucket via their adapters), so a single entry
// here exercises the per-source fan-out path regardless of which
// upstream produced it.
type scenarioFeeds struct {
	FeodoIPs     []string       `json:"feodo_ips"`
	URLhausIPs   []string       `json:"urlhaus_ips"`
	URLhausHosts []string       `json:"urlhaus_hosts"`
	MISPFeeds    []scenarioMISP `json:"misp_feeds"`
}

// scenarioMISP describes one stub feed for a scenario. Source becomes
// the "feed:<name>" prefix in finding details. Tags is keyed by raw
// indicator value (the analyzer lowercases domain keys internally so
// the test injector mirrors that).
type scenarioMISP struct {
	Source  string              `json:"source"`
	IPs     []string            `json:"ips"`
	CIDRs   []string            `json:"cidrs"`
	Domains []string            `json:"domains"`
	Hashes  []string            `json:"hashes"`
	Tags    map[string][]string `json:"tags"`
}

func loadScenarioFeeds(dir string) (feodoIPs, urlhausIPs, urlhausHosts map[string]bool, provider feeds.Provider, err error) {
	feodoIPs = map[string]bool{}
	urlhausIPs = map[string]bool{}
	urlhausHosts = map[string]bool{"malware.test": true}

	raw, readErr := os.ReadFile(filepath.Join(dir, "feeds.json"))
	if readErr != nil {
		// No feeds.json — fall back to defaults silently. Most scenarios
		// don't need TI injection beyond the default malware.test entry.
		return feodoIPs, urlhausIPs, urlhausHosts, nil, nil
	}
	var f scenarioFeeds
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, nil, nil, err
	}
	// feeds.json fully replaces the defaults for whichever fields it sets.
	if f.FeodoIPs != nil {
		feodoIPs = make(map[string]bool, len(f.FeodoIPs))
		for _, ip := range f.FeodoIPs {
			feodoIPs[ip] = true
		}
	}
	if f.URLhausIPs != nil {
		urlhausIPs = make(map[string]bool, len(f.URLhausIPs))
		for _, ip := range f.URLhausIPs {
			urlhausIPs[ip] = true
		}
	}
	if f.URLhausHosts != nil {
		urlhausHosts = make(map[string]bool, len(f.URLhausHosts))
		for _, h := range f.URLhausHosts {
			urlhausHosts[h] = true
		}
	}
	if len(f.MISPFeeds) > 0 {
		buckets := make([]feeds.SourcedIndicators, 0, len(f.MISPFeeds))
		for _, mf := range f.MISPFeeds {
			b := feeds.SourcedIndicators{
				Source:  mf.Source,
				IPs:     map[string]bool{},
				Domains: map[string]bool{},
				Hashes:  map[string]bool{},
				Tags:    map[string][]string{},
			}
			for _, ip := range mf.IPs {
				b.IPs[ip] = true
			}
			for _, c := range mf.CIDRs {
				if _, ipnet, perr := net.ParseCIDR(c); perr == nil {
					b.CIDRs = append(b.CIDRs, ipnet)
				}
			}
			for _, d := range mf.Domains {
				b.Domains[strings.ToLower(d)] = true
			}
			for _, h := range mf.Hashes {
				b.Hashes[strings.ToLower(h)] = true
			}
			for k, v := range mf.Tags {
				b.Tags[strings.ToLower(k)] = v
			}
			buckets = append(buckets, b)
		}
		provider = &goldenStubFeedProvider{out: buckets}
	}
	return feodoIPs, urlhausIPs, urlhausHosts, provider, nil
}

// loadScenarioOperatorFingerprints reads an optional operator_fingerprints.json
// (a JSON array of JA3/JA4 strings) from a scenario dir. Absent file = nil.
func loadScenarioOperatorFingerprints(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "operator_fingerprints.json"))
	if err != nil {
		return nil
	}
	var fps []string
	if err := json.Unmarshal(raw, &fps); err != nil {
		t.Fatalf("decode operator_fingerprints.json in %s: %v", dir, err)
	}
	return fps
}

// goldenStubFeedProvider implements feeds.Provider for scenario injection.
// Distinct type from feedprovider_test.go's stubFeedProvider (which lives
// in a different test file) to keep the two test surfaces independent.
type goldenStubFeedProvider struct {
	out []feeds.SourcedIndicators
}

func (g *goldenStubFeedProvider) EnabledFeedIndicators() []feeds.SourcedIndicators {
	return g.out
}

// runScenario runs one fixture subdirectory through the analyzer and either
// asserts against (or, with -update, regenerates) the scenario's golden file.
func runScenario(t *testing.T, dir string) {
	t.Helper()
	files := collectFixtureLogs(t, dir)
	if len(files) == 0 {
		t.Fatalf("no .log fixtures in %s", dir)
	}

	feodoIPs, urlhausIPs, urlhausHosts, provider, err := loadScenarioFeeds(dir)
	if err != nil {
		t.Fatalf("load feeds.json in %s: %v", dir, err)
	}

	a := New(config.Default(), "", nil, nil)
	// Inject deterministic feeds. prefetchFeeds skips its live HTTP fetches
	// when caches are non-nil, so the run never touches the public internet.
	a.feodoIPs = feodoIPs
	a.urlhausIPs = urlhausIPs
	a.urlhausHosts = urlhausHosts
	if provider != nil {
		a.SetFeedProvider(provider)
	}
	// Optional operator JA3/JA4 IOC list — a scenario drops an
	// operator_fingerprints.json (JSON array of strings) to exercise the
	// operator-supplied Malicious JA3/JA4 path alongside the built-in tables.
	if fps := loadScenarioOperatorFingerprints(t, dir); len(fps) > 0 {
		a.SetOperatorFingerprints(fps)
	}

	got := projectFindings(a.Analyze(files))

	goldenPath := filepath.Join(dir, "expected_findings.json")

	if *updateGolden {
		buf, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("marshal golden: %v", err)
		}
		buf = append(buf, '\n')
		if err := os.WriteFile(goldenPath, buf, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("regenerated %s with %d findings", goldenPath, len(got))
		return
	}

	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s (run `go test ./internal/analysis/... -run TestGoldenZeek -update` to generate): %v", goldenPath, err)
	}
	var want []goldenFinding
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("decode golden: %v", err)
	}

	if len(got) != len(want) {
		t.Errorf("finding count: got %d, want %d", len(got), len(want))
		t.Logf("got findings:")
		for i, f := range got {
			t.Logf("  [%d] %+v", i, f)
		}
		t.Logf("want findings:")
		for i, f := range want {
			t.Logf("  [%d] %+v", i, f)
		}
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("finding[%d] mismatch\n  got:  %+v\n  want: %+v", i, got[i], want[i])
		}
	}
}

// TestGoldenZeek discovers every scenario subdirectory under testdata/zeek/
// and runs each as its own subtest. Each scenario is a self-contained
// fixture: one or more *.log files plus an expected_findings.json captured
// against current analyzer output.
func TestGoldenZeek(t *testing.T) {
	root := filepath.Join("testdata", "zeek")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read scenario root %s: %v", root, err)
	}
	scenarios := make([]string, 0)
	for _, e := range entries {
		if e.IsDir() {
			scenarios = append(scenarios, e.Name())
		}
	}
	sort.Strings(scenarios)
	if len(scenarios) == 0 {
		t.Fatalf("no scenario subdirectories in %s", root)
	}

	for _, name := range scenarios {
		t.Run(name, func(t *testing.T) {
			runScenario(t, filepath.Join(root, name))
		})
	}
}
