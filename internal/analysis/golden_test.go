package analysis

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// updateGolden regenerates the expected-findings JSON instead of asserting
// against it. Use after a CHANGELOG-acknowledged detection change:
//
//	go test ./internal/analysis/... -run TestGoldenZeek -update
//
// Then commit the new testdata/zeek/expected_findings.json with the same
// commit that landed the detection change.
var updateGolden = flag.Bool("update", false, "regenerate golden expected_findings.json from current analyzer output")

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

func TestGoldenZeek(t *testing.T) {
	dir := filepath.Join("testdata", "zeek")
	files := collectFixtureLogs(t, dir)
	if len(files) == 0 {
		t.Fatalf("no .log fixtures in %s", dir)
	}

	a := New(config.Default(), nil, nil)
	// Inject deterministic feeds. prefetchFeeds skips its live HTTP fetches
	// when caches are non-nil, so this run never touches the public internet.
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{"malware.test": true}

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
