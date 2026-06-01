package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestFirstAddr covers the Zeek set[addr] shapes GetStr can hand back:
// a JSON-log array (`["a","b"]`), a TSV comma-set (`a,b`), the
// single-element forms, and the empty array. F-COR-4: the old
// strings.Trim(s,"[]\"") only handled a single quoted element, so
// `["1.2.3.4","5.6.7.8"]` trimmed to the garbage `1.2.3.4","5.6.7.8`
// and became the finding's IP and dedup key.
func TestFirstAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{`["1.2.3.4"]`, "1.2.3.4"},
		{`["1.2.3.4","5.6.7.8"]`, "1.2.3.4"},
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4,5.6.7.8", "1.2.3.4"},
		{"[]", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := firstAddr(c.in); got != c.want {
			t.Errorf("firstAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func writeFilesLog(t *testing.T, lines ...string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "files.log")
	var content string
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write files.log: %v", err)
	}
	return []string{path}
}

// TestAnalyzeFiles_EmptyTxHostsFallsBackToOrigH is F-COR-1: a suspicious
// download whose tx_hosts Zeek couldn't attribute (`[]`) but whose
// id.orig_h is present must still emit, attributed to id.orig_h — not be
// silently dropped. Pre-fix GetStr returned the literal "[]" so the
// empty test never reached the id.orig_h fallback, then the later trim
// blanked it and the record was discarded.
func TestAnalyzeFiles_EmptyTxHostsFallsBackToOrigH(t *testing.T) {
	files := writeFilesLog(t,
		`{"ts":1000.0,"tx_hosts":[],"rx_hosts":["10.0.0.5"],"id.orig_h":"203.0.113.9","id.resp_h":"10.0.0.5","mime_type":"application/x-dosexec","filename":"evil.bin"}`)

	a := New(config.Default(), "", nil, nil)
	a.analyzeFiles(files)

	f := findingOfType(a.findings, "Suspicious File Download")
	if f == nil {
		t.Fatalf("expected a Suspicious File Download finding; record with empty tx_hosts was dropped")
	}
	if f.SrcIP != "10.0.0.5" {
		t.Errorf("SrcIP (downloader) = %q, want 10.0.0.5", f.SrcIP)
	}
	if f.DstIP != "203.0.113.9" {
		t.Errorf("DstIP (sender) = %q, want 203.0.113.9 (id.orig_h fallback)", f.DstIP)
	}
}

// TestAnalyzeFiles_MultiElementTxHostsCleanIP is F-COR-4: a multi-element
// tx_hosts must yield a clean first address as the finding's DstIP, not
// the trimmed-but-still-garbage middle of the array.
func TestAnalyzeFiles_MultiElementTxHostsCleanIP(t *testing.T) {
	files := writeFilesLog(t,
		`{"ts":1001.0,"tx_hosts":["198.51.100.7","198.51.100.8"],"rx_hosts":["10.0.0.6"],"mime_type":"application/x-dosexec","filename":"evil2.bin"}`)

	a := New(config.Default(), "", nil, nil)
	a.analyzeFiles(files)

	f := findingOfType(a.findings, "Suspicious File Download")
	if f == nil {
		t.Fatalf("expected a Suspicious File Download finding")
	}
	if f.DstIP != "198.51.100.7" {
		t.Errorf("DstIP = %q, want clean first element 198.51.100.7", f.DstIP)
	}
	if f.SrcIP != "10.0.0.6" {
		t.Errorf("SrcIP = %q, want 10.0.0.6", f.SrcIP)
	}
}
