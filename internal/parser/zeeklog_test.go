package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseLog_HandlesOversizedRecords verifies the parser tolerates
// single records that exceed the previous 1 MiB scanner cap. The
// 2026-05-10 audit raised this as a trust bug — pre-fix any log with
// one giant record (large HTTP POST URI, fat set[string] field,
// concatenated annotations, base64-encoded upload) silently truncated
// at the long line and the analyzer discarded the parser error so
// analysts had no signal. Post-fix the buffer is 16 MiB and ParseLog's
// error propagates to the caller.
func TestParseLog_HandlesOversizedRecords(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "http.log")

	// 2 MiB URI on the second record. Pre-fix this would have hit
	// bufio.ErrTooLong and silently dropped every record after.
	huge := strings.Repeat("A", 2<<20)
	content := `{"ts":1000.0,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","uri":"/short"}` + "\n" +
		`{"ts":1001.0,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","uri":"/` + huge + `"}` + "\n" +
		`{"ts":1002.0,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","uri":"/after"}` + "\n"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var got []string
	err := ParseLog(path, func(rec map[string]any) bool {
		uri, _ := rec["uri"].(string)
		got = append(got, uri)
		return true
	})
	if err != nil {
		t.Fatalf("ParseLog returned error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 records (including the oversized one), got %d: %v", len(got), summarizeURIs(got))
	}
	if got[0] != "/short" {
		t.Errorf("record 1 uri = %q, want /short", got[0])
	}
	if !strings.HasPrefix(got[1], "/AAAA") || len(got[1]) < 1<<20 {
		t.Errorf("record 2 uri should be the huge URI; got prefix %q (len %d)", truncate(got[1], 16), len(got[1]))
	}
	if got[2] != "/after" {
		t.Errorf("record 3 uri = %q, want /after — third record was lost (silent truncation)", got[2])
	}
}

// TestParseLog_ReportsErrorOnTrulyPathologicalLine verifies that a
// single line larger than even the new 16 MiB ceiling still surfaces
// as a non-nil error (no silent truncation past the cap either).
func TestParseLog_ReportsErrorOnTrulyPathologicalLine(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "weird.log")

	massive := strings.Repeat("X", 17<<20) // 17 MiB, just past the cap
	content := `{"ts":1000.0,"x":"` + massive + `"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	err := ParseLog(path, func(rec map[string]any) bool { return true })
	if err == nil {
		t.Fatalf("expected error on 17 MiB line, got nil — silent truncation regression")
	}
}

func summarizeURIs(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = truncate(v, 32)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
