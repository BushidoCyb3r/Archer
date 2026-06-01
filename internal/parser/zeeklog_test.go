package parser

import (
	"bytes"
	"compress/gzip"
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

// writeGzip writes content to path as a gzip stream.
func writeGzip(t *testing.T, path, content string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

// TestParseLog_GzipLimitErrorsNotSilent verifies a .gz that decompresses
// past the per-file ceiling surfaces a non-nil error rather than EOF-ing
// silently. A bare io.LimitReader returns EOF on a limit hit, so the
// analyzer would record nothing and the analyst would get finding counts
// implying a full scan while the tail was dropped — the same trust-bug
// class as the 16 MiB line-cap fix.
func TestParseLog_GzipLimitErrorsNotSilent(t *testing.T) {
	old := gzipDecompressLimit
	gzipDecompressLimit = 200
	defer func() { gzipDecompressLimit = old }()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "conn.log.gz")
	var sb strings.Builder
	for i := 0; i < 50; i++ { // well over 200 decompressed bytes
		sb.WriteString(`{"ts":1000.0,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2"}` + "\n")
	}
	writeGzip(t, path, sb.String())

	err := ParseLog(path, func(rec map[string]any) bool { return true })
	if err == nil {
		t.Fatal("expected error when gzip exceeds the decompression limit, got nil — silent truncation")
	}
}

// TestParseLog_GzipUnderLimitParsesAll guards the new limit reader against
// breaking the normal path: a gzip comfortably under the ceiling parses
// every record with no error.
func TestParseLog_GzipUnderLimitParsesAll(t *testing.T) {
	old := gzipDecompressLimit
	gzipDecompressLimit = 1 << 20
	defer func() { gzipDecompressLimit = old }()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "conn.log.gz")
	content := `{"ts":1.0,"uri":"/a"}` + "\n" +
		`{"ts":2.0,"uri":"/b"}` + "\n" +
		`{"ts":3.0,"uri":"/c"}` + "\n"
	writeGzip(t, path, content)

	var n int
	err := ParseLog(path, func(rec map[string]any) bool { n++; return true })
	if err != nil {
		t.Fatalf("ParseLog returned error on under-limit gzip: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 records, got %d", n)
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
