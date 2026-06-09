package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseLog_HeaderlessTSVErrorsNotSilent is the LG-8 regression. A TSV
// file without its #fields header is misdetected as JSON; every line fails
// json.Unmarshal and was silently skipped, so ParseLog returned nil with zero
// records and the analyzer reported a clean scan of a file it read nothing
// from. ParseLog must now surface an error when data lines exist but none
// parse — while genuinely empty / all-comment files stay clean, and valid
// JSON and valid header-bearing TSV keep parsing without error.
func TestParseLog_HeaderlessTSVErrorsNotSilent(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	count := func(path string) (int, error) {
		n := 0
		err := ParseLog(path, func(map[string]any) bool { n++; return true })
		return n, err
	}

	t.Run("headerless TSV errors", func(t *testing.T) {
		// Zeek conn.log rows with no #fields header line.
		p := write("conn.log",
			"1700000000.0\tCabc\t10.0.0.1\t1234\t8.8.8.8\t53\n"+
				"1700000001.0\tCdef\t10.0.0.1\t1235\t8.8.4.4\t53\n")
		n, err := count(p)
		if err == nil {
			t.Errorf("expected an error for a headerless TSV; got nil (silent 0-record parse)")
		}
		if n != 0 {
			t.Errorf("expected 0 records yielded, got %d", n)
		}
	})

	t.Run("non-Zeek garbage errors", func(t *testing.T) {
		p := write("weird.log", "this is not a log file\nneither is this\n")
		if _, err := count(p); err == nil {
			t.Errorf("expected an error for a non-Zeek file; got nil")
		}
	})

	t.Run("valid NDJSON is clean", func(t *testing.T) {
		p := write("http.log",
			`{"ts":1700000000.0,"id.orig_h":"10.0.0.1","host":"example.com"}`+"\n")
		n, err := count(p)
		if err != nil {
			t.Errorf("valid NDJSON returned error: %v", err)
		}
		if n != 1 {
			t.Errorf("valid NDJSON: got %d records, want 1", n)
		}
	})

	t.Run("valid TSV with header is clean", func(t *testing.T) {
		p := write("dns.log",
			"#fields\tts\tid.orig_h\tquery\n"+
				"1700000000.0\t10.0.0.1\texample.com\n")
		n, err := count(p)
		if err != nil {
			t.Errorf("valid TSV returned error: %v", err)
		}
		if n != 1 {
			t.Errorf("valid TSV: got %d records, want 1", n)
		}
	})

	t.Run("empty file is clean", func(t *testing.T) {
		p := write("empty.log", "")
		n, err := count(p)
		if err != nil {
			t.Errorf("empty file returned error: %v", err)
		}
		if n != 0 {
			t.Errorf("empty file: got %d records, want 0", n)
		}
	})

	t.Run("all-comment file is clean", func(t *testing.T) {
		p := write("comments.log", "#separator \\x09\n#path conn\n#close 2026-01-01\n")
		n, err := count(p)
		if err != nil {
			t.Errorf("all-comment file returned error: %v", err)
		}
		if n != 0 {
			t.Errorf("all-comment file: got %d records, want 0", n)
		}
	})
}
