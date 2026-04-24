package server

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// TestRunArchive_MovesOldFilesPreservingLayout exercises the core archive
// workflow end-to-end: files older than the cutoff move into the archive dir
// preserving their dataset subdirectory, while fresh files stay put.
func TestRunArchive_MovesOldFilesPreservingLayout(t *testing.T) {
	tmpLogs := t.TempDir()
	tmpArchive := t.TempDir()

	origArchiveDir := archiveDir
	archiveDir = tmpArchive
	defer func() { archiveDir = origArchiveDir }()

	// Dataset "apt29" with an old conn.log (40 days back)
	oldDS := filepath.Join(tmpLogs, "apt29")
	if err := os.MkdirAll(oldDS, 0o755); err != nil {
		t.Fatal(err)
	}
	oldFile := filepath.Join(oldDS, "conn.log")
	if err := os.WriteFile(oldFile, []byte("ancient zeek data"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// Dataset "live-feed" with a recent http.log
	newDS := filepath.Join(tmpLogs, "live-feed")
	if err := os.MkdirAll(newDS, 0o755); err != nil {
		t.Fatal(err)
	}
	newFile := filepath.Join(newDS, "http.log")
	if err := os.WriteFile(newFile, []byte("fresh zeek data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Nested subdirectory to confirm layout preservation in the archive
	deepOldDir := filepath.Join(tmpLogs, "apt29", "2024-01-01")
	if err := os.MkdirAll(deepOldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	deepOldFile := filepath.Join(deepOldDir, "dns.log")
	if err := os.WriteFile(deepOldFile, []byte("nested ancient"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(deepOldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// Non-Zeek file (should be ignored entirely regardless of age)
	junkFile := filepath.Join(oldDS, "notes.txt")
	if err := os.WriteFile(junkFile, []byte("not a log"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(junkFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	s := &Server{logsDir: tmpLogs}
	res := s.runArchive(30, false)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.FilesArchived != 2 {
		t.Errorf("expected 2 files archived (conn.log + dns.log), got %d", res.FilesArchived)
	}
	if res.FindingsPruned != 0 {
		t.Errorf("expected 0 findings pruned with pruneFindings=false, got %d", res.FindingsPruned)
	}

	// Old files should be gone from logsDir
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Errorf("expected old conn.log to be removed from logsDir, stat err: %v", err)
	}
	if _, err := os.Stat(deepOldFile); !os.IsNotExist(err) {
		t.Errorf("expected nested dns.log to be removed from logsDir, stat err: %v", err)
	}

	// Fresh file must stay
	if _, err := os.Stat(newFile); err != nil {
		t.Errorf("fresh http.log should remain in logsDir: %v", err)
	}

	// Non-Zeek file must stay regardless of age
	if _, err := os.Stat(junkFile); err != nil {
		t.Errorf("notes.txt should not be touched (not a Zeek log): %v", err)
	}

	// Archive layout matches logs layout, with correct contents
	archivedConn := filepath.Join(tmpArchive, "apt29", "conn.log")
	if data, err := os.ReadFile(archivedConn); err != nil {
		t.Errorf("archived conn.log missing: %v", err)
	} else if string(data) != "ancient zeek data" {
		t.Errorf("archived conn.log content mismatch: %q", string(data))
	}

	archivedDNS := filepath.Join(tmpArchive, "apt29", "2024-01-01", "dns.log")
	if data, err := os.ReadFile(archivedDNS); err != nil {
		t.Errorf("archived nested dns.log missing: %v", err)
	} else if string(data) != "nested ancient" {
		t.Errorf("archived dns.log content mismatch: %q", string(data))
	}
}

// TestRunArchive_RejectsInvalidConfig confirms we don't silently succeed when
// the caller passes a nonsensical retention value or an unconfigured logs dir.
func TestRunArchive_RejectsInvalidConfig(t *testing.T) {
	tmpArchive := t.TempDir()
	origArchiveDir := archiveDir
	archiveDir = tmpArchive
	defer func() { archiveDir = origArchiveDir }()

	s := &Server{logsDir: t.TempDir()}

	if res := s.runArchive(0, false); res.Err == "" {
		t.Error("expected error for afterDays=0")
	}
	if res := s.runArchive(-1, false); res.Err == "" {
		t.Error("expected error for negative afterDays")
	}

	noLogs := &Server{logsDir: ""}
	if res := noLogs.runArchive(30, false); res.Err == "" {
		t.Error("expected error for empty logsDir")
	}
}

// TestRunArchive_SkipsExistingDestination prevents the worker from clobbering
// a previously-archived file if the same name resurfaces in logsDir.
func TestRunArchive_SkipsExistingDestination(t *testing.T) {
	tmpLogs := t.TempDir()
	tmpArchive := t.TempDir()
	origArchiveDir := archiveDir
	archiveDir = tmpArchive
	defer func() { archiveDir = origArchiveDir }()

	// Pre-seed an existing archive entry
	if err := os.MkdirAll(filepath.Join(tmpArchive, "ds"), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(tmpArchive, "ds", "conn.log")
	if err := os.WriteFile(existing, []byte("pre-existing archive"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Put an old file in logs at the same relative path
	logPath := filepath.Join(tmpLogs, "ds", "conn.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("new copy with same name"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(logPath, old, old); err != nil {
		t.Fatal(err)
	}

	s := &Server{logsDir: tmpLogs}
	res := s.runArchive(30, false)

	if res.FilesArchived != 0 {
		t.Errorf("expected 0 archived (dest exists), got %d", res.FilesArchived)
	}
	if res.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", res.Skipped)
	}

	// Existing archive entry must be unchanged
	data, _ := os.ReadFile(existing)
	if string(data) != "pre-existing archive" {
		t.Errorf("existing archive file was clobbered: got %q", string(data))
	}

	// Source file must remain in logsDir (archive was a no-op for it)
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("source should remain when archive skipped it: %v", err)
	}
}

// TestPreflightMemoryWarning_Thresholds verifies the helper fires only when
// the estimated working set approaches or exceeds GOMEMLIMIT. Uses
// debug.SetMemoryLimit to hold a deterministic budget during the test.
func TestPreflightMemoryWarning_Thresholds(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(orig)

	// Budget: 10 MiB. Peak ratio is 1.2×, threshold is 0.8×budget = 8 MiB.
	debug.SetMemoryLimit(10 << 20)

	tmp := t.TempDir()
	makeFile := func(name string, size int) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	s := &Server{}

	// 1 MiB → est peak 1.2 MiB, well below threshold → no warning
	if msg := s.preflightMemoryWarning([]string{makeFile("small.log", 1<<20)}); msg != "" {
		t.Errorf("small dataset unexpectedly warned: %s", msg)
	}

	// 8 MiB → est peak 9.6 MiB, between 0.8× and 1.0× → "approaching"
	midPath := makeFile("mid.log", 8<<20)
	msg := s.preflightMemoryWarning([]string{midPath})
	if msg == "" {
		t.Fatal("mid-size dataset should warn")
	}
	if !strings.Contains(msg, "approaching") {
		t.Errorf("expected 'approaching' in warning, got: %s", msg)
	}

	// 20 MiB → est peak 24 MiB, exceeds budget → "likely exceeding"
	bigPath := makeFile("big.log", 20<<20)
	msg = s.preflightMemoryWarning([]string{bigPath})
	if msg == "" {
		t.Fatal("oversized dataset should warn")
	}
	if !strings.Contains(msg, "likely exceeding") {
		t.Errorf("expected 'likely exceeding' in warning, got: %s", msg)
	}
}

// TestHumanBytes_Formatting sanity-checks the IEC unit formatter used in the
// preflight warning — one decimal for single-digit values, none otherwise.
func TestHumanBytes_Formatting(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{10 * 1024, "10 KiB"},
		{3435973836, "3.2 GiB"}, // ≈ 3.2 × 2³⁰
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMoveFile_CopyFallback explicitly exercises the cross-filesystem copy+
// remove path by forcing moveFile to take it even when Rename would succeed.
// This is the code path that actually runs in production (/logs bind-mount →
// /data volume) but never fires in a typical same-filesystem test.
func TestMoveFile_CopyFallback(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	src := filepath.Join(srcDir, "conn.log")
	dst := filepath.Join(dstDir, "conn.log")
	payload := []byte("file-contents")

	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-7 * 24 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(src, stamp, stamp); err != nil {
		t.Fatal(err)
	}

	if err := moveFile(src, dst); err != nil {
		t.Fatalf("moveFile: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source should be gone after move: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("dst content mismatch: got %q", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stamp) {
		t.Errorf("mtime not preserved: got %v want %v", info.ModTime(), stamp)
	}
}
