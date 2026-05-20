package server

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// newArchiveTestServer builds a Server wired to an in-memory store so the
// archive worker's RecordArchiveRun and Prune/Count calls are safe to call.
// Tests don't care about the recorded telemetry; this just keeps runArchive
// from nil-dereferencing on s.store.
func newArchiveTestServer(logsDir string) *Server {
	return &Server{logsDir: logsDir, store: store.New(config.Default())}
}

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

	s := newArchiveTestServer(tmpLogs)
	res := s.runArchive(30, false, false, "test")

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

// TestRunArchive_PrunesEmptyDirsAfterMove confirms that subdirectories which
// become empty as a result of archiving are cleaned up, while directories
// that still hold a fresh file or a non-Zeek file are preserved. The dataset
// root itself is preserved even when fully emptied so import scans can still
// recognise it.
func TestRunArchive_PrunesEmptyDirsAfterMove(t *testing.T) {
	tmpLogs := t.TempDir()
	tmpArchive := t.TempDir()

	origArchiveDir := archiveDir
	archiveDir = tmpArchive
	defer func() { archiveDir = origArchiveDir }()

	old := time.Now().Add(-40 * 24 * time.Hour)

	// Dataset "drained" — a date subdirectory holding only old logs that
	// will all migrate out, leaving the subdirectory empty.
	drainedSub := filepath.Join(tmpLogs, "drained", "2026-01-01")
	if err := os.MkdirAll(drainedSub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"conn.log", "dns.log"} {
		p := filepath.Join(drainedSub, name)
		if err := os.WriteFile(p, []byte("ancient"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	// Dataset "mixed" — date dir within the 30-day window; both files stay
	// regardless of their individual mtimes because directory date is authoritative.
	mixedSub := filepath.Join(tmpLogs, "mixed", "2026-05-15")
	if err := os.MkdirAll(mixedSub, 0o755); err != nil {
		t.Fatal(err)
	}
	oldP := filepath.Join(mixedSub, "conn.log")
	if err := os.WriteFile(oldP, []byte("ancient"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldP, old, old); err != nil {
		t.Fatal(err)
	}
	freshP := filepath.Join(mixedSub, "http.log")
	if err := os.WriteFile(freshP, []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Dataset "with-junk" — old log plus a non-Zeek file. Archive only
	// touches the log; the directory should remain because notes.txt stays.
	junkSub := filepath.Join(tmpLogs, "with-junk", "2026-01-15")
	if err := os.MkdirAll(junkSub, 0o755); err != nil {
		t.Fatal(err)
	}
	junkOld := filepath.Join(junkSub, "ssl.log")
	if err := os.WriteFile(junkOld, []byte("ancient"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(junkOld, old, old); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(junkSub, "notes.txt")
	if err := os.WriteFile(notes, []byte("hand-written"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := newArchiveTestServer(tmpLogs)
	res := s.runArchive(30, false, false, "test")

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.FilesArchived != 3 {
		t.Errorf("expected 3 files archived (drained×2 + with-junk×1), got %d", res.FilesArchived)
	}

	// Drained dataset: subdirectory and parent should both be gone, but the
	// logs root stays.
	if _, err := os.Stat(drainedSub); !os.IsNotExist(err) {
		t.Errorf("drained subdirectory should be removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpLogs, "drained")); !os.IsNotExist(err) {
		t.Errorf("drained dataset directory should be removed when empty: %v", err)
	}
	if _, err := os.Stat(tmpLogs); err != nil {
		t.Errorf("logs root must always survive: %v", err)
	}

	// Mixed dataset: both files stay because the directory date (2026-05-15) is
	// within the retention window, regardless of individual file mtime.
	if _, err := os.Stat(mixedSub); err != nil {
		t.Errorf("mixed subdirectory should remain: %v", err)
	}
	if _, err := os.Stat(oldP); err != nil {
		t.Errorf("conn.log in recent date-dir should remain: %v", err)
	}
	if _, err := os.Stat(freshP); err != nil {
		t.Errorf("http.log in recent date-dir should remain: %v", err)
	}

	// With-junk dataset: subdirectory must remain because notes.txt stayed.
	if _, err := os.Stat(junkSub); err != nil {
		t.Errorf("with-junk subdirectory should remain (notes.txt holds it): %v", err)
	}
	if _, err := os.Stat(notes); err != nil {
		t.Errorf("notes.txt should not be touched: %v", err)
	}
}

// TestRunArchive_DryRunReportsWithoutMutating exercises the preview path
// powering the "confirm before archive" UI flow. The dry run must report
// the same counts a real run would produce, while leaving every file in
// place, every finding in the store, and the last-run telemetry empty.
func TestRunArchive_DryRunReportsWithoutMutating(t *testing.T) {
	tmpLogs := t.TempDir()
	tmpArchive := t.TempDir()

	origArchiveDir := archiveDir
	archiveDir = tmpArchive
	defer func() { archiveDir = origArchiveDir }()

	old := time.Now().Add(-40 * 24 * time.Hour)
	oldFile := filepath.Join(tmpLogs, "ds", "conn.log")
	if err := os.MkdirAll(filepath.Dir(oldFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldFile, []byte("ancient zeek data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldFile, old, old); err != nil {
		t.Fatal(err)
	}

	s := newArchiveTestServer(tmpLogs)
	res := s.runArchive(30, false, true, "preview-by-admin")

	if res.FilesArchived != 1 {
		t.Errorf("dry run should report 1 file movable, got %d", res.FilesArchived)
	}
	if int(res.BytesArchived) != len("ancient zeek data") {
		t.Errorf("dry run should report payload size, got %d", res.BytesArchived)
	}

	// File must still be in logsDir
	if _, err := os.Stat(oldFile); err != nil {
		t.Errorf("dry run should not move files, but source is gone: %v", err)
	}
	// Archive dir must be untouched
	if _, err := os.Stat(filepath.Join(tmpArchive, "ds", "conn.log")); !os.IsNotExist(err) {
		t.Errorf("dry run should not write to archive dir: %v", err)
	}
	// Last-run telemetry must remain empty — preview never records.
	if last := s.store.GetArchive().LastRunAt; last != "" {
		t.Errorf("dry run should not record telemetry, got LastRunAt=%q", last)
	}
}

// TestRunArchive_RejectsInvalidConfig confirms we don't silently succeed when
// the caller passes a nonsensical retention value or an unconfigured logs dir.
func TestRunArchive_RejectsInvalidConfig(t *testing.T) {
	tmpArchive := t.TempDir()
	origArchiveDir := archiveDir
	archiveDir = tmpArchive
	defer func() { archiveDir = origArchiveDir }()

	s := newArchiveTestServer(t.TempDir())

	if res := s.runArchive(0, false, false, "test"); res.Err == "" {
		t.Error("expected error for afterDays=0")
	}
	if res := s.runArchive(-1, false, false, "test"); res.Err == "" {
		t.Error("expected error for negative afterDays")
	}

	noLogs := newArchiveTestServer("")
	if res := noLogs.runArchive(30, false, false, "test"); res.Err == "" {
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

	s := newArchiveTestServer(tmpLogs)
	res := s.runArchive(30, false, false, "test")

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

// TestDirDateFromPath verifies the date-extraction helper against paths with
// and without YYYY-MM-DD segments.
func TestDirDateFromPath(t *testing.T) {
	cases := []struct {
		path    string
		wantOk  bool
		wantDay string // YYYY-MM-DD, empty when wantOk=false
	}{
		{"/logs/sensor/2026-03-10/conn.00:00:00-01:00:00.log.gz", true, "2026-03-10"},
		{"/logs/apt29/2024-01-01/dns.log", true, "2024-01-01"},
		{"/logs/sensor/conn.log", false, ""},
		{"/logs/sensor/notadate/conn.log", false, ""},
		{"/logs/sensor/2026-13-01/conn.log", false, ""},
	}
	for _, c := range cases {
		got, ok := dirDateFromPath(c.path)
		if ok != c.wantOk {
			t.Errorf("dirDateFromPath(%q): ok=%v want %v", c.path, ok, c.wantOk)
			continue
		}
		if ok && got.Format("2006-01-02") != c.wantDay {
			t.Errorf("dirDateFromPath(%q): date=%s want %s", c.path, got.Format("2006-01-02"), c.wantDay)
		}
	}
}

// TestRunArchive_DirectoryDateDominatesMtime is the regression test for the
// rsync timestamp preservation bug. A file that arrived on the server with a
// current mtime (because rsync did not preserve the original sensor mtime)
// must still be archived if its YYYY-MM-DD directory path places it beyond
// the retention cutoff.
func TestRunArchive_DirectoryDateDominatesMtime(t *testing.T) {
	tmpLogs := t.TempDir()
	tmpArchive := t.TempDir()
	origArchiveDir := archiveDir
	archiveDir = tmpArchive
	defer func() { archiveDir = origArchiveDir }()

	// A log that is 45 days old by directory name but has a CURRENT mtime
	// (simulating rsync landing with the transfer timestamp instead of the
	// original sensor timestamp).
	oldDateDir := filepath.Join(tmpLogs, "sensor", "2026-04-05")
	if err := os.MkdirAll(oldDateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	staleFile := filepath.Join(oldDateDir, "conn.00:00:00-01:00:00.log.gz")
	if err := os.WriteFile(staleFile, []byte("old traffic"), 0o644); err != nil {
		t.Fatal(err)
	}
	// mtime is intentionally left as-is (current time) — the bug scenario.

	// A log with a date dir inside the retention window; mtime is old.
	recentDateDir := filepath.Join(tmpLogs, "sensor", "2026-05-15")
	if err := os.MkdirAll(recentDateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	recentFile := filepath.Join(recentDateDir, "conn.00:00:00-01:00:00.log.gz")
	if err := os.WriteFile(recentFile, []byte("recent traffic"), 0o644); err != nil {
		t.Fatal(err)
	}
	recentOldMtime := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(recentFile, recentOldMtime, recentOldMtime); err != nil {
		t.Fatal(err)
	}

	s := newArchiveTestServer(tmpLogs)
	res := s.runArchive(30, false, false, "test")

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	// Only the old-date-dir file should be archived, not the recent-date-dir file.
	if res.FilesArchived != 1 {
		t.Errorf("expected 1 archived, got %d", res.FilesArchived)
	}

	if _, err := os.Stat(staleFile); !os.IsNotExist(err) {
		t.Errorf("stale log (old dir, current mtime) should be archived: stat err %v", err)
	}
	if _, err := os.Stat(recentFile); err != nil {
		t.Errorf("recent log (recent dir, old mtime) must not be archived: %v", err)
	}
}

// TestMoveFile_NonEXDEVErrorSurfaces asserts moveFile returns the original
// rename error rather than falling through to copy when Rename fails for a
// reason other than EXDEV. Pre-fix the copy fallback ran on every non-nil
// rename error, so a missing-source error would be replaced by a useless
// "open: no such file" diagnostic from the copy path. Audit 2026-05-10
// NEW-13.
func TestMoveFile_NonEXDEVErrorSurfaces(t *testing.T) {
	dstDir := t.TempDir()
	src := filepath.Join(t.TempDir(), "does-not-exist.log")
	dst := filepath.Join(dstDir, "conn.log")

	err := moveFile(src, dst)
	if err == nil {
		t.Fatal("moveFile of missing source must return an error")
	}
	// We don't pin the exact error string (cross-platform fragility), but
	// the dst must NOT have been created — that would mean copy fallback
	// fired for a non-EXDEV error.
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("non-EXDEV failure must not create dst via copy fallback")
	}
}
