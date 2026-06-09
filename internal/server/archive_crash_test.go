package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRunArchive_TruncatedDstNotTreatedAsComplete is the LG-3 regression. If a
// previous archive run was killed mid-copy (OOM/power loss), the destination
// file in the archive is truncated. The stale-cleanup branch checked only that
// dst existed (os.Stat) before deleting the /logs source — so the next run
// would delete the only intact copy against a partial archive, losing log data
// permanently. The branch must compare sizes: a truncated dst is dropped and
// re-archived from the intact source; a byte-complete dst lets the stale
// source be removed as before.
func TestRunArchive_TruncatedDstNotTreatedAsComplete(t *testing.T) {
	oldTime := time.Now().Add(-40 * 24 * time.Hour)
	const fullData = "complete ancient zeek conn.log payload"

	setup := func(t *testing.T, dstContent string) (s *Server, src, dst string) {
		tmpLogs := t.TempDir()
		tmpArchive := t.TempDir()
		orig := archiveDir
		archiveDir = tmpArchive
		t.Cleanup(func() { archiveDir = orig })

		ds := filepath.Join(tmpLogs, "apt29", "2024-01-01")
		if err := os.MkdirAll(ds, 0o755); err != nil {
			t.Fatal(err)
		}
		src = filepath.Join(ds, "conn.log")
		if err := os.WriteFile(src, []byte(fullData), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(src, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}

		// Pre-seed the archive copy at the mirrored relative path.
		rel, err := filepath.Rel(tmpLogs, src)
		if err != nil {
			t.Fatal(err)
		}
		dst = filepath.Join(tmpArchive, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(dstContent), 0o644); err != nil {
			t.Fatal(err)
		}
		return newArchiveTestServer(tmpLogs), src, dst
	}

	t.Run("truncated dst: full data ends up in the archive", func(t *testing.T) {
		s, _, dst := setup(t, "trunc") // shorter than fullData

		res := s.runArchive(7, false, false, "test")

		// The interrupted copy is dropped and the file re-archived (moved)
		// from the intact source. The data-integrity invariant is that the
		// archive copy is now complete — under the old behavior the source
		// was deleted against the truncated copy and the full data was lost.
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("read dst: %v", err)
		}
		if string(got) != fullData {
			t.Errorf("archive copy = %q, want the full data re-archived (%q) — truncated copy was trusted as complete", string(got), fullData)
		}
		if res.FilesArchived != 1 {
			t.Errorf("FilesArchived = %d, want 1", res.FilesArchived)
		}
	})

	t.Run("complete dst: stale source removed", func(t *testing.T) {
		s, src, _ := setup(t, fullData) // exact same size → complete

		res := s.runArchive(7, false, false, "test")

		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Errorf("stale source should have been removed for a byte-complete archive copy; stat err = %v", err)
		}
		if res.FilesArchived != 1 {
			t.Errorf("FilesArchived = %d, want 1", res.FilesArchived)
		}
	})
}
