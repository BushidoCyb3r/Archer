package server

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPurgeSensorLogs_DoesNotCollideOnHyphenatedNames is the regression
// for NEW-21. Pre-fix the archive layout was
// /_archived/<name>-<stamp>/ and purge used HasPrefix(name + "-"), so
// purging "abc" would also wipe "abc-east". Post-fix the layout is
// /_archived/<name>/<stamp>/ and purge is a single os.RemoveAll on
// the per-sensor directory, which can't match another sensor's tree
// because validSensorName forbids "/" in names.
func TestPurgeSensorLogs_DoesNotCollideOnHyphenatedNames(t *testing.T) {
	logs := t.TempDir()
	s := &Server{logsDir: logs}

	// Two sensors whose names share a hyphenated prefix — exactly the
	// region-hostname convention the audit called out as common.
	mustWriteFile(t, filepath.Join(logs, "abc", "conn.log"), "abc-data")
	mustWriteFile(t, filepath.Join(logs, "abc-east", "conn.log"), "abc-east-data")

	// Disenroll-time rotation moves both /logs/abc/ and
	// /logs/abc-east/ into /_archived/<name>/<stamp>/.
	s.rotateSensorLogs("abc", "2026-01-15")
	s.rotateSensorLogs("abc-east", "2026-01-20")

	// Both archived dirs exist before the purge.
	abcArchive := filepath.Join(logs, "_archived", "abc", "2026-01-15")
	abcEastArchive := filepath.Join(logs, "_archived", "abc-east", "2026-01-20")
	if _, err := os.Stat(abcArchive); err != nil {
		t.Fatalf("abc archive missing post-rotate: %v", err)
	}
	if _, err := os.Stat(abcEastArchive); err != nil {
		t.Fatalf("abc-east archive missing post-rotate: %v", err)
	}

	// Purge "abc". Pre-fix this would also delete "abc-east"'s
	// archive because HasPrefix("abc-east-…", "abc-") matches.
	s.purgeSensorLogs("abc")

	if _, err := os.Stat(abcArchive); !os.IsNotExist(err) {
		t.Errorf("abc archive should be gone: stat err=%v", err)
	}
	if _, err := os.Stat(abcEastArchive); err != nil {
		t.Errorf("abc-east archive must NOT be deleted by purging 'abc'; got err=%v", err)
	}
}

// TestRotateSensorLogs_SuffixesOnSameDayCollision verifies that a
// second disenroll on the same calendar day for the same sensor name
// gets a counter suffix rather than merging into the existing dir.
// (Post-NEW-21 the collision is now per-sensor-per-day, so the suffix
// path moves from "<name>-<stamp>-2" to "<stamp>-2" inside the
// per-sensor archive directory.)
func TestRotateSensorLogs_SuffixesOnSameDayCollision(t *testing.T) {
	logs := t.TempDir()
	s := &Server{logsDir: logs}

	mustWriteFile(t, filepath.Join(logs, "host1", "conn.log"), "first")
	s.rotateSensorLogs("host1", "2026-01-15")

	// Re-create active dir and rotate again on the same date.
	mustWriteFile(t, filepath.Join(logs, "host1", "conn.log"), "second")
	s.rotateSensorLogs("host1", "2026-01-15")

	first := filepath.Join(logs, "_archived", "host1", "2026-01-15")
	second := filepath.Join(logs, "_archived", "host1", "2026-01-15-2")
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("first archive missing: %v", err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Errorf("second rotate should land in suffixed dir; got err=%v", err)
	}
}

func mustWriteFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
