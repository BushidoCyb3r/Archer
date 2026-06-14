package store

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestSetConfigPreservingRuntime_WorkerTelemetrySurvives is the ARC-2
// regression. The admin Settings PUT is a read-decode-write: it reads the
// config, edits operator-editable fields, and writes the whole struct back. The
// runtime/telemetry fields (analysis timestamps, dataset fingerprint, archive-run
// results) ride in that struct but are owned by the background watch/archive
// workers, not the admin. The invariant: a worker telemetry write that lands
// after the admin's read is NOT rolled back by the admin's subsequent write —
// the merge keeps the live telemetry and applies only the operator edits.
func TestSetConfigPreservingRuntime_WorkerTelemetrySurvives(t *testing.T) {
	db := openTestDB(t)
	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	// Baseline telemetry, as if a prior run had set it.
	t0 := time.Unix(1_700_000_000, 0).UTC()
	s.SetLastAnalysisTime(t0)
	s.SetLastAnalysisFingerprint("fp-old")

	// Admin opens Settings and reads a snapshot — it carries the t0 telemetry.
	adminEdit := s.GetConfig()
	adminEdit.BeaconMinConnections = 9 // an operator-editable threshold change

	// Between the admin's read and write, a watch worker finishes a run and an
	// archive worker finishes a sweep, writing fresher telemetry to the store.
	t1 := time.Unix(1_700_009_999, 0).UTC()
	s.SetLastAnalysisTime(t1)
	s.SetLastAnalysisFingerprint("fp-new")
	s.RecordArchiveRun(7, 4096, 3, "watch")

	// Admin submits the PUT carrying its now-stale snapshot.
	saved := s.SetConfigPreservingRuntime(adminEdit)

	// The operator edit must land.
	if saved.BeaconMinConnections != 9 {
		t.Errorf("operator edit lost: BeaconMinConnections = %d, want 9", saved.BeaconMinConnections)
	}
	// The worker telemetry must NOT have been rolled back to the t0 snapshot.
	if saved.LastAnalysisUnix != t1.Unix() {
		t.Errorf("returned config rolled back telemetry: LastAnalysisUnix = %d, want %d (t1)", saved.LastAnalysisUnix, t1.Unix())
	}
	if saved.LastAnalysisFingerprint != "fp-new" {
		t.Errorf("returned config rolled back fingerprint: %q, want fp-new", saved.LastAnalysisFingerprint)
	}
	if saved.ArchiveLastTriggeredBy != "watch" || saved.ArchiveLastFilesArchived != 7 {
		t.Errorf("returned config rolled back archive telemetry: triggeredBy=%q files=%d, want watch/7", saved.ArchiveLastTriggeredBy, saved.ArchiveLastFilesArchived)
	}

	// And the persisted/live store agrees — the write committed the merge.
	if got := s.GetLastAnalysisTime(); !got.Equal(t1) {
		t.Errorf("live store telemetry clobbered: LastAnalysisTime = %v, want %v", got, t1)
	}
	if live := s.GetConfig(); live.BeaconMinConnections != 9 || live.LastAnalysisUnix != t1.Unix() {
		t.Errorf("live config mismatch after merge: BeaconMinConnections=%d LastAnalysisUnix=%d, want 9/%d",
			live.BeaconMinConnections, live.LastAnalysisUnix, t1.Unix())
	}
}
