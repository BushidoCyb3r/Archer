package store

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestSaveFindings_PersistenceErrorFlag is the AR-3 regression. A findings
// write failure (disk full, DB locked/closed) used to be log-only, so
// in-memory state could silently diverge from disk — analyst status/notes
// made afterward would persist in memory and vanish on the next restart with
// no operator signal. saveFindings now records the failure on the store
// (surfaced by the analyze-status endpoint and a watch SSE status event) and
// clears it on the next successful save. The invariant: PersistenceError is
// empty after a save that committed and non-empty after one that didn't.
func TestSaveFindings_PersistenceErrorFlag(t *testing.T) {
	db := openTestDB(t)
	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	mk := func(typ, src, dst string) model.Finding {
		return model.Finding{Type: typ, SrcIP: src, DstIP: dst, DstPort: "443", Timestamp: "2026-01-01 00:00:00"}
	}

	// Baseline: a save that commits leaves no persistence error.
	s.SetFindings([]model.Finding{mk("Beacon", "10.0.0.1", "203.0.113.1")})
	if pe := s.PersistenceError(); pe != "" {
		t.Fatalf("after a successful save, PersistenceError = %q, want empty", pe)
	}

	// Induce a real write failure by closing the DB out from under the store.
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	s.SetFindings([]model.Finding{mk("Strobe", "10.0.0.2", "203.0.113.2")})
	if pe := s.PersistenceError(); pe == "" {
		t.Fatalf("after a failed save (DB closed), PersistenceError is empty — the failure was not surfaced")
	}

	// Recovery: re-point the store at a working DB; the next successful save
	// must clear the flag (proves the defer clears, not just sets).
	db2 := openTestDB(t)
	if err := RunMigrations(db2); err != nil {
		t.Fatalf("RunMigrations (db2): %v", err)
	}
	s.InitDB(db2)
	s.SetFindings([]model.Finding{mk("Beacon", "10.0.0.3", "203.0.113.3")})
	if pe := s.PersistenceError(); pe != "" {
		t.Errorf("after recovery save, PersistenceError = %q, want empty (flag should clear on success)", pe)
	}
}
