package store

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestBulkUpdateStatus pins the batched status-transition contract behind the
// bulk ack/escalate/dismiss endpoint: every present, not-already-in-target id
// flips to the new status (with analyst/note/ts), missing and duplicate ids are
// skipped, the returned count and before-snapshots are accurate, and a DB
// failure applies nothing in memory while raising the persistence-degraded flag.
func TestBulkUpdateStatus(t *testing.T) {
	db := openTestDB(t)
	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	mk := func(typ, src, dst string) model.Finding {
		return model.Finding{Type: typ, SrcIP: src, DstIP: dst, DstPort: "443", Timestamp: "2026-01-01 00:00:00"}
	}
	s.SetFindings([]model.Finding{
		mk("Beacon", "10.0.0.1", "203.0.113.1"),
		mk("Beacon", "10.0.0.2", "203.0.113.2"),
		mk("Exfil", "10.0.0.3", "203.0.113.3"),
		mk("DNS Tunnel", "10.0.0.4", "203.0.113.4"),
	})
	all := s.GetFindings()
	if len(all) != 4 {
		t.Fatalf("seed: got %d findings, want 4", len(all))
	}
	byID := func() map[int]model.Finding {
		m := map[int]model.Finding{}
		for _, f := range s.GetFindings() {
			m[f.ID] = f
		}
		return m
	}
	targets := []int{all[0].ID, all[1].ID, all[2].ID}

	// Acknowledge three, with a duplicate id and a missing id mixed in — both
	// must be ignored so the count reflects only distinct, present targets.
	arg := append(append([]int{}, targets...), targets[0], 999999)
	befores, n := s.BulkUpdateStatus(arg, model.StatusAcknowledged, "alice", "triaged", "2026-01-02 00:00:00 UTC")
	if n != 3 {
		t.Errorf("affected = %d, want 3 (duplicate + missing id must be skipped)", n)
	}
	if len(befores) != 3 {
		t.Fatalf("befores len = %d, want 3", len(befores))
	}
	for _, b := range befores {
		if b.Status != model.StatusOpen {
			t.Errorf("before snapshot status = %q, want open", b.Status)
		}
	}

	got := byID()
	for _, id := range targets {
		f := got[id]
		if f.Status != model.StatusAcknowledged {
			t.Errorf("id %d status = %q, want acknowledged", id, f.Status)
		}
		if f.Analyst != "alice" || f.AnalystNote != "triaged" || f.StatusTS != "2026-01-02 00:00:00 UTC" {
			t.Errorf("id %d fields not applied: analyst=%q note=%q ts=%q", id, f.Analyst, f.AnalystNote, f.StatusTS)
		}
	}
	if got[all[3].ID].Status != model.StatusOpen {
		t.Errorf("untouched finding %d changed status to %q", all[3].ID, got[all[3].ID].Status)
	}

	// Re-applying the same status is a no-op (already in target).
	if _, n2 := s.BulkUpdateStatus(targets, model.StatusAcknowledged, "bob", "again", "ts"); n2 != 0 {
		t.Errorf("re-applying the same status affected = %d, want 0", n2)
	}

	// DB failure: closing the handle makes the transaction fail; nothing is
	// applied in memory and the persistence-degraded flag is raised.
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if _, n3 := s.BulkUpdateStatus([]int{all[3].ID}, model.StatusDismissed, "bob", "", "ts"); n3 != 0 {
		t.Errorf("affected on closed DB = %d, want 0", n3)
	}
	if f, _ := s.GetFinding(all[3].ID); f.Status != model.StatusOpen {
		t.Errorf("closed-DB bulk update applied an in-memory change: status=%q, want open", f.Status)
	}
	if s.PersistenceError() == "" {
		t.Error("closed-DB bulk update did not raise the persistence-degraded flag")
	}
}
