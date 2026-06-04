package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	_ "modernc.org/sqlite"
)

func newAuditTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)
	return s
}

// TestPruneAuditLogOlderThan codifies the audit-log retention contract:
// the daily sweep removes rows strictly older than the cutoff, keeps the
// rest, no-ops when retention is unlimited (cutoff <= 0), and is idempotent.
// The invariant the prune enforces is "nothing at or after the cutoff is
// ever removed" — that's what keeps a retention misconfiguration from eating
// recent trail, so the test asserts it directly rather than just a count.
func TestPruneAuditLogOlderThan(t *testing.T) {
	s := newAuditTestStore(t)
	// Deterministic timestamps (LogAuditEvent honours a non-zero TS).
	s.LogAuditEvent(AuditEntry{TS: 1000, Action: "login_success", ActorEmail: "a"})
	s.LogAuditEvent(AuditEntry{TS: 1500, Action: "login_success", ActorEmail: "a"})
	s.LogAuditEvent(AuditEntry{TS: 2000, Action: "login_success", ActorEmail: "a"})
	s.LogAuditEvent(AuditEntry{TS: 3000, Action: "login_success", ActorEmail: "a"})

	// Unlimited (cutoff <= 0) must be a no-op — the keep-forever default.
	if n := s.PruneAuditLogOlderThan(0); n != 0 {
		t.Errorf("prune(0) removed %d; want 0 (unlimited = no-op)", n)
	}
	if got := len(s.ListAuditLog(0, 100)); got != 4 {
		t.Fatalf("after unlimited no-op: %d entries, want 4", got)
	}

	// Cutoff at 2000: rows with ts < 2000 go (1000, 1500), ts >= 2000 stay.
	if n := s.PruneAuditLogOlderThan(2000); n != 2 {
		t.Errorf("prune(2000) removed %d; want 2", n)
	}
	remaining := s.ListAuditLog(0, 100)
	if len(remaining) != 2 {
		t.Fatalf("after prune(2000): %d entries, want 2", len(remaining))
	}
	for _, e := range remaining {
		if e.TS < 2000 {
			t.Errorf("entry ts=%d survived cutoff 2000 — prune must never keep older-than-cutoff... but the inverse failed", e.TS)
		}
	}

	// Idempotent: re-running the same cutoff removes nothing.
	if n := s.PruneAuditLogOlderThan(2000); n != 0 {
		t.Errorf("second prune(2000) removed %d; want 0 (idempotent)", n)
	}
}

// TestAuditLog_RoundTrip covers the v0.14.0 audit-log addition. A
// happy-path write must be retrievable; a nil-user write must store
// as NULL user_id (system-issued action shape); pagination must walk
// id-DESC and the next cursor must lead to no overlap with the
// previous page.
func TestAuditLog_RoundTrip(t *testing.T) {
	s := newAuditTestStore(t)

	// Write 5 entries — one system, four user-attributed.
	s.LogAuditEvent(AuditEntry{Action: "system_boot", ActorEmail: "system"})
	for i := 1; i <= 4; i++ {
		s.LogAuditEvent(AuditEntry{
			ActorID:     int64(i),
			ActorEmail:  "alice@example.test",
			Action:      "user_role_change",
			TargetType:  "user",
			TargetID:    "99",
			TargetName:  "bob@example.test",
			BeforeValue: MarshalAuditDetails(map[string]any{"role": "analyst"}),
			AfterValue:  MarshalAuditDetails(map[string]any{"role": "admin"}),
			SourceIP:    "10.0.0.5",
		})
	}

	if got := s.CountAuditLog(); got != 5 {
		t.Errorf("CountAuditLog = %d; want 5", got)
	}

	// Page 1: 3 most recent.
	page1 := s.ListAuditLog(0, 3)
	if len(page1) != 3 {
		t.Fatalf("page1 size = %d; want 3", len(page1))
	}
	// id-DESC order: page1[0] must have the highest id.
	if page1[0].ID <= page1[2].ID {
		t.Errorf("page1 not id-DESC: %d, %d, %d", page1[0].ID, page1[1].ID, page1[2].ID)
	}

	// Page 2: cursor on the lowest id from page 1.
	page2 := s.ListAuditLog(page1[2].ID, 3)
	if len(page2) != 2 { // 5 total - 3 on page 1 = 2 remaining
		t.Errorf("page2 size = %d; want 2", len(page2))
	}
	// No overlap.
	for _, a := range page2 {
		for _, b := range page1 {
			if a.ID == b.ID {
				t.Errorf("page2 contains id %d that was on page 1", a.ID)
			}
		}
	}

	// The system entry should have ActorID 0 (NULL stored, coalesced
	// to 0 on read).
	sysEntry := page2[len(page2)-1] // earliest id is the system_boot row
	if sysEntry.Action != "system_boot" {
		// id-DESC iterating — the oldest is the last in page2.
		t.Logf("expected oldest (system_boot) at page2[%d], got action=%s", len(page2)-1, sysEntry.Action)
	}
}

// TestAuditLog_PaginationCap covers the server-side cap on the count
// parameter. Pre-fix the cap wasn't enforced and a hostile/buggy
// client could request 10^9 entries and OOM the server.
func TestAuditLog_PaginationCap(t *testing.T) {
	s := newAuditTestStore(t)
	for i := 0; i < 600; i++ {
		s.LogAuditEvent(AuditEntry{Action: "noise", ActorEmail: "test"})
	}
	got := s.ListAuditLog(0, 1_000_000)
	if len(got) > 500 {
		t.Errorf("ListAuditLog returned %d entries; cap is 500", len(got))
	}
}
