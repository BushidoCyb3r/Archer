package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestDetectedAt_SurvivesReanalysis codifies the invariant the per-user
// "new since you last looked" count rests on (migration 0029): a finding's
// detected_at is stamped once when its fingerprint first enters the store
// and is carried forward UNCHANGED on every later merge — exactly like the
// stable ID — even as the volatile IsNew flag flips to false. If detected_at
// were re-stamped each run (the bug class the old is_new count had), every
// hourly watch pass would reset a finding's age and the login modal would
// undercount. The test drives two SetFindings passes over the same
// fingerprint and asserts the timestamp is identical across them.
func TestDetectedAt_SurvivesReanalysis(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	beacon := func() model.Finding {
		return model.Finding{
			Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-29 09:00:00",
		}
	}

	// First pass: fresh fingerprint. detected_at stamped, IsNew true.
	s.SetFindings([]model.Finding{beacon()})
	if len(s.findings) != 1 {
		t.Fatalf("first pass: want 1 finding, got %d", len(s.findings))
	}
	first := s.findings[0]
	if first.DetectedAt <= 0 {
		t.Fatalf("first pass: detected_at not stamped (%d)", first.DetectedAt)
	}
	if !first.IsNew {
		t.Error("first pass: fresh fingerprint should be IsNew")
	}

	// Second pass over the same fingerprint: carried forward. detected_at
	// must be unchanged; IsNew must drop to false.
	s.SetFindings([]model.Finding{beacon()})
	if len(s.findings) != 1 {
		t.Fatalf("second pass: want 1 finding, got %d", len(s.findings))
	}
	second := s.findings[0]
	if second.DetectedAt != first.DetectedAt {
		t.Errorf("detected_at changed across re-analysis: first=%d second=%d (must be carried forward)", first.DetectedAt, second.DetectedAt)
	}
	if second.IsNew {
		t.Error("second pass: carried-forward finding should not be IsNew")
	}

	// Survives a reload from disk into a fresh Store.
	s2 := New(config.Default())
	s2.InitDB(db)
	if len(s2.findings) != 1 {
		t.Fatalf("reload: want 1 finding, got %d", len(s2.findings))
	}
	if s2.findings[0].DetectedAt != first.DetectedAt {
		t.Errorf("detected_at lost across reload: want %d, got %d", first.DetectedAt, s2.findings[0].DetectedAt)
	}
}

// TestCountUnseen covers the per-user unseen count: findings detected after
// the marker, roll-ups excluded, with the total spanning everything. The
// boundary is strict (> since), so a marker equal to the detection time
// reports zero — that's what advancing the marker on modal-dismiss relies
// on to silence already-seen findings.
func TestCountUnseen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	// Two per-record detections plus one roll-up, all stamped this pass.
	s.SetFindings([]model.Finding{
		{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-29 09:00:00"},
		{Type: "DNS Tunneling", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", DstPort: "53",
			Score: 70, Severity: model.SevMedium, Timestamp: "2026-05-29 09:00:00"},
		{Type: model.TypeHostRiskScore, SrcIP: "10.0.0.1", DstIP: "", DstPort: "",
			Score: 90, Severity: model.SevCritical, Timestamp: "2026-05-29 09:00:00"},
	})
	if len(s.findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(s.findings))
	}
	dt := s.findings[0].DetectedAt
	if dt <= 0 {
		t.Fatalf("detected_at not stamped (%d)", dt)
	}

	// Marker just before detection: both per-record findings are unseen,
	// the roll-up is excluded, total counts all three.
	unseen, total := s.CountUnseen(dt - 1)
	if unseen != 2 {
		t.Errorf("unseen with marker before detection = %d, want 2 (roll-up excluded)", unseen)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3 (roll-up included in total)", total)
	}

	// Marker at detection time: strict > means nothing is unseen.
	if unseen, _ := s.CountUnseen(dt); unseen != 0 {
		t.Errorf("unseen with marker at detection time = %d, want 0", unseen)
	}
}

// TestSessionNewBoundary covers the per-session new-findings boundary: a new
// account starts caught-up (marker seeded at creation), opening a session
// freezes the PREVIOUS marker as the session's boundary and advances the
// stored marker to now, the next session anchors against that, and an unknown
// token reads as zero ("everything new"). This is what keeps the modal and
// the "New only" filter showing the same stable set across a session instead
// of resetting on dismiss.
func TestSessionNewBoundary(t *testing.T) {
	us := newAuthTestStore(t)
	u, err := us.CreateUser("seen@example.com", "See", "Enn", "password-123456", model.RoleAnalyst, model.StatusActive)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// New account starts caught-up: marker seeded at creation (> 0).
	var seeded int64
	us.db.QueryRow(`SELECT findings_seen_at FROM users WHERE id = ?`, u.ID).Scan(&seeded)
	if seeded <= 0 {
		t.Errorf("new user findings_seen_at = %d, want > 0 (seeded at creation)", seeded)
	}

	// Pin a known previous-login time, then open a session: it freezes that
	// value as the boundary and advances the stored marker past it.
	if _, err := us.db.Exec(`UPDATE users SET findings_seen_at = ? WHERE id = ?`, int64(1000), u.ID); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	tok := us.CreateSession(u.ID)
	if b := us.SessionNewBoundary(tok); b != 1000 {
		t.Errorf("session boundary = %d, want 1000 (frozen previous marker)", b)
	}
	var advanced int64
	us.db.QueryRow(`SELECT findings_seen_at FROM users WHERE id = ?`, u.ID).Scan(&advanced)
	if advanced <= 1000 {
		t.Errorf("findings_seen_at after login = %d, want advanced past 1000", advanced)
	}

	// A second login anchors against the value the first login wrote.
	tok2 := us.CreateSession(u.ID)
	if b := us.SessionNewBoundary(tok2); b != advanced {
		t.Errorf("second session boundary = %d, want %d (time the first login set)", b, advanced)
	}

	// Unknown token reads as zero.
	if b := us.SessionNewBoundary("nope"); b != 0 {
		t.Errorf("unknown token boundary = %d, want 0", b)
	}
}
