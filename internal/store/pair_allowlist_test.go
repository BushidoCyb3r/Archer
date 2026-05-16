package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestPairAllowlist_MatchScopeAndReload asserts the store-side
// invariants the pair-allowlist feature depends on, including the one
// the filter test can't cover from an in-process store: a rule
// survives a restart (the InitDB load path), and a delete is
// persisted.
//
// Invariant, not failure case: every match axis (src, dst, port,
// type-scope) is exercised in both directions plus the
// persistence/reload/delete lifecycle, so a future change to the
// tuple key, the type-scope rule, or the InitDB loader fails here
// instead of shipping a filter that quietly stops hiding (or never
// stops hiding) a pair.
func TestPairAllowlist_MatchScopeAndReload(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pair.db")

	db1, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db1.SetMaxOpenConns(1)
	if err := RunMigrations(db1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s1 := New(config.Default())
	s1.InitDB(db1)

	scopedID, err := s1.AddPairAllow(model.PairAllowEntry{
		Src: "10.0.0.1", Dst: "1.1.1.1", Port: "53", FindingType: "Beaconing",
	})
	if err != nil {
		t.Fatalf("AddPairAllow: %v", err)
	}

	// Match precision + type-scope safety.
	checks := []struct {
		name                  string
		src, dst, port, ftype string
		want                  bool
	}{
		{"exact match", "10.0.0.1", "1.1.1.1", "53", "Beaconing", true},
		{"same pair, other type stays visible", "10.0.0.1", "1.1.1.1", "53", "DNS Tunneling", false},
		{"different port", "10.0.0.1", "1.1.1.1", "443", "Beaconing", false},
		{"different dst", "10.0.0.1", "9.9.9.9", "53", "Beaconing", false},
		{"different src", "10.0.0.2", "1.1.1.1", "53", "Beaconing", false},
	}
	for _, c := range checks {
		if got := s1.IsPairAllowed(c.src, c.dst, c.port, c.ftype); got != c.want {
			t.Errorf("%s: IsPairAllowed(%s,%s,%s,%s)=%v, want %v",
				c.name, c.src, c.dst, c.port, c.ftype, got, c.want)
		}
	}

	// Empty FindingType is the deliberate broaden — hides every type
	// on the tuple.
	if _, err := s1.AddPairAllow(model.PairAllowEntry{
		Src: "10.0.0.9", Dst: "8.8.8.8", Port: "53", FindingType: "",
	}); err != nil {
		t.Fatalf("AddPairAllow all-types: %v", err)
	}
	if !s1.IsPairAllowed("10.0.0.9", "8.8.8.8", "53", "Beaconing") ||
		!s1.IsPairAllowed("10.0.0.9", "8.8.8.8", "53", "TI Hit (IP)") {
		t.Error("all-types rule should hide every finding type on the tuple")
	}

	// Idempotent add: re-adding the scoped rule returns the same id,
	// no duplicate.
	if again, err := s1.AddPairAllow(model.PairAllowEntry{
		Src: "10.0.0.1", Dst: "1.1.1.1", Port: "53", FindingType: "Beaconing",
	}); err != nil || again != scopedID {
		t.Errorf("idempotent add: got id=%d err=%v, want id=%d err=nil", again, err, scopedID)
	}
	if n := len(s1.ListPairAllowlist()); n != 2 {
		t.Errorf("after idempotent re-add: %d rules, want 2", n)
	}
	_ = db1.Close()

	// Reload from the same DB into a fresh Store: the load path in
	// InitDB must rebuild the index so the rules still apply.
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	db2.SetMaxOpenConns(1)
	defer db2.Close()
	s2 := New(config.Default())
	s2.InitDB(db2)

	if !s2.IsPairAllowed("10.0.0.1", "1.1.1.1", "53", "Beaconing") {
		t.Error("scoped rule did not survive reload")
	}
	if !s2.IsPairAllowed("10.0.0.9", "8.8.8.8", "53", "anything") {
		t.Error("all-types rule did not survive reload")
	}
	if n := len(s2.ListPairAllowlist()); n != 2 {
		t.Errorf("reloaded store has %d rules, want 2", n)
	}

	// Delete is persisted.
	s2.RemovePairAllow(scopedID)
	if s2.IsPairAllowed("10.0.0.1", "1.1.1.1", "53", "Beaconing") {
		t.Error("scoped rule still matches after RemovePairAllow")
	}
	_ = db2.Close()

	db3, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen db3: %v", err)
	}
	db3.SetMaxOpenConns(1)
	defer db3.Close()
	s3 := New(config.Default())
	s3.InitDB(db3)
	if s3.IsPairAllowed("10.0.0.1", "1.1.1.1", "53", "Beaconing") {
		t.Error("deleted rule reappeared after reload — delete was not persisted")
	}
	if n := len(s3.ListPairAllowlist()); n != 1 {
		t.Errorf("after delete + reload: %d rules, want 1 (the all-types rule)", n)
	}
}
