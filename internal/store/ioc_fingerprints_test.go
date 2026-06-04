package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestIOCFingerprints_RoundTripAndSanitize codifies the operator JA3/JA4 IOC
// list contract (migration 0033): entries are lowercased, stripped of inline
// labels, de-commented, and deduped on save; the cleaned list survives a
// reopen→reload; and AddIOCFingerprint appends exactly-once. The list is the
// operator-supplied half of Malicious JA3/JA4 detection, so a silent drop or a
// case mismatch (the analyzer reads lowercased ja3/ja4) would mean a pasted
// fingerprint never fires.
func TestIOCFingerprints_RoundTripAndSanitize(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
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

	// Mixed input: uppercase JA3, an inline label, a whole-line comment, a
	// case-variant duplicate of the first, a JA4, and a blank line.
	s1.SetIOCFingerprints([]string{
		"AABBCCDDAABBCCDDAABBCCDDAABBCCDD  # cobalt variant",
		"# section header",
		"aabbccddaabbccddaabbccddaabbccdd",
		"T13D1234H1_AAAA_BBBB",
		"",
	})

	want := []string{
		"aabbccddaabbccddaabbccddaabbccdd",
		"t13d1234h1_aaaa_bbbb",
	}
	if got := s1.GetIOCFingerprints(); !slicesEqual(got, want) {
		t.Fatalf("after SetIOCFingerprints = %v; want %v", got, want)
	}

	// AddIOCFingerprint appends a new entry once and no-ops on a repeat.
	if !s1.AddIOCFingerprint("EE11EE11EE11EE11EE11EE11EE11EE11") {
		t.Errorf("AddIOCFingerprint(new) = false; want true")
	}
	if s1.AddIOCFingerprint("ee11ee11ee11ee11ee11ee11ee11ee11") {
		t.Errorf("AddIOCFingerprint(existing, different case) = true; want false (already present)")
	}
	want = append(want, "ee11ee11ee11ee11ee11ee11ee11ee11")
	_ = db1.Close()

	// Reopen into a fresh store — InitDB's loadOrdered must restore the list.
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	db2.SetMaxOpenConns(1)
	defer db2.Close()

	s2 := New(config.Default())
	s2.InitDB(db2)
	if got := s2.GetIOCFingerprints(); !slicesEqual(got, want) {
		t.Fatalf("after reload = %v; want %v", got, want)
	}
}
