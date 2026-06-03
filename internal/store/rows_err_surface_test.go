package store

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// These tests cover the rows.Err()/integrity-read fixes: a read that aborts
// mid-iteration must never be mistaken for a clean end-of-rows. They reuse the
// fault-injecting sqlite driver from rows_err_test.go (same package).

// recordingHandler captures emitted slog records so a test can assert that an
// incomplete read was surfaced rather than silently swallowed.
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// sawSurfaced reports whether a record at warn level or above carried the
// substring — i.e. the condition was surfaced, not silently swallowed.
func (h *recordingHandler) sawSurfaced(substr string) bool {
	for _, r := range h.records {
		if r.Level >= slog.LevelWarn && strings.Contains(r.Message, substr) {
			return true
		}
	}
	return false
}

// TestCheckIntegrity_TruncatedReadIsNotHealthy asserts the startup integrity
// gate fails closed: if the PRAGMA integrity_check read aborts before SQLite
// emits its result, CheckIntegrity must return an error, not nil ("healthy").
// A false-clean here would let a corrupt volume pass the startup gate.
func TestCheckIntegrity_TruncatedReadIsNotHealthy(t *testing.T) {
	registerFailDriver(t)
	dbPath := filepath.Join(t.TempDir(), "store.db")

	seed, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if err := RunMigrations(seed); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	seed.Close()

	db, err := sql.Open("sqlite-failrows", dbPath)
	if err != nil {
		t.Fatalf("open fault db: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := New(config.Default())
	s.InitDB(db) // fault not yet enabled — InitDB runs clean

	// Fail the integrity_check read on its very first row.
	failCfg.Lock()
	failCfg.enabled, failCfg.target, failCfg.failAfter = true, "integrity_check", 0
	failCfg.Unlock()
	defer func() {
		failCfg.Lock()
		failCfg.enabled = false
		failCfg.Unlock()
	}()

	err = s.CheckIntegrity()
	if err == nil {
		t.Fatal("CheckIntegrity returned nil on a truncated read — a corrupt volume would pass the startup gate")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("CheckIntegrity error = %q, want it to name the incomplete read", err)
	}
}

// TestListUnauthorizedAttempts_TruncatedReadIsSurfaced asserts the read-getter
// class surfaces a truncated read at error level instead of silently returning
// a partial slice as if it were the complete set. unauthorized_attempts is used
// because it has no foreign keys; the fix pattern is identical across every
// getter touched (sensors, feeds, service tokens, beacon history, users, audit).
func TestListUnauthorizedAttempts_TruncatedReadIsSurfaced(t *testing.T) {
	registerFailDriver(t)
	dbPath := filepath.Join(t.TempDir(), "store.db")

	seed, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if err := RunMigrations(seed); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := seed.Exec(`INSERT INTO unauthorized_attempts
		(name, source_ip, first_seen, last_seen, attempt_count, pinned)
		VALUES (?,?,?,?,1,0),(?,?,?,?,1,0),(?,?,?,?,1,0)`,
		"a", "1.1.1.1", 1, 1, "b", "2.2.2.2", 2, 2, "c", "3.3.3.3", 3, 3); err != nil {
		t.Fatalf("seed attempts: %v", err)
	}
	seed.Close()

	db, err := sql.Open("sqlite-failrows", dbPath)
	if err != nil {
		t.Fatalf("open fault db: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := New(config.Default())
	s.InitDB(db)

	rec := &recordingHandler{}
	old := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(old)

	failCfg.Lock()
	failCfg.enabled, failCfg.target, failCfg.failAfter = true, "FROM unauthorized_attempts", 1
	failCfg.Unlock()
	defer func() {
		failCfg.Lock()
		failCfg.enabled = false
		failCfg.Unlock()
	}()

	got := s.ListUnauthorizedAttempts()

	if len(got) >= 3 {
		t.Fatalf("expected a truncated read (<3 rows), got %d — fault driver did not engage", len(got))
	}
	if !rec.sawSurfaced("incomplete unauthorized-attempts read") {
		t.Fatal("truncated read was not surfaced in the log — a partial result was returned as if complete")
	}
}
