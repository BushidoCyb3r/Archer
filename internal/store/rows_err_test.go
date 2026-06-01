package store

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	_ "modernc.org/sqlite"
)

// --- Fault-injecting sqlite driver -----------------------------------------
//
// modernc.org/sqlite offers no seam to force a mid-iteration read error, so
// this thin wrapper drives every query through the basic Prepare/Stmt path
// and makes a targeted SELECT's rows.Next() return an error after N rows.
// That reproduces the F-REL-2 condition (a partial read that looks like a
// clean end-of-rows) which the production code must not silently truncate.

var failCfg struct {
	sync.Mutex
	enabled   bool
	target    string // fail queries whose text contains this substring
	failAfter int    // return this many rows, then error
}

var registerFailOnce sync.Once

func registerFailDriver(t *testing.T) {
	t.Helper()
	registerFailOnce.Do(func() {
		probe, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatalf("open probe db: %v", err)
		}
		base := probe.Driver()
		probe.Close()
		sql.Register("sqlite-failrows", failDriver{base: base})
	})
}

type failDriver struct{ base driver.Driver }

func (d failDriver) Open(name string) (driver.Conn, error) {
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return failConn{Conn: c}, nil
}

// failConn embeds the driver.Conn interface so Close/Begin are promoted from
// the base; only Prepare is overridden. Crucially it does NOT expose the
// optional QueryerContext/ExecerContext interfaces, so database/sql routes
// every statement through Prepare → failStmt, the one path this wrapper
// controls.
type failConn struct{ driver.Conn }

func (c failConn) Prepare(query string) (driver.Stmt, error) {
	st, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return failStmt{Stmt: st, query: query}, nil
}

type failStmt struct {
	driver.Stmt
	query string
}

func (s failStmt) Query(args []driver.Value) (driver.Rows, error) {
	rows, err := s.Stmt.Query(args)
	if err != nil {
		return nil, err
	}
	failCfg.Lock()
	en, tgt, fa := failCfg.enabled, failCfg.target, failCfg.failAfter
	failCfg.Unlock()
	if en && strings.Contains(s.query, tgt) {
		return &failRows{Rows: rows, failAfter: fa}, nil
	}
	return rows, nil
}

type failRows struct {
	driver.Rows
	failAfter int
	count     int
}

func (r *failRows) Next(dest []driver.Value) error {
	if r.count >= r.failAfter {
		return errors.New("injected mid-iteration read error")
	}
	if err := r.Rows.Next(dest); err != nil {
		return err
	}
	r.count++
	return nil
}

// --- Test ------------------------------------------------------------------

// TestInitDB_TruncatedAllowlistReadDoesNotDestroyDisk is F-REL-2: a read
// error partway through the allowlist load must not be mistaken for a clean
// end-of-rows. Pre-fix loadOrdered ignored rows.Err(), so a truncated read
// returned a partial list; InitDB then sanitized it (the first entry carries
// a trailing comment, so the sanitized form differs) and re-persisted via
// DELETE-then-reinsert — permanently dropping the unread tail. The invariant:
// an incomplete authoritative-state load never rewrites the table.
func TestInitDB_TruncatedAllowlistReadDoesNotDestroyDisk(t *testing.T) {
	registerFailDriver(t)
	dbPath := filepath.Join(t.TempDir(), "store.db")

	// Seed three allowlist rows on a clean connection. Row 1 is "dirty"
	// (trailing comment) so a re-persist of a truncated read would collapse
	// the table to just the cleaned row 1.
	seed, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if err := RunMigrations(seed); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := seed.Exec(`INSERT INTO allowlist (entry) VALUES (?),(?),(?)`,
		"10.0.0.1  # workstation", "10.0.0.2", "10.0.0.3"); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	seed.Close()

	// Open through the fault driver: the allowlist SELECT fails after 1 row.
	failCfg.Lock()
	failCfg.enabled, failCfg.target, failCfg.failAfter = true, "FROM allowlist", 1
	failCfg.Unlock()
	defer func() {
		failCfg.Lock()
		failCfg.enabled = false
		failCfg.Unlock()
	}()

	db, err := sql.Open("sqlite-failrows", dbPath)
	if err != nil {
		t.Fatalf("open fault db: %v", err)
	}
	db.SetMaxOpenConns(1)
	s := New(config.Default())
	s.InitDB(db)
	db.Close()

	// Reopen cleanly and count rows on disk.
	chk, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer chk.Close()
	var n int
	if err := chk.QueryRow(`SELECT COUNT(*) FROM allowlist`).Scan(&n); err != nil {
		t.Fatalf("count allowlist: %v", err)
	}
	if n != 3 {
		t.Fatalf("allowlist on disk has %d rows, want 3 — a truncated read destructively re-persisted the partial list", n)
	}
}
