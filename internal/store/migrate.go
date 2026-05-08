package store

// SQLite schema migration framework. Numbered SQL files under
// migrations/ are embedded at build time and applied in order to the
// shared archer.db. A schema_migrations tracking table records which
// versions have been applied so subsequent boots are no-ops; failures
// roll the transaction back and abort startup so a half-applied
// schema never reaches handler code.
//
// The bootstrap-stamp logic on first boot after upgrading to the
// migration framework: if schema_migrations is empty AND a recognizable
// pre-framework table exists (we use `findings` as the sentinel because
// every Archer install since v0.1.0 has had it), version 1 is stamped
// as applied without running 0001_init.sql. The current schema on
// existing installs already matches what 0001 would create, so
// running it would either be a no-op (with IF NOT EXISTS) or an error
// (without). Stamping is the cleaner record of "this DB is at version 1".
//
// Migration policy (also documented in RELEASING.md):
//   1. Every schema change is a new file: 0002_*.sql, 0003_*.sql, ...
//   2. Never edit a migration that's been released. Apply a new one to
//      adjust whatever the previous one got wrong.
//   3. Migrations are atomic per-version (one transaction each); a
//      mid-migration crash leaves the previous version intact.
//   4. CHANGELOG entries for schema changes go under `### Breaking`
//      (pre-1.0 minor bump) so operators know to expect schema work
//      on upgrade.

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationFile is a parsed migration ready to apply.
type migrationFile struct {
	version int
	name    string // filename minus the leading "migrations/" prefix
	body    string
}

// loadMigrations walks the embedded migrations/ directory and returns
// every file sorted by version. Filenames must match NNNN_<title>.sql
// where NNNN is a positive integer; non-conforming names are a build
// error rather than a runtime surprise so the maintainer notices when
// they break the convention.
func loadMigrations() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations dir: %w", err)
	}
	var out []migrationFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, err := parseMigrationVersion(e.Name())
		if err != nil {
			return nil, fmt.Errorf("migration %q: %w", e.Name(), err)
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		out = append(out, migrationFile{version: v, name: e.Name(), body: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	// Detect duplicate version numbers: two files with the same NNNN
	// would silently apply in lexicographic order otherwise.
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("duplicate migration version %d in %q and %q", out[i].version, out[i-1].name, out[i].name)
		}
	}
	return out, nil
}

// parseMigrationVersion extracts NNNN from "NNNN_some_title.sql".
func parseMigrationVersion(name string) (int, error) {
	idx := strings.IndexAny(name, "_-.")
	if idx <= 0 {
		return 0, fmt.Errorf("filename must start with NNNN_ or NNNN-")
	}
	v, err := strconv.Atoi(name[:idx])
	if err != nil {
		return 0, fmt.Errorf("filename version prefix not numeric: %w", err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("version must be a positive integer")
	}
	return v, nil
}

// RunMigrations brings the database schema up to the version embedded
// in this binary. Safe to call repeatedly — the schema_migrations table
// gates re-application. Returns a non-nil error if any migration fails;
// callers should treat that as a hard startup failure.
func RunMigrations(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("RunMigrations: nil database handle")
	}

	// Foreign keys must be explicitly enabled per-connection in SQLite.
	// Phase 7's feed_indicators table relies on ON DELETE CASCADE; the
	// users.db connection sets MaxOpenConns=1 so this PRAGMA holds for
	// the connection's lifetime. Older migrations didn't depend on FK
	// enforcement so this is safe to enable retroactively on existing
	// installs.
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	// Ensure the tracking table exists before we look at it. Idempotent.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := readAppliedMigrations(db)
	if err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		// No embedded migrations — this is a build problem (the
		// migrations/ directory should always carry at least 0001).
		return fmt.Errorf("no migrations embedded; check //go:embed directive")
	}

	// Bootstrap-stamp existing installs that predate the migration
	// framework. The findings table has existed since v0.1.0; if it's
	// present but schema_migrations is empty, we're upgrading from a
	// pre-Phase-3 install and version 1's expected schema is already
	// in place. Stamp without running.
	if len(applied) == 0 {
		exists, err := tableExists(db, "findings")
		if err != nil {
			return fmt.Errorf("probe pre-framework schema: %w", err)
		}
		if exists {
			if _, err := db.Exec(
				`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
				1, time.Now().Unix(),
			); err != nil {
				return fmt.Errorf("bootstrap-stamp version 1: %w", err)
			}
			applied[1] = true
			log.Printf("store: existing install detected — schema migration 0001 stamped without re-running")
		}
	}

	// Apply pending migrations in order.
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := applyMigration(db, m); err != nil {
			return err
		}
		log.Printf("store: applied schema migration %04d (%s)", m.version, m.name)
	}
	return nil
}

func readAppliedMigrations(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan schema_migrations row: %w", err)
		}
		out[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// tableExists checks SQLite's sqlite_master catalog for a named table.
// Used to detect pre-migration-framework installs in the bootstrap path.
func tableExists(db *sql.DB, name string) (bool, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
		name,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// applyMigration runs one migration body inside a transaction and
// records its version on success. SQLite's database/sql driver doesn't
// support multi-statement Exec on every release, but modernc.org/sqlite
// (which this project uses) handles `;`-separated statements fine, so a
// single Exec on the whole body works.
func applyMigration(db *sql.DB, m migrationFile) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("migration %d: begin tx: %w", m.version, err)
	}
	if _, err := tx.Exec(m.body); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
		m.version, time.Now().Unix(),
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("migration %d: record applied: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %d: commit: %w", m.version, err)
	}
	return nil
}
