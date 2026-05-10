package store

import (
	"database/sql"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// openTestDB opens a fresh SQLite file under t.TempDir(). Closes
// automatically on test cleanup.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// listTables returns every user-defined table in the database, sorted
// alphabetically. Used to assert post-migration schema state.
func listTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		out = append(out, n)
	}
	return out
}

func TestRunMigrations_FreshDB_AppliesAllMigrations(t *testing.T) {
	db := openTestDB(t)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("first migration run: %v", err)
	}

	// schema_migrations should contain version 1 (and any others embedded).
	applied, err := readAppliedMigrations(db)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if !applied[1] {
		t.Errorf("version 1 not applied after fresh-DB migration: %v", applied)
	}

	// All tables defined in 0001_init.sql should exist.
	tables := listTables(t, db)
	expected := []string{
		"allowlist",
		"enrollment_tokens",
		"findings",
		"ioc_list",
		"schema_migrations",
		"sensors",
		"settings",
		"suppressions",
		"unauthorized_attempts",
		"users",
	}
	sort.Strings(tables)
	for _, want := range expected {
		found := false
		for _, got := range tables {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected table %q after fresh migration; got %v", want, tables)
		}
	}
}

func TestRunMigrations_ExistingPreFrameworkDB_StampsVersion1(t *testing.T) {
	db := openTestDB(t)

	// Simulate a pre-Phase-3 install: tables created directly without
	// the migration framework, leaving schema_migrations nonexistent.
	// RunMigrations should detect the existing schema and stamp
	// version 1 without trying to re-run 0001. The sentinel for the
	// pre-framework detection is `findings`; the rest of the tables
	// are seeded as stubs because 0001 created all of them and any
	// later migration that ALTERs a 0001-defined table would fail
	// against a single-table seed (e.g. 0007 ADD COLUMN on `sensors`,
	// or any future ALTER of `users`).
	preFrameworkTables := []string{
		`CREATE TABLE findings (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE sensors (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE allowlist (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE ioc_list (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE settings (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE suppressions (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE enrollment_tokens (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE unauthorized_attempts (id INTEGER PRIMARY KEY)`,
	}
	for _, ddl := range preFrameworkTables {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("seed pre-framework table: %v", err)
		}
	}

	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrations against pre-framework DB: %v", err)
	}

	applied, err := readAppliedMigrations(db)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if !applied[1] {
		t.Errorf("version 1 should be stamped on pre-framework DB; applied=%v", applied)
	}

	// Crucially: the findings table we seeded must still be there with
	// only its single column. If RunMigrations had re-run 0001, the
	// CREATE TABLE IF NOT EXISTS would have been a no-op (preserving the
	// stub), but if a future migration wasn't IF NOT EXISTS the seed
	// could have been clobbered. Verify the stub survived.
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('findings')`).Scan(&count); err != nil {
		t.Fatalf("inspect findings columns: %v", err)
	}
	if count != 1 {
		t.Errorf("seeded findings table appears to have been re-created; expected 1 column, got %d", count)
	}
}

func TestRunMigrations_Idempotent(t *testing.T) {
	db := openTestDB(t)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Snapshot applied versions after the first run.
	first, _ := readAppliedMigrations(db)

	// Second run must succeed without error and not touch
	// schema_migrations.
	if err := RunMigrations(db); err != nil {
		t.Fatalf("second run (should be idempotent): %v", err)
	}
	second, _ := readAppliedMigrations(db)

	if len(first) != len(second) {
		t.Errorf("idempotent re-run added rows: before=%v after=%v", first, second)
	}
	for v := range first {
		if !second[v] {
			t.Errorf("version %d disappeared on idempotent re-run", v)
		}
	}
}

func TestParseMigrationVersion(t *testing.T) {
	cases := []struct {
		name    string
		want    int
		wantErr bool
	}{
		{"0001_init.sql", 1, false},
		{"0002_rename_dataset.sql", 2, false},
		{"42_short.sql", 42, false},
		{"0010-dash-style.sql", 10, false},
		{"no_version.sql", 0, true},
		{"", 0, true},
		{"_leading.sql", 0, true},
		{"0_zero.sql", 0, true},
		{"-1_neg.sql", 0, true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, err := parseMigrationVersion(c.name)
			if c.wantErr {
				if err == nil {
					t.Errorf("parseMigrationVersion(%q) = %d, nil; expected error", c.name, got)
				}
				return
			}
			if err != nil {
				t.Errorf("parseMigrationVersion(%q) errored: %v", c.name, err)
				return
			}
			if got != c.want {
				t.Errorf("parseMigrationVersion(%q) = %d; want %d", c.name, got, c.want)
			}
		})
	}
}

func TestApplyMigration_RollsBackOnSQLError(t *testing.T) {
	db := openTestDB(t)

	// Bring schema_migrations into existence so applyMigration's INSERT
	// has a target.
	if _, err := db.Exec(
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`,
	); err != nil {
		t.Fatalf("seed schema_migrations: %v", err)
	}

	bad := migrationFile{
		version: 99,
		name:    "0099_invalid.sql",
		body:    `CREATE TABLE valid (id INTEGER); SELECT * FROM nonexistent_table;`,
	}

	if err := applyMigration(db, bad); err == nil {
		t.Fatal("expected error from migration with invalid SQL; got nil")
	}

	// The "valid" CREATE inside the failing migration must be rolled back
	// — the table should NOT exist post-failure. This is the atomicity
	// guarantee we promise in the migrate.go header.
	var count int
	_ = db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='valid'`,
	).Scan(&count)
	if count != 0 {
		t.Errorf("partial migration was committed: 'valid' table exists after rollback")
	}

	// And version 99 must not be recorded as applied.
	applied, _ := readAppliedMigrations(db)
	if applied[99] {
		t.Error("failing migration recorded as applied")
	}
}

func TestLoadMigrations_FindsEmbeddedFiles(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no embedded migrations found; embed.FS misconfigured?")
	}
	if migrations[0].version != 1 {
		t.Errorf("first migration version = %d; want 1", migrations[0].version)
	}
	// Versions must be strictly increasing (loadMigrations sorts and
	// rejects duplicates, so a sort-monotone walk is enough).
	for i := 1; i < len(migrations); i++ {
		if migrations[i].version <= migrations[i-1].version {
			t.Errorf("migration order broken: %d (%s) follows %d (%s)",
				migrations[i].version, migrations[i].name,
				migrations[i-1].version, migrations[i-1].name)
		}
	}
	// Spot-check that 0001's body actually contains the expected schema —
	// catches a misnamed file that loaded but doesn't have the right
	// content.
	if !strings.Contains(migrations[0].body, "CREATE TABLE IF NOT EXISTS findings") {
		t.Error("0001_init.sql doesn't appear to contain the findings table")
	}
}
