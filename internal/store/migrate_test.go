package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
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
		// findings carries `type` because a real pre-framework install
		// created it with the full 0001 schema, and migration 0031 reads
		// findings.type. The stub still omits the rest of 0001's columns so
		// the re-run check below can detect a spurious 0001 re-create.
		`CREATE TABLE findings (id INTEGER PRIMARY KEY, type TEXT)`,
		`CREATE TABLE sensors (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE allowlist (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE ioc_list (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE settings (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE suppressions (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE enrollment_tokens (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE unauthorized_attempts (id INTEGER PRIMARY KEY)`,
		// audit_log is created by migration 0009. Pre-framework
		// installs predated that migration so they don't have the
		// table — but later migrations don't ALTER it either, so
		// no seed is needed here. This comment lives in the loop
		// body to remind future-you that 0009 was post-Phase-3
		// and doesn't need pre-seeding.
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

	// Crucially: the seeded findings table must survive — RunMigrations
	// must NOT have re-run 0001 and re-created the table. Later
	// migrations (e.g. 0010 adding the correlations column) legitimately
	// add columns to findings, so we can't just check the column count.
	// Verify the original `id` column from the stub is still present
	// (and the only non-migration column); a CREATE TABLE re-run would
	// have produced 0001's full column set instead.
	cols := map[string]bool{}
	rows2, err := db.Query(`SELECT name FROM pragma_table_info('findings')`)
	if err != nil {
		t.Fatalf("inspect findings columns: %v", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var name string
		if err := rows2.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		cols[name] = true
	}
	if !cols["id"] {
		t.Errorf("seeded findings table missing the `id` column; expected stub to survive")
	}
	// If 0001 had been re-run, the table would have ~20+ columns from
	// the full v0.1.0 schema. The stub had id + type (the latter needed by
	// 0031); migrations 0002-0009 don't touch findings; 0010 adds
	// correlations. So only id, type, and columns from post-0001 migrations
	// should be present. If any other 0001 column (like `severity`,
	// `src_ip`) shows up, 0001 was re-run against the seeded table.
	for _, postStub := range []string{"severity", "src_ip", "dst_ip", "score"} {
		if cols[postStub] {
			t.Errorf("seeded findings table has %q column — 0001 was re-run against the existing stub", postStub)
		}
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

// applyMigrationsUpTo replays the embedded migration chain through
// version n on a fresh DB — the exact schema a deployment that stopped
// upgrading at version n had, since released migrations are never
// edited. schema_migrations is created first because applyMigration
// records each version (RunMigrations normally owns that).
func applyMigrationsUpTo(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range migrations {
		if m.version > n {
			break
		}
		if err := applyMigration(db, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}
}

// TestRunMigrations_UpgradeFromEveryCheckpoint pins the upgrade-path
// invariant the v1.0 schema promise rests on: a database created at ANY
// historical schema version migrates cleanly to current. Each subtest
// builds the schema a deployment frozen at version N actually had
// (migrations 1..N), then runs the full RunMigrations and asserts every
// remaining version applies and lands in schema_migrations. A migration
// that works on a fresh DB but breaks against some historical
// intermediate schema fails here, named by checkpoint.
func TestRunMigrations_UpgradeFromEveryCheckpoint(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	want := len(migrations)
	for _, checkpoint := range migrations {
		n := checkpoint.version
		t.Run(fmt.Sprintf("from_%04d", n), func(t *testing.T) {
			db := openTestDB(t)
			applyMigrationsUpTo(t, db, n)
			if err := RunMigrations(db); err != nil {
				t.Fatalf("upgrade from checkpoint %d: %v", n, err)
			}
			applied, err := readAppliedMigrations(db)
			if err != nil {
				t.Fatalf("readAppliedMigrations: %v", err)
			}
			if len(applied) != want {
				t.Errorf("applied %d migrations, want %d", len(applied), want)
			}
		})
	}
}

// TestRunMigrations_DataSurvivesUpgradeFromV1 pins the other half of the
// upgrade promise: operator data written under the oldest schema rides
// the full migration chain intact. Seeds findings at schema version 1 —
// including a pre-v0.50.0 "Beaconing" row (exercising 0031's in-place
// type rename) and analyst triage state — migrates to current, then
// reads back through the modern Store and asserts identity, rename, and
// analyst work all survived.
func TestRunMigrations_DataSurvivesUpgradeFromV1(t *testing.T) {
	db := openTestDB(t)
	applyMigrationsUpTo(t, db, 1)

	// Every v1 column populated, as the v1-era writer always did — the
	// baseline schema has no NOT NULL constraints, but no real deployment
	// ever held NULLs because the era's INSERT supplied every column.
	if _, err := db.Exec(`INSERT INTO findings
		(id, type, severity, score, src_ip, dst_ip, dst_port, detail, timestamp, source_file, status, analyst, analyst_note, status_ts, ioc_match, is_new, sensor, intervals, ts_data, notes)
		VALUES
		(1, 'Beaconing', 'high', 82, '10.0.0.5', '203.0.113.7', '443', '60s interval', '2026-01-01 00:00:00', '/logs/s1/conn.log', 'acknowledged', 'phill@example.com', 'known C2 drill', '2026-01-02 00:00:00', 0, 0, 's1', '', '', ''),
		(2, 'DNS Tunneling', 'high', 75, '10.0.0.9', 'tunnel.example.net', '53', 'high entropy', '2026-01-01 00:00:00', '/logs/s1/dns.log', 'open', '', '', '', 0, 0, 's1', '', '', '')`); err != nil {
		t.Fatalf("seed v1 findings: %v", err)
	}

	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations from v1 schema: %v", err)
	}

	s := New(config.Default())
	s.InitDB(db)
	findings := s.GetFindings()
	if len(findings) != 2 {
		t.Fatalf("findings after upgrade = %d, want 2", len(findings))
	}
	byID := map[int]model.Finding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	beacon := byID[1]
	if beacon.Type != "Beacon" {
		t.Errorf("0031 rename: type = %q, want Beacon", beacon.Type)
	}
	if beacon.Status != model.StatusAcknowledged || beacon.Analyst != "phill@example.com" || beacon.AnalystNote != "known C2 drill" {
		t.Errorf("analyst triage state did not survive: %+v", beacon)
	}
	if beacon.Score != 82 || beacon.SrcIP != "10.0.0.5" || beacon.DstIP != "203.0.113.7" {
		t.Errorf("finding identity did not survive: %+v", beacon)
	}
	if byID[2].Type != "DNS Tunneling" {
		t.Errorf("non-renamed type altered: %q", byID[2].Type)
	}
}
