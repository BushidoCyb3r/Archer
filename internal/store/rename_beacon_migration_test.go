package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestMigration0031_RenamesBeaconingInPlace asserts the end-to-end invariant
// of the Beaconing -> Beacon type rename: persisted state predating the rename
// is rewritten in place so nothing silently regresses on upgrade. Specifically
// a finding keeps its id and analyst note (so the next analysis fingerprint-
// matches it instead of duplicating it as a historical row), a pair-allowlist
// suppression rule scoped to the old type keeps matching the renamed finding,
// and beacon_history rows keep their persistence continuity (finding_type and
// the fingerprint PK prefix both move).
//
// The framework applies every migration at once, so to exercise 0031 against
// legacy rows we seed the old-typed data after the first run, then roll back
// only 0031's marker and migrate again — re-running the real migration SQL
// over the seeded data.
func TestMigration0031_RenamesBeaconingInPlace(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rename.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("initial migrate: %v", err)
	}

	// The fingerprint's field separator is the 0x1f byte — build it in SQL
	// with char(31) so the stored value carries the real control byte (a Go
	// %q-formatted string would inject a literal "\x1f" escape instead).
	sep := "char(31)"
	seed := []string{
		`INSERT INTO findings (id, type, analyst_note) VALUES
			(1, 'Beaconing', 'keep me'),
			(2, 'HTTP Beaconing', ''),
			(3, 'DNS Beaconing', ''),
			(4, 'DNS Tunneling', 'untouched')`,
		`INSERT INTO pair_allowlist (src, dst, port, finding_type, created_at) VALUES
			('10.0.0.1', '1.1.1.1', '443', 'Beaconing', 0)`,
		fmt.Sprintf(`INSERT INTO beacon_history
			(fingerprint, day_utc, finding_type, src_ip, dst_ip, max_score, severity, created_at) VALUES
			('Beaconing'||%[1]s||'10.0.0.1'||%[1]s||'1.1.1.1'||%[1]s||'443'||%[1]s||%[1]s||%[1]s,
			 '2026-06-01', 'Beaconing', '10.0.0.1', '1.1.1.1', 90, 'CRITICAL', 0)`, sep),
	}
	for _, q := range seed {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}

	// Roll back only 0031's marker, then re-migrate so the real migration SQL
	// runs over the seeded legacy rows.
	if _, err := db.Exec(`DELETE FROM schema_migrations WHERE version = 31`); err != nil {
		t.Fatalf("rollback marker: %v", err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}

	// findings: types rewritten, id + note + unrelated type preserved.
	wantTypes := map[int]string{1: "Beacon", 2: "HTTP Beacon", 3: "DNS Beacon", 4: "DNS Tunneling"}
	for id, want := range wantTypes {
		var got, note string
		if err := db.QueryRow(`SELECT type, analyst_note FROM findings WHERE id = ?`, id).Scan(&got, &note); err != nil {
			t.Fatalf("read finding %d: %v", id, err)
		}
		if got != want {
			t.Errorf("finding %d type = %q; want %q", id, got, want)
		}
		if id == 1 && note != "keep me" {
			t.Errorf("finding 1 analyst_note = %q; want preserved 'keep me'", note)
		}
	}

	// pair_allowlist scope rewritten, and the loaded store still suppresses the
	// renamed beacon on that pair — the suppression-continuity invariant.
	s := New(config.Default())
	s.InitDB(db)
	if !s.IsPairAllowed("10.0.0.1", "1.1.1.1", "443", "Beacon", "") {
		t.Error("pair-allowlist rule no longer matches the renamed Beacon finding after migration")
	}

	// beacon_history: finding_type and the fingerprint PK prefix both move.
	var fpType, fp string
	if err := db.QueryRow(`SELECT finding_type, fingerprint FROM beacon_history`).Scan(&fpType, &fp); err != nil {
		t.Fatalf("read beacon_history: %v", err)
	}
	if fpType != "Beacon" {
		t.Errorf("beacon_history finding_type = %q; want 'Beacon'", fpType)
	}
	usep := string(rune(31))
	if !strings.HasPrefix(fp, "Beacon"+usep) || strings.HasPrefix(fp, "Beaconing") {
		t.Errorf("beacon_history fingerprint = %q; want 'Beacon<0x1f>...' prefix", fp)
	}
}
