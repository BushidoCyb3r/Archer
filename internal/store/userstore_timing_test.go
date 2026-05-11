package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	_ "modernc.org/sqlite"
)

// TestAuthenticate_TimingPad covers NEW-46: the unknown-email
// failure path must run a bcrypt comparison so its wall-clock
// latency is roughly equal to the wrong-password path. Pre-fix
// the unknown-email path returned in ~1ms while wrong-password
// took ~200ms — an attacker measuring response time could
// enumerate registered emails by latency alone.
//
// The test doesn't assert exact equality (system load adds noise);
// it asserts the unknown-email path takes at LEAST a meaningful
// fraction of the wrong-password path's time, which is enough to
// catch a regression that removes the timing pad entirely. A
// pre-fix run would show the unknown path running 50-200× faster
// than the known path.
func TestAuthenticate_TimingPad(t *testing.T) {
	us := newAuthTestStore(t)
	if _, err := us.CreateUser("real@example.com", "Real", "User", "correct-horse-battery-staple", model.RoleViewer, model.StatusActive); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Warm up bcrypt — the first invocation tends to be slower as
	// the package initializes internal state. Without warmup the
	// two measurements below have unfair starting conditions.
	us.EnumerationTimingPad("warmup")

	// Time the unknown-email failure path.
	start := time.Now()
	if _, ok := us.Authenticate("nobody@example.test", "anything"); ok {
		t.Fatal("Authenticate returned ok for unknown email")
	}
	unknownLat := time.Since(start)

	// Time the wrong-password failure path.
	start = time.Now()
	if _, ok := us.Authenticate("real@example.com", "wrong-password"); ok {
		t.Fatal("Authenticate returned ok for wrong password")
	}
	wrongPassLat := time.Since(start)

	// Pre-fix unknownLat << wrongPassLat. Post-fix they should be
	// roughly equal (both run a bcrypt). Assert that the unknown
	// path took at least 50% of the wrong-password path's time —
	// catches the "timing pad removed" regression with margin for
	// CI noise.
	if float64(unknownLat) < 0.5*float64(wrongPassLat) {
		t.Errorf("unknown-email latency %v is much faster than wrong-password latency %v — timing-pad regression (NEW-46)",
			unknownLat, wrongPassLat)
	}
}

func newAuthTestStore(t *testing.T) *UserStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "users.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return &UserStore{db: db, sessions: make(map[string]userSession)}
}
