package server

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
	_ "modernc.org/sqlite"
)

// newAuditTestServer is a thin wrapper around the same plumbing the
// feeds tests use — a real on-disk SQLite store with migrations
// applied. Audit-driven regression tests live in this file.
func newAuditTestServer(t testing.TB) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := store.RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	st := store.New(config.Default())
	st.InitDB(db)
	return &Server{
		store:  st,
		broker: NewBroker(),
		users:  store.NewUserStore(t.TempDir()),
	}
}

// TestSuppressions_RejectsInvalidDays asserts the bounds and finite-ness
// checks added in audit NEW-7 fire 400 before AddSuppression is reached.
// Pre-fix {"days": 1e15} silently overflowed int64 inside
// time.Duration construction, so a hostile/malformed analyst payload
// could land an effectively-permanent suppression that would be
// invisible in the audit trail. NaN/Inf had the same shape via
// undefined float→int conversion.
func TestSuppressions_RejectsInvalidDays(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"NaN", `{"target":"1.2.3.4","days":"NaN"}`, http.StatusBadRequest},
		{"PositiveInfinity", `{"target":"1.2.3.4","days":1e400}`, http.StatusBadRequest},
		{"NegativeInfinity", `{"target":"1.2.3.4","days":-1e400}`, http.StatusBadRequest},
		{"ExceedsCap", `{"target":"1.2.3.4","days":366}`, http.StatusBadRequest},
		{"AbsurdLargeFinite", `{"target":"1.2.3.4","days":1e15}`, http.StatusBadRequest},
		{"NegativeFinite", `{"target":"1.2.3.4","days":-7}`, http.StatusBadRequest},
		{"Zero", `{"target":"1.2.3.4","days":0}`, http.StatusBadRequest},
		{"WithinCap", `{"target":"1.2.3.4","days":7}`, http.StatusOK},
		{"AtCap", `{"target":"1.2.3.4","days":365}`, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newAuditTestServer(t)
			req := withUser(
				httptest.NewRequest(http.MethodPost, "/api/suppressions", bytes.NewBufferString(c.body)),
				model.RoleAnalyst,
			)
			w := httptest.NewRecorder()
			s.handleSuppressions(w, req)
			if w.Code != c.want {
				t.Errorf("status=%d, want %d; body: %s", w.Code, c.want, w.Body.String())
			}
		})
	}
}

// TestRequireAuth_RejectsNonActiveStatus asserts a session whose owning
// user has been flipped to non-active is rejected on the next request,
// even before the in-memory session table is pruned. Pre-fix the only
// gate was session-token validity (24-hour TTL), so an admin demoting
// or deactivating a user left them with up to 24 hours of continued
// access. Audit 2026-05-10 NEW-8.
func TestRequireAuth_RejectsNonActiveStatus(t *testing.T) {
	s := newAuditTestServer(t)
	user, err := s.users.CreateUser("u@example.test", "U", "ser", "secret-password", model.RoleAnalyst, model.StatusActive)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := s.users.CreateSession(user.ID)

	hit := false
	handler := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))

	// Active user: passes through.
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !hit || w.Code != http.StatusOK {
		t.Fatalf("active user blocked: status=%d hit=%v", w.Code, hit)
	}

	// Flip status to pending out from under the live session — what
	// happens when an admin marks a user pending in the user-mgmt UI
	// without explicitly invalidating sessions.
	if _, err := s.users.DB().Exec(
		`UPDATE users SET status = ? WHERE id = ?`, model.StatusPending, user.ID,
	); err != nil {
		t.Fatalf("flip status: %v", err)
	}

	hit = false
	req2 := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if hit {
		t.Error("requireAuth let a non-active user through")
	}
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401; body=%s", w2.Code, w2.Body.String())
	}

	// Defensive: the session token should also be dropped so a status
	// flip-back doesn't silently re-validate the same cookie.
	if _, ok := s.users.GetSession(token); ok {
		t.Error("session not deleted after non-active rejection")
	}
}

// TestDeleteSessionsForUser_DropsAllSessions asserts the helper used by
// the admin role-change / approve / delete paths actually clears every
// live token for the affected user. Without this, the re-login forced
// by an admin demote would only reach users whose 24-hour session had
// expired naturally. Audit 2026-05-10 NEW-8.
func TestDeleteSessionsForUser_DropsAllSessions(t *testing.T) {
	s := newAuditTestServer(t)
	user, err := s.users.CreateUser("v@example.test", "V", "ser", "secret-password", model.RoleAnalyst, model.StatusActive)
	if err != nil {
		t.Fatal(err)
	}
	t1 := s.users.CreateSession(user.ID)
	t2 := s.users.CreateSession(user.ID)
	other, _ := s.users.CreateUser("w@example.test", "W", "ser", "secret-password", model.RoleAnalyst, model.StatusActive)
	t3 := s.users.CreateSession(other.ID)

	s.users.DeleteSessionsForUser(user.ID)

	if _, ok := s.users.GetSession(t1); ok {
		t.Error("t1 not deleted")
	}
	if _, ok := s.users.GetSession(t2); ok {
		t.Error("t2 not deleted")
	}
	if _, ok := s.users.GetSession(t3); !ok {
		t.Error("unrelated user's session t3 was deleted (over-broad)")
	}
}

// TestSuppressions_DeleteUnescapesPath covers the audit-LOW PathUnescape
// fix — a percent-encoded suppression key should resolve to its
// unescaped form before lookup, otherwise the delete silently no-ops.
func TestSuppressions_DeleteUnescapesPath(t *testing.T) {
	s := newAuditTestServer(t)
	const target = "192.0.2.1/24"
	s.store.AddSuppression(target, time.Now().Add(24*time.Hour), "test")

	escaped := strings.ReplaceAll(target, "/", "%2F")
	req := withUser(
		httptest.NewRequest(http.MethodDelete, "/api/suppressions/"+escaped, nil),
		model.RoleAnalyst,
	)
	w := httptest.NewRecorder()
	s.handleDeleteSuppression(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", w.Code, w.Body.String())
	}
	if _, ok := s.store.GetSuppressions()[target]; ok {
		t.Error("suppression still present after delete; PathUnescape regression")
	}
}
