package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestHandleLogout_AuditsWithoutRequestContextUser is the S-3 regression.
// /logout is a bare route with no requireAuth, so the request context never
// carries a user. The handler used to read userFromCtx (always the zero User
// here), so its `u.ID != 0` audit branch never fired and logout events were
// silently absent from the trail. The handler must resolve the logging-out
// user from the session cookie so the audit row is written — exercised here
// WITHOUT withUser, exactly as the real bare route is hit.
func TestHandleLogout_AuditsWithoutRequestContextUser(t *testing.T) {
	s := newAuditTestServer(t)
	user, err := s.users.CreateUser("bye@example.test", "By", "E", "correct-horse", model.RoleAnalyst, model.StatusActive)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := s.users.CreateSession(user.ID)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	// Deliberately NOT withUser — the bare /logout route has no user in ctx.
	w := httptest.NewRecorder()
	s.handleLogout(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("logout status=%d, want 303", w.Code)
	}
	if _, ok := s.users.GetSession(token); ok {
		t.Error("session still resolves after logout")
	}

	var found bool
	for _, e := range s.store.ListAuditLog(0, 50) {
		if e.Action == "logout" {
			if e.ActorID != int64(user.ID) {
				t.Errorf("logout audit ActorID=%d, want %d", e.ActorID, user.ID)
			}
			if e.ActorEmail != user.Email {
				t.Errorf("logout audit ActorEmail=%q, want %q", e.ActorEmail, user.Email)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("no logout audit row written — logout events are absent from the trail")
	}
}
