package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestHandleLogin_FormBodyCapped is the S-4 regression. handleLogin reads
// fields via r.FormValue, which parses an unbounded request body into memory
// unless the body is wrapped — every other decode in the codebase is capped,
// but FormValue bypassed that. With http.MaxBytesReader in place, a body
// exceeding the cap fails to parse, so the credentials come back empty and the
// login does not succeed (the protection is engaged); a normal-size valid
// login still works.
func TestHandleLogin_FormBodyCapped(t *testing.T) {
	s := newAuditTestServer(t)
	if _, err := s.users.CreateUser("u@example.test", "U", "ser", "correct-horse", model.RoleAnalyst, model.StatusActive); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.handleLogin(w, req)
		return w
	}
	hasSession := func(w *httptest.ResponseRecorder) bool {
		for _, c := range w.Result().Cookies() {
			if c.Name == sessionCookie && c.Value != "" {
				return true
			}
		}
		return false
	}

	creds := url.Values{"email": {"u@example.test"}, "password": {"correct-horse"}}.Encode()

	// Control: a normal-size valid login succeeds (session cookie set, 303).
	w := post(creds)
	if w.Code != http.StatusSeeOther || !hasSession(w) {
		t.Fatalf("valid login: status=%d hasSession=%v, want 303 + session cookie", w.Code, hasSession(w))
	}

	// Oversized: the same valid creds plus padding past the cap must not
	// authenticate — the capped reader makes ParseForm fail and the fields
	// come back empty.
	oversized := creds + "&pad=" + strings.Repeat("A", authFormMaxBytes+1024)
	w = post(oversized)
	if hasSession(w) {
		t.Errorf("oversized login body authenticated — form body cap not engaged")
	}
}
