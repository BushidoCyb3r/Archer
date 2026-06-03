package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestRequireAuth_CrossOriginCSRF asserts the defense-in-depth CSRF layer in
// requireAuth: an authenticated unsafe-method request whose Origin/Referer is
// cross-origin is rejected with 403, while same-origin and header-absent
// requests pass and safe methods are never gated. This sits behind the
// SameSite=Strict session cookie as a second barrier.
func TestRequireAuth_CrossOriginCSRF(t *testing.T) {
	s := newAuditTestServer(t)
	user, err := s.users.CreateUser("c@example.test", "C", "ser", "secret-password", model.RoleAnalyst, model.StatusActive)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := s.users.CreateSession(user.ID)

	var hit bool
	handler := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))

	// httptest.NewRequest defaults r.Host to "example.com".
	cases := []struct {
		name     string
		method   string
		origin   string
		referer  string
		wantCode int
		wantHit  bool
	}{
		{"same-origin POST", http.MethodPost, "https://example.com", "", http.StatusOK, true},
		{"cross-origin POST via Origin", http.MethodPost, "https://evil.test", "", http.StatusForbidden, false},
		{"cross-origin POST via Referer", http.MethodPost, "", "https://evil.test/x", http.StatusForbidden, false},
		{"same-origin POST via Referer", http.MethodPost, "", "https://example.com/app", http.StatusOK, true},
		{"header-absent POST allowed", http.MethodPost, "", "", http.StatusOK, true},
		{"cross-origin DELETE blocked", http.MethodDelete, "https://evil.test", "", http.StatusForbidden, false},
		{"cross-origin GET not gated", http.MethodGet, "https://evil.test", "", http.StatusOK, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit = false
			req := httptest.NewRequest(c.method, "/api/findings", nil)
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			if c.referer != "" {
				req.Header.Set("Referer", c.referer)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != c.wantCode {
				t.Errorf("status=%d, want %d; body=%s", w.Code, c.wantCode, w.Body.String())
			}
			if hit != c.wantHit {
				t.Errorf("handler reached=%v, want %v", hit, c.wantHit)
			}
		})
	}
}
