package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestRequireRole_DenialMatrix pins the access-control contract of the
// requireRole middleware across every (allowed-set, caller-role) pair.
// The three role-aware route wrappers in server.go (any/write/admin)
// are all thin calls to requireRole, so a regression here — an allow
// map built wrong, a role string typo, an inverted check — would open
// or close routes wholesale. The invariant: a caller passes iff their
// role is in the allowed set, and nothing else about the request matters.
func TestRequireRole_DenialMatrix(t *testing.T) {
	allRoles := []string{model.RoleAdmin, model.RoleAnalyst, model.RoleViewer}
	sets := []struct {
		name    string
		allowed []string
	}{
		{"admin-only", []string{model.RoleAdmin}},
		{"write (admin+analyst)", []string{model.RoleAdmin, model.RoleAnalyst}},
		{"any (all three)", []string{model.RoleAdmin, model.RoleAnalyst, model.RoleViewer}},
	}
	for _, set := range sets {
		allowSet := make(map[string]bool, len(set.allowed))
		for _, r := range set.allowed {
			allowSet[r] = true
		}
		mw := requireRole(set.allowed...)
		for _, role := range allRoles {
			role := role
			t.Run(set.name+"/"+role, func(t *testing.T) {
				hit := false
				handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hit = true
					w.WriteHeader(http.StatusOK)
				}))
				req := withUser(httptest.NewRequest(http.MethodGet, "/api/anything", nil), role)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				wantAllowed := allowSet[role]
				if wantAllowed {
					if !hit || w.Code != http.StatusOK {
						t.Errorf("role %q should pass %s; got code=%d hit=%v", role, set.name, w.Code, hit)
					}
				} else {
					if hit {
						t.Errorf("role %q reached handler through %s — privilege escalation", role, set.name)
					}
					if w.Code != http.StatusForbidden {
						t.Errorf("role %q denied by %s should be 403; got %d", role, set.name, w.Code)
					}
				}
			})
		}
	}
}

// TestHandleRegister_BootstrapThenSelfService pins the two-population
// contract of self-registration: the very first account is the admin
// bootstrap (admin + active + a live session cookie), and every account
// after it is an unprivileged viewer parked in pending until an admin
// approves. A regression that auto-approved the second user, or minted a
// session for it, would hand an unauthenticated stranger an active
// foothold. This is the highest-stakes role-assignment path in the app.
func TestHandleRegister_BootstrapThenSelfService(t *testing.T) {
	s := newAuditTestServer(t)
	s.webDir = "../../web"
	s.authTmpls = loadAuthTemplates(s.webDir)
	s.rateLimit = newRateLimiter()

	register := func(email string) *httptest.ResponseRecorder {
		form := url.Values{
			"first_name": {"Test"},
			"last_name":  {"User"},
			"email":      {email},
			"password":   {"correct-horse"},
			"confirm":    {"correct-horse"},
		}
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.handleRegister(w, req)
		return w
	}

	hasSessionCookie := func(w *httptest.ResponseRecorder) bool {
		for _, c := range w.Result().Cookies() {
			if c.Name == sessionCookie && c.Value != "" {
				return true
			}
		}
		return false
	}
	findUser := func(email string) (model.User, bool) {
		for _, u := range s.users.ListUsers() {
			if u.Email == email {
				return u, true
			}
		}
		return model.User{}, false
	}

	// First registration: admin bootstrap, auto-approved, logged in.
	w1 := register("first@example.test")
	if w1.Code != http.StatusSeeOther {
		t.Fatalf("first register: status=%d, want 303; body=%s", w1.Code, w1.Body.String())
	}
	if !hasSessionCookie(w1) {
		t.Error("first register did not set a session cookie — admin was not logged in")
	}
	admin, ok := findUser("first@example.test")
	if !ok {
		t.Fatal("first user was not created")
	}
	if admin.Role != model.RoleAdmin {
		t.Errorf("first user role=%q, want admin", admin.Role)
	}
	if admin.Status != model.StatusActive {
		t.Errorf("first user status=%q, want active", admin.Status)
	}

	// Second registration: unprivileged, pending, no session.
	w2 := register("second@example.test")
	if w2.Code != http.StatusOK {
		t.Fatalf("second register: status=%d, want 200 (pending render); body=%s", w2.Code, w2.Body.String())
	}
	if hasSessionCookie(w2) {
		t.Error("second register minted a session cookie — a self-service signup must not log itself in")
	}
	second, ok := findUser("second@example.test")
	if !ok {
		t.Fatal("second user was not created")
	}
	if second.Role != model.RoleViewer {
		t.Errorf("second user role=%q, want viewer", second.Role)
	}
	if second.Status != model.StatusPending {
		t.Errorf("second user status=%q, want pending", second.Status)
	}
}

// TestHandleRegister_ConcurrentBootstrapElectsOneAdmin is the AZ-N1 regression.
// UserCount()==0 and CreateUser are two separate DB calls; before registerMu
// serialized them, concurrent first registrations with distinct emails could
// both observe an empty user table and both be created as active admins — a
// network-adjacent party racing the operator during the open bootstrap window
// could plant a second admin. The invariant: however many registrations land
// concurrently on a fresh install, exactly one becomes an active admin and the
// rest are pending viewers. Run under -race to also catch the data race.
func TestHandleRegister_ConcurrentBootstrapElectsOneAdmin(t *testing.T) {
	s := newAuditTestServer(t)
	s.webDir = "../../web"
	s.authTmpls = loadAuthTemplates(s.webDir)
	s.rateLimit = newRateLimiter()

	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			form := url.Values{
				"first_name": {"Test"},
				"last_name":  {"User"},
				"email":      {fmt.Sprintf("user%d@example.test", i)},
				"password":   {"correct-horse"},
				"confirm":    {"correct-horse"},
			}
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// Distinct source IP per goroutine so the unauth rate limiter
			// doesn't drop any registration.
			req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i+1)
			s.handleRegister(httptest.NewRecorder(), req)
		}(i)
	}
	wg.Wait()

	users := s.users.ListUsers()
	admins, active := 0, 0
	for _, u := range users {
		if u.Role == model.RoleAdmin {
			admins++
		}
		if u.Status == model.StatusActive {
			active++
		}
	}
	if len(users) != n {
		t.Errorf("created %d users, want %d (every distinct-email registration should succeed)", len(users), n)
	}
	if admins != 1 {
		t.Errorf("got %d admins after %d concurrent registrations, want exactly 1 (bootstrap race elected multiple)", admins, n)
	}
	if active != 1 {
		t.Errorf("got %d active users, want exactly 1 (only the bootstrap admin is auto-approved)", active)
	}
}

// TestHandleUsersCollection_POSTRequiresAdmin asserts the in-handler
// authorization on user creation: only an admin may POST a new account.
// The route is admin-wrapped in server.go, but the handler re-checks
// rather than trusting the wrapper — this test pins that second barrier
// so a future route-table edit that loosened the wrapper can't silently
// open user creation to analysts.
func TestHandleUsersCollection_POSTRequiresAdmin(t *testing.T) {
	body := `{"email":"new@example.test","password":"correct-horse","role":"analyst","first_name":"New","last_name":"User"}`

	for _, role := range []string{model.RoleViewer, model.RoleAnalyst} {
		t.Run("denied/"+role, func(t *testing.T) {
			s := newAuditTestServer(t)
			req := withUser(httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBufferString(body)), role)
			w := httptest.NewRecorder()
			s.handleUsersCollection(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s POST /api/users: status=%d, want 403", role, w.Code)
			}
			if len(s.users.ListUsers()) != 0 {
				t.Errorf("%s created a user despite 403", role)
			}
		})
	}

	t.Run("admin allowed", func(t *testing.T) {
		s := newAuditTestServer(t)
		req := withUser(httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBufferString(body)), model.RoleAdmin)
		w := httptest.NewRecorder()
		s.handleUsersCollection(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("admin POST /api/users: status=%d, want 201; body=%s", w.Code, w.Body.String())
		}
		if len(s.users.ListUsers()) != 1 {
			t.Errorf("admin POST created %d users, want 1", len(s.users.ListUsers()))
		}
	})
}

// TestHandleUserItem_SelfMutationGuards pins the self-protection
// invariants on the admin user-management endpoint: an admin cannot
// demote, delete, or self-reset their own account through it. These
// guards are what stop an admin from accidentally locking every admin
// out of the deployment (demote-self) or removing the last account
// (delete-self). withUser sets the caller's ID to 1, so a path of
// /api/users/1 is the self target.
func TestHandleUserItem_SelfMutationGuards(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   string
	}{
		{"demote self", http.MethodPatch, `{"role":"analyst"}`},
		{"reset own password here", http.MethodPatch, `{"password":"another-password"}`},
		{"delete self", http.MethodDelete, ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newAuditTestServer(t)
			var bodyReader *strings.Reader
			if c.body != "" {
				bodyReader = strings.NewReader(c.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := withUser(httptest.NewRequest(c.method, "/api/users/1", bodyReader), model.RoleAdmin)
			w := httptest.NewRecorder()
			s.handleUserItem(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: status=%d, want 400 (self-mutation guard); body=%s", c.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleLogout_DeletesSessionAndClearsCookie pins the logout session
// contract: the server-side session is destroyed (the token stops
// resolving) and the clearing Set-Cookie carries the same security flags
// as the login cookie with an expiry in the past. A logout that cleared
// the browser cookie but left the server session live would leave a
// stealable token valid for its full 24-hour TTL.
func TestHandleLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	s := newAuditTestServer(t)
	user, err := s.users.CreateUser("u@example.test", "U", "ser", "correct-horse", model.RoleAnalyst, model.StatusActive)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := s.users.CreateSession(user.ID)

	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req = withUser(req, model.RoleAnalyst)
	w := httptest.NewRecorder()
	s.handleLogout(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("logout status=%d, want 303", w.Code)
	}
	if _, ok := s.users.GetSession(token); ok {
		t.Error("session still resolves after logout — server-side session was not destroyed")
	}
	var cleared *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("logout did not emit a clearing Set-Cookie for the session")
	}
	if cleared.Value != "" {
		t.Errorf("clearing cookie value=%q, want empty", cleared.Value)
	}
	// SetCookie with MaxAge:-1 emits "Max-Age=0", which readSetCookies
	// parses back to MaxAge==-1 ("delete this cookie"). Anything >= 0
	// would leave the cookie live.
	if cleared.MaxAge >= 0 {
		t.Errorf("clearing cookie MaxAge=%d, want < 0 (immediate expiry)", cleared.MaxAge)
	}
	if !cleared.HttpOnly || !cleared.Secure || cleared.SameSite != http.SameSiteStrictMode {
		t.Errorf("clearing cookie lost security flags: HttpOnly=%v Secure=%v SameSite=%v",
			cleared.HttpOnly, cleared.Secure, cleared.SameSite)
	}
}
