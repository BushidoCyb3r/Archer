package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestHandleLogin_Contract is the CS-2 regression. The login handler is a
// system-breaking surface (auth/sessions) that had no direct test. It pins
// three properties the project's security posture depends on:
//  1. a valid login 303-redirects and sets a session cookie with
//     Secure / HttpOnly / SameSite=Strict;
//  2. an unknown user and a wrong password return the byte-identical response
//     (no account-enumeration signal);
//  3. the per-IP rate limiter engages (429) once its bucket is drained.
func TestHandleLogin_Contract(t *testing.T) {
	s := newAuditTestServer(t)
	s.webDir = "../../web" // renderAuth needs templates/login.html for the error paths
	if _, err := s.users.CreateUser("real@example.test", "R", "eal", "correct-horse-battery", model.RoleAnalyst, model.StatusActive); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	post := func(form url.Values, remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if remoteAddr != "" {
			req.RemoteAddr = remoteAddr
		}
		w := httptest.NewRecorder()
		s.handleLogin(w, req)
		return w
	}

	// 1. Valid login → 303 + hardened session cookie.
	w := post(url.Values{"email": {"real@example.test"}, "password": {"correct-horse-battery"}}, "203.0.113.10:5000")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("valid login status=%d, want 303", w.Code)
	}
	var sc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			sc = c
		}
	}
	if sc == nil || sc.Value == "" {
		t.Fatal("valid login did not set a session cookie")
	}
	if !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie flags: Secure=%v HttpOnly=%v SameSite=%v — want all hardened", sc.Secure, sc.HttpOnly, sc.SameSite)
	}

	// 2. Unknown user vs wrong password → byte-identical response (no enumeration).
	read := func(w *httptest.ResponseRecorder) (int, string) {
		res := w.Result()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	uCode, uBody := read(post(url.Values{"email": {"ghost@example.test"}, "password": {"whatever-xyz"}}, "203.0.113.20:5000"))
	pCode, pBody := read(post(url.Values{"email": {"real@example.test"}, "password": {"wrong-password"}}, "203.0.113.21:5000"))
	if uCode != pCode || uBody != pBody {
		t.Errorf("unknown-user and wrong-password responses differ — account-enumeration signal\n  unknown: %d %q\n  wrongpw: %d %q", uCode, uBody, pCode, pBody)
	}

	// 3. Rate limiter engages past the bucket (nil until now, so steps 1-2 were unthrottled).
	s.rateLimit = newRateLimiter()
	const ip = "198.51.100.5:6000"
	got429 := false
	for i := 0; i < rateLimitBucketCapacity+3; i++ {
		if post(url.Values{"email": {"real@example.test"}, "password": {"nope"}}, ip).Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Errorf("rate limiter never returned 429 after %d attempts from one IP", rateLimitBucketCapacity+3)
	}
}
