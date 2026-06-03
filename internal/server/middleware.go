package server

import (
	"context"
	"net/http"
	"net/url"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

type ctxKey int

const (
	ctxUser     ctxKey = 0
	ctxBoundary ctxKey = 1
	ctxToken    ctxKey = 2
)

// requireAuth is middleware that validates the session cookie.
// Unauthenticated requests are redirected to /login.
// API requests (path starts with /api/ or /events) get a 401 instead.
//
// The user's account status is re-checked on every request. Pre-fix
// requireAuth trusted whatever status was in the database row at the
// time of session creation; an admin demoting an analyst from active
// → pending (or marking an account compromised) had no effect on
// that user's existing 24-hour session. Audit 2026-05-10 NEW-8.
// Now the session resolves to a User row whose Status is checked
// every request: a non-active row returns 401 just as if the
// session had been deleted, and the ApproveUser / UpdateUserRole
// / DeleteUser code paths additionally call
// DeleteSessionsForUser so the in-memory session map doesn't hold
// orphans that would 401 every request until 24-hour expiry.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			s.redirectOrUnauthorized(w, r)
			return
		}
		user, ok := s.users.GetSession(c.Value)
		if !ok {
			s.redirectOrUnauthorized(w, r)
			return
		}
		if user.Status != model.StatusActive {
			// Stale session for a deactivated/pending account.
			// Drop the session token so the cookie stops resolving
			// even after the row's status flips back, and force the
			// user back through the login flow.
			s.users.DeleteSession(c.Value)
			s.redirectOrUnauthorized(w, r)
			return
		}
		if isUnsafeMethod(r.Method) && crossOriginRequest(r) {
			http.Error(w, `{"error":"cross-origin request blocked"}`, http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, user)
		ctx = context.WithValue(ctx, ctxBoundary, s.users.SessionNewBoundary(c.Value))
		ctx = context.WithValue(ctx, ctxToken, c.Value)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isUnsafeMethod reports whether the method can change state, and so must
// carry a same-origin Origin/Referer when authenticated by session cookie.
func isUnsafeMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// crossOriginRequest reports whether the request presents an Origin (or,
// failing that, Referer) whose host does not match the host the request
// arrived on. This is a defense-in-depth CSRF layer behind the
// SameSite=Strict session cookie: SameSite already blocks cross-site cookie
// attachment in current browsers, and this rejects a forged request a second
// way if that attribute is ever absent or unhonored. A request with neither
// header is allowed — a same-origin fetch always sends Origin, so rejecting
// on absence would break legitimate non-browser session clients without
// covering anything SameSite does not already block.
func crossOriginRequest(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err != nil || u.Host != r.Host
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err != nil || u.Host != r.Host
	}
	return false
}

func (s *Server) redirectOrUnauthorized(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if len(p) >= 5 && p[:5] == "/api/" || p == "/events" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// requireRole returns middleware that allows only users whose role is in the given set.
// Must be composed inside requireAuth (user must already be in context).
func requireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowed[userFromCtx(r).Role] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// userFromCtx extracts the authenticated user from a request context.
func userFromCtx(r *http.Request) model.User {
	u, _ := r.Context().Value(ctxUser).(model.User)
	return u
}

// newBoundaryFromCtx returns the session's frozen "new since you last looked"
// cutoff (epoch seconds). Zero when no session set it — which makes the
// delta/unseen queries treat everything as new, the safe default.
func newBoundaryFromCtx(r *http.Request) int64 {
	b, _ := r.Context().Value(ctxBoundary).(int64)
	return b
}

// sessionTokenFromCtx returns the requesting session's cookie token, used to
// read/update per-session state (e.g. the new-findings modal high-water).
func sessionTokenFromCtx(r *http.Request) string {
	t, _ := r.Context().Value(ctxToken).(string)
	return t
}
