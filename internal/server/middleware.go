package server

import (
	"context"
	"net/http"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

type ctxKey int

const ctxUser ctxKey = 0

// requireAuth is middleware that validates the session cookie.
// Unauthenticated requests are redirected to /login.
// API requests (path starts with /api/ or /events) get a 401 instead.
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
		ctx := context.WithValue(r.Context(), ctxUser, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
