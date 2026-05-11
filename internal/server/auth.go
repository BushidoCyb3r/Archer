package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

const sessionCookie = "archer_session"

// handleLogin serves GET /login and processes POST /login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderAuth(w, "login.html", map[string]any{"Error": ""})
	case http.MethodPost:
		// Normalize the email exactly the way registration does (trim
		// + lowercase) before authenticating. The SQL lookup uses
		// COLLATE NOCASE so login works either way today, but the
		// normalization mismatch is a footgun: anyone removing the
		// COLLATE clause thinking emails are normalized at write
		// time would silently break login. Audit 2026-05-10.
		srcIP := sourceIP(r)
		if allowed, shouldAudit := s.rateLimit.allow(srcIP); !allowed {
			// Audit only the FIRST refusal per bucket-trip (NEW-47);
			// subsequent excess on the same already-tripped bucket
			// returns 429 silently so an attacker cannot scale the
			// audit-log volume by sustaining their flood. The flag
			// clears on the next admitted request, so a re-trip
			// after legitimate traffic resumes audits again.
			if shouldAudit {
				s.recordAuditLogin(r, "request_rate_limited", 0, "", map[string]any{
					"path":   "/login",
					"reason": "unauth_rate_limit",
				})
			}
			http.Error(w, "rate limit exceeded — try again shortly", http.StatusTooManyRequests)
			return
		}
		email := store.NormalizeEmail(r.FormValue("email"))
		password := r.FormValue("password")

		if !validEmail(email) {
			s.recordAuditLogin(r, "login_failure", 0, email, map[string]any{"reason": "invalid_email"})
			s.renderAuth(w, "login.html", map[string]any{"Error": "Enter a valid email address."})
			return
		}

		user, ok := s.users.Authenticate(email, password)
		if !ok {
			s.recordAuditLogin(r, "login_failure", 0, email, map[string]any{"reason": "bad_credentials"})
			s.renderAuth(w, "login.html", map[string]any{"Error": "Invalid email or password."})
			return
		}
		if user.Status == model.StatusPending {
			s.recordAuditLogin(r, "login_failure", user.ID, user.Email, map[string]any{"reason": "pending_approval"})
			s.renderAuth(w, "login.html", map[string]any{"Error": "Your account is awaiting admin approval."})
			return
		}

		token := s.users.CreateSession(user.ID)
		s.recordAuditLogin(r, "login_success", user.ID, user.Email, nil)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRegister serves GET /register and processes POST /register.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderAuth(w, "register.html", map[string]any{"Error": "", "FirstName": "", "LastName": "", "Email": ""})
	case http.MethodPost:
		srcIP := sourceIP(r)
		if allowed, shouldAudit := s.rateLimit.allow(srcIP); !allowed {
			if shouldAudit {
				s.recordAuditLogin(r, "request_rate_limited", 0, "", map[string]any{
					"path":   "/register",
					"reason": "unauth_rate_limit",
				})
			}
			http.Error(w, "rate limit exceeded — try again shortly", http.StatusTooManyRequests)
			return
		}
		firstName := strings.TrimSpace(r.FormValue("first_name"))
		lastName := strings.TrimSpace(r.FormValue("last_name"))
		email := store.NormalizeEmail(r.FormValue("email"))
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		// Helper to re-render with the form values preserved
		fail := func(msg string) {
			s.renderAuth(w, "register.html", map[string]any{
				"Error": msg, "FirstName": firstName, "LastName": lastName, "Email": email,
			})
		}

		if firstName == "" {
			fail("First name is required.")
			return
		}
		if lastName == "" {
			fail("Last name is required.")
			return
		}
		if !validEmail(email) {
			fail("Enter a valid email address.")
			return
		}
		if len(password) < 8 {
			fail("Password must be at least 8 characters.")
			return
		}
		if password != confirm {
			fail("Passwords do not match.")
			return
		}
		// Don't reveal whether an email is already registered — return the
		// same "pending approval" response a real new registration produces.
		// The existing account is left untouched. A throwaway bcrypt also
		// equalizes timing so the duplicate-email path isn't distinguishable
		// by latency.
		if s.users.EmailExists(email) {
			s.users.EnumerationTimingPad(password)
			s.renderAuth(w, "register.html", map[string]any{"Pending": true})
			return
		}

		isFirstUser := s.users.UserCount() == 0
		role := model.RoleViewer
		status := model.StatusPending
		if isFirstUser {
			// First registration bootstraps the admin and is auto-approved,
			// otherwise nobody could ever log in on a fresh install.
			role = model.RoleAdmin
			status = model.StatusActive
		}

		user, err := s.users.CreateUser(email, firstName, lastName, password, role, status)
		if err != nil {
			fail("Registration failed. Please try again.")
			return
		}

		if !isFirstUser {
			// Self-service registration of a viewer in pending status.
			// Pre-v0.14.3 this was the only admin-relevant path that
			// produced zero audit-log rows; an attacker (or curious
			// user) could land in pending state without surfacing in
			// the audit trail until an admin approved them. Audit row
			// uses actor_id=0 (the user isn't authenticated to act on
			// their own behalf) with the registered email captured
			// for the trail. v0.14.3 NEW-38.
			s.recordAuditLogin(r, "user_register", 0, email, map[string]any{
				"path":   "self_service",
				"status": string(model.StatusPending),
				"role":   model.RoleViewer,
			})
			s.renderAuth(w, "register.html", map[string]any{"Pending": true})
			return
		}

		// First-user bootstrap is the single highest-privilege account-
		// creation event in this deployment's lifetime. Distinct action
		// name so it's filterable in the audit UI and operationally
		// distinct from later self-service registrations. v0.14.3
		// NEW-38.
		s.recordAuditLogin(r, "admin_bootstrap", user.ID, user.Email, map[string]any{
			"path":   "first_user",
			"status": string(model.StatusActive),
			"role":   model.RoleAdmin,
		})
		token := s.users.CreateSession(user.ID)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLogout clears the session cookie. v0.14.3 NEW-44 adds an
// audit row so session timelines are reconstructible from the log
// without inferring end-times from the absence of subsequent
// activity.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Snapshot the user before the cookie is cleared so the audit
	// row captures who logged out.
	u := userFromCtx(r)
	c, err := r.Cookie(sessionCookie)
	if err == nil {
		s.users.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	if u.ID != 0 {
		s.recordAuditLogin(r, "logout", u.ID, u.Email, nil)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleMe returns the current user as JSON.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":         user.ID,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"display":    user.DisplayName(),
		"role":       user.Role,
	})
}

// handleUsersCollection handles GET /api/users and POST /api/users.
// GET  — admin: all users; others: only themselves.
// POST — admin only: create a user.
func (s *Server) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	me := userFromCtx(r)

	switch r.Method {
	case http.MethodGet:
		if me.Role == model.RoleAdmin {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s.users.ListUsers())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]model.User{{
			ID: me.ID, Email: me.Email,
			FirstName: me.FirstName, LastName: me.LastName, Role: me.Role,
		}})

	case http.MethodPost:
		if me.Role != model.RoleAdmin {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Email     string `json:"email"`
			Password  string `json:"password"`
			Role      string `json:"role"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		}
		if err := decodeJSONBody(w, r, &req, 4<<10); err != nil {
			return
		}
		req.Email = store.NormalizeEmail(req.Email)
		req.FirstName = strings.TrimSpace(req.FirstName)
		req.LastName = strings.TrimSpace(req.LastName)
		if req.FirstName == "" || req.LastName == "" {
			jsonError(w, "first and last name are required", http.StatusBadRequest)
			return
		}
		if !validEmail(req.Email) {
			jsonError(w, "invalid email address", http.StatusBadRequest)
			return
		}
		if len(req.Password) < 8 {
			jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}
		if !model.IsValidRole(req.Role) {
			req.Role = model.RoleAnalyst
		}
		if s.users.EmailExists(req.Email) {
			jsonError(w, "email already registered", http.StatusConflict)
			return
		}
		user, err := s.users.CreateUser(req.Email, req.FirstName, req.LastName, req.Password, req.Role, model.StatusActive)
		if err != nil {
			jsonError(w, "failed to create user", http.StatusInternalServerError)
			return
		}
		user.PasswordHash = ""
		s.recordAudit(r, "user_create", auditEvent{
			TargetType: "user",
			TargetID:   strconv.Itoa(user.ID),
			TargetName: user.Email,
			AfterValue: map[string]any{"email": user.Email, "role": user.Role},
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUserItem handles PATCH /api/users/{id} and DELETE /api/users/{id}.
// Admin only (enforced by route middleware in server.go).
func (s *Server) handleUserItem(w http.ResponseWriter, r *http.Request) {
	me := userFromCtx(r)

	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var req struct {
			Role   string `json:"role,omitempty"`
			Status string `json:"status,omitempty"`
		}
		if err := decodeJSONBody(w, r, &req, 1<<10); err != nil {
			return
		}
		if req.Status != "" {
			if req.Status != model.StatusActive {
				jsonError(w, "invalid status", http.StatusBadRequest)
				return
			}
			// Snapshot before the mutation so the audit log records the
			// transition rather than just the post-state.
			before, _ := s.users.GetUserByID(id)
			if !s.users.ApproveUser(id) {
				http.NotFound(w, r)
				return
			}
			// Pending → active doesn't strictly need session
			// invalidation (a pending user has no live sessions
			// — they couldn't get past requireAuth). Defensive
			// drop anyway in case status was flipped via direct
			// DB write before this transition.
			s.users.DeleteSessionsForUser(id)
			s.recordAudit(r, "user_status_change", auditEvent{
				TargetType:  "user",
				TargetID:    strconv.Itoa(id),
				TargetName:  before.Email,
				BeforeValue: map[string]any{"status": before.Status},
				AfterValue:  map[string]any{"status": model.StatusActive},
			})
			jsonOK(w)
			return
		}
		if req.Role == "" {
			jsonError(w, "no changes specified", http.StatusBadRequest)
			return
		}
		if !model.IsValidRole(req.Role) {
			jsonError(w, "invalid role", http.StatusBadRequest)
			return
		}
		// Prevent admin from demoting themselves
		if id == me.ID && req.Role != model.RoleAdmin {
			jsonError(w, "cannot change your own role", http.StatusBadRequest)
			return
		}
		before, _ := s.users.GetUserByID(id)
		if !s.users.UpdateUserRole(id, req.Role) {
			http.NotFound(w, r)
			return
		}
		// Force re-login so the new role is reflected in the
		// session-derived role cache. Pre-fix the existing
		// session continued to act under the old role for up to
		// 24 hours after a demote. Audit 2026-05-10 NEW-8.
		s.users.DeleteSessionsForUser(id)
		s.recordAudit(r, "user_role_change", auditEvent{
			TargetType:  "user",
			TargetID:    strconv.Itoa(id),
			TargetName:  before.Email,
			BeforeValue: map[string]any{"role": before.Role},
			AfterValue:  map[string]any{"role": req.Role},
		})
		jsonOK(w)

	case http.MethodDelete:
		if id == me.ID {
			jsonError(w, "cannot delete your own account", http.StatusBadRequest)
			return
		}
		before, _ := s.users.GetUserByID(id)
		if !s.users.DeleteUser(id) {
			http.NotFound(w, r)
			return
		}
		// Drop any in-memory sessions so the cookie stops
		// resolving immediately rather than 401-ing every
		// request until the 24-hour TTL elapses.
		s.users.DeleteSessionsForUser(id)
		s.recordAudit(r, "user_delete", auditEvent{
			TargetType:  "user",
			TargetID:    strconv.Itoa(id),
			TargetName:  before.Email,
			BeforeValue: map[string]any{"email": before.Email, "role": before.Role},
		})
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderAuth(w http.ResponseWriter, tmplName string, data map[string]any) {
	tmplPath := filepath.Join(s.webDir, "templates", tmplName)
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

func validEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at < 1 {
		return false
	}
	local := s[:at]
	domain := s[at+1:]
	if local == "" || domain == "" {
		return false
	}
	dot := strings.LastIndexByte(domain, '.')
	if dot < 1 || dot == len(domain)-1 {
		return false
	}
	return !strings.ContainsAny(s, " \t\n\r")
}
