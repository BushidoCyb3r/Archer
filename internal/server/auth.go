package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

const sessionCookie = "archer_session"

// handleLogin serves GET /login and processes POST /login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderAuth(w, "login.html", map[string]any{"Error": ""})
	case http.MethodPost:
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")

		if !validEmail(email) {
			s.renderAuth(w, "login.html", map[string]any{"Error": "Enter a valid email address."})
			return
		}

		user, ok := s.users.Authenticate(email, password)
		if !ok {
			s.renderAuth(w, "login.html", map[string]any{"Error": "Invalid email or password."})
			return
		}
		if user.Status == model.StatusPending {
			s.renderAuth(w, "login.html", map[string]any{"Error": "Your account is awaiting admin approval."})
			return
		}

		token := s.users.CreateSession(user.ID)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
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
		firstName := strings.TrimSpace(r.FormValue("first_name"))
		lastName := strings.TrimSpace(r.FormValue("last_name"))
		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
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
			s.renderAuth(w, "register.html", map[string]any{"Pending": true})
			return
		}

		token := s.users.CreateSession(user.ID)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLogout clears the session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request", http.StatusBadRequest)
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.Status != "" {
			if req.Status != model.StatusActive {
				jsonError(w, "invalid status", http.StatusBadRequest)
				return
			}
			if !s.users.ApproveUser(id) {
				http.NotFound(w, r)
				return
			}
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
		if !s.users.UpdateUserRole(id, req.Role) {
			http.NotFound(w, r)
			return
		}
		jsonOK(w)

	case http.MethodDelete:
		if id == me.ID {
			jsonError(w, "cannot delete your own account", http.StatusBadRequest)
			return
		}
		if !s.users.DeleteUser(id) {
			http.NotFound(w, r)
			return
		}
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
