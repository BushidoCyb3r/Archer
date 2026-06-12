package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// tokenOrSession wraps a handler to accept either an X-Archer-Token
// header (validated against service_tokens) or a browser session cookie.
// Used for /api/sensors/health so Prometheus/Nagios can scrape without
// a browser session. If the header is present and invalid the request
// is rejected with 401 immediately; the session path is not attempted.
func (s *Server) tokenOrSession(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok := r.Header.Get("X-Archer-Token"); tok != "" {
			if !s.store.ValidateServiceToken(tok) {
				// Throttle bogus-token floods on this unauthenticated
				// path the same way login/enroll/checkin are throttled —
				// the per-IP bucket is charged only on a failed token so
				// legitimate monitoring scrapers with a valid token are
				// never limited.
				if allowed, _ := s.rateLimit.allow(sourceIP(r)); !allowed {
					jsonError(w, "rate limit exceeded — try again shortly", http.StatusTooManyRequests)
					return
				}
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
			return
		}
		s.requireAuth(http.HandlerFunc(h)).ServeHTTP(w, r)
	})
}

// handleServiceTokens handles GET and POST on /api/service-tokens.
// Admin only (enforced by route middleware).
//
//	GET  — returns the list of tokens (label + metadata, no hashes).
//	POST — creates a new token; returns id, label, and the raw token
//	       (shown exactly once; not stored or recoverable).
func (s *Server) handleServiceTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.store.ListServiceTokens())

	case http.MethodPost:
		var req struct {
			Label string `json:"label"`
		}
		if err := decodeJSONBody(w, r, &req, 1<<10); err != nil {
			return
		}
		req.Label = strings.TrimSpace(req.Label)
		if req.Label == "" {
			jsonError(w, "label is required", http.StatusBadRequest)
			return
		}
		actor := userFromCtx(r)
		id, token, err := s.store.CreateServiceToken(req.Label, actor.Email)
		if err != nil {
			jsonError(w, "failed to create token", http.StatusInternalServerError)
			return
		}
		s.recordAudit(r, "service_token_create", auditEvent{
			TargetType: "service_token",
			TargetID:   strconv.FormatInt(id, 10),
			TargetName: req.Label,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    id,
			"label": req.Label,
			"token": token,
		})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleServiceTokenItem handles DELETE /api/service-tokens/{id}.
// Admin only (enforced by route middleware).
func (s *Server) handleServiceTokenItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/service-tokens/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "invalid token id", http.StatusBadRequest)
		return
	}
	tok, ok := s.store.GetServiceToken(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.store.RevokeServiceToken(id)
	s.recordAudit(r, "service_token_revoke", auditEvent{
		TargetType: "service_token",
		TargetID:   strconv.FormatInt(id, 10),
		TargetName: tok.Label,
	})
	jsonOK(w)
}
