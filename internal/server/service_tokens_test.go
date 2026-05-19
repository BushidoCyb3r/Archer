package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// TestServiceToken_CreateListRevoke codifies the full lifecycle:
// create returns the raw token exactly once, list shows metadata (no
// token), revoke removes the row and invalidates the token.
func TestServiceToken_CreateListRevoke(t *testing.T) {
	s := newAuditTestServer(t)

	// Create
	body, _ := json.Marshal(map[string]string{"label": "test-scraper"})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/service-tokens", bytes.NewReader(body)), "admin")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleServiceTokens(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		ID    int64  `json:"id"`
		Label string `json:"label"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Token == "" {
		t.Fatal("create response missing token")
	}
	if created.Label != "test-scraper" {
		t.Errorf("label = %q, want test-scraper", created.Label)
	}
	if len(created.Token) < 40 {
		t.Errorf("token looks too short: %q", created.Token)
	}

	// Validate: token should authenticate
	if !s.store.ValidateServiceToken(created.Token) {
		t.Error("ValidateServiceToken returned false for a freshly created token")
	}

	// List
	req2 := withUser(httptest.NewRequest(http.MethodGet, "/api/service-tokens", nil), "admin")
	w2 := httptest.NewRecorder()
	s.handleServiceTokens(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("list: status=%d", w2.Code)
	}
	var list []struct {
		ID    int64  `json:"id"`
		Label string `json:"label"`
		Token string `json:"token"` // must not be present
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list: want 1 token, got %d", len(list))
	}
	if list[0].Token != "" {
		t.Error("list response must not include raw token")
	}
	if list[0].Label != "test-scraper" {
		t.Errorf("list[0].label = %q, want test-scraper", list[0].Label)
	}

	// Revoke
	idStr := strconv.FormatInt(created.ID, 10)
	req3 := withUser(httptest.NewRequest(http.MethodDelete, "/api/service-tokens/"+idStr, nil), "admin")
	req3.SetPathValue("id", idStr)
	w3 := httptest.NewRecorder()
	s.handleServiceTokenItem(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("revoke: status=%d body=%s", w3.Code, w3.Body.String())
	}

	// Token must no longer validate
	if s.store.ValidateServiceToken(created.Token) {
		t.Error("ValidateServiceToken returned true after revoke")
	}

	// List must be empty
	req4 := withUser(httptest.NewRequest(http.MethodGet, "/api/service-tokens", nil), "admin")
	w4 := httptest.NewRecorder()
	s.handleServiceTokens(w4, req4)
	var list2 []any
	_ = json.Unmarshal(w4.Body.Bytes(), &list2)
	if len(list2) != 0 {
		t.Errorf("list after revoke: want 0 tokens, got %d", len(list2))
	}
}

// TestServiceToken_TokenOrSessionMiddleware codifies the tokenOrSession
// invariant: a valid X-Archer-Token header bypasses the session cookie
// and reaches the handler; an invalid token returns 401; absent header
// falls through to session auth (401 when no session either).
func TestServiceToken_TokenOrSessionMiddleware(t *testing.T) {
	s := newAuditTestServer(t)

	_, rawToken, err := s.store.CreateServiceToken("prom", "admin@test")
	if err != nil {
		t.Fatalf("CreateServiceToken: %v", err)
	}

	reached := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := s.tokenOrSession(h)

	// Valid token → reaches handler.
	reached = false
	req := httptest.NewRequest(http.MethodGet, "/api/sensors/health", nil)
	req.Header.Set("X-Archer-Token", rawToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("valid token: status=%d, want 200", w.Code)
	}
	if !reached {
		t.Error("valid token: handler was not reached")
	}

	// Invalid token → 401, handler not reached.
	reached = false
	req2 := httptest.NewRequest(http.MethodGet, "/api/sensors/health", nil)
	req2.Header.Set("X-Archer-Token", "archer_notavalidtoken")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("invalid token: status=%d, want 401", w2.Code)
	}
	if reached {
		t.Error("invalid token: handler must not be reached")
	}

	// No token, no session → 401 (session path rejects).
	reached = false
	req3 := httptest.NewRequest(http.MethodGet, "/api/sensors/health", nil)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("no auth: status=%d, want 401", w3.Code)
	}
	if reached {
		t.Error("no auth: handler must not be reached")
	}
}

// TestServiceToken_EmptyLabelRejected verifies that creating a token
// with an empty label returns 400 and no token is stored.
func TestServiceToken_EmptyLabelRejected(t *testing.T) {
	s := newAuditTestServer(t)
	body, _ := json.Marshal(map[string]string{"label": "  "})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/service-tokens", bytes.NewReader(body)), "admin")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleServiceTokens(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
	if got := s.store.ListServiceTokens(); len(got) != 0 {
		t.Errorf("store has %d tokens, want 0", len(got))
	}
}
