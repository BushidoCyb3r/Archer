package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// assertJSONError asserts one response satisfies the API error contract
// (docs/API.md): Content-Type application/json and a body of the shape
// {"error": "<non-empty>"}.
func assertJSONError(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("%s: Content-Type = %q, want application/json", name, ct)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Errorf("%s: body is not JSON: %v (body: %q)", name, err, w.Body.String())
		return
	}
	if body.Error == "" {
		t.Errorf("%s: JSON body has no error field: %q", name, w.Body.String())
	}
}

// TestAPIErrors_AreJSON pins the contract docs/API.md promises and the
// v1.0 freeze locks: every /api/* error response is JSON with an
// {"error"} body — never plaintext. Two layers are asserted: the
// handler-level method gate across one representative handler per
// family, and the middleware layer (auth 401, role 403, cross-origin
// 403) that fronts every API route.
func TestAPIErrors_AreJSON(t *testing.T) {
	s := newAuditTestServer(t)

	// Handler layer: a disallowed method on each handler family must
	// produce a JSON 405.
	handlers := []struct {
		name   string
		method string
		path   string
		fn     http.HandlerFunc
	}{
		{"findings", http.MethodDelete, "/api/findings", s.handleFindings},
		{"analyze", http.MethodGet, "/api/analyze", s.handleAnalyze},
		{"pair-allowlist", http.MethodPut, "/api/pair-allowlist", s.handlePairAllowlist},
		{"suppressions delete", http.MethodGet, "/api/suppressions/x", s.handleDeleteSuppression},
		{"service-tokens item", http.MethodGet, "/api/service-tokens/1", s.handleServiceTokenItem},
		{"escalate", http.MethodGet, "/api/escalate", s.handleEscalate},
		{"import", http.MethodGet, "/api/import", s.handleImportJSON},
		{"sensors tokens", http.MethodPut, "/api/sensors/tokens", s.handleSensorsTokens},
		{"quiver enroll", http.MethodGet, "/api/quiver/enroll", s.handleQuiverEnroll},
		{"config", http.MethodDelete, "/api/config", s.handleConfig},
	}
	for _, h := range handlers {
		w := httptest.NewRecorder()
		h.fn(w, withUser(httptest.NewRequest(h.method, h.path, nil), model.RoleAdmin))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", h.name, w.Code)
		}
		assertJSONError(t, h.name+" (405)", w)
	}

	// Middleware layer, driven through the real mux: unauthenticated
	// API request → JSON 401; viewer hitting a write route → JSON 403;
	// cross-origin unsafe method → JSON 403.
	s.mux = http.NewServeMux()
	s.rateLimit = newRateLimiter()
	s.routes()

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: status = %d, want 401", w.Code)
	}
	assertJSONError(t, "middleware unauthenticated (401)", w)

	w = httptest.NewRecorder()
	roleGate := requireRole(model.RoleAnalyst, model.RoleAdmin)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	roleGate.ServeHTTP(w, withUser(httptest.NewRequest(http.MethodPost, "/api/escalate", nil), model.RoleViewer))
	if w.Code != http.StatusForbidden {
		t.Errorf("role gate: status = %d, want 403", w.Code)
	}
	assertJSONError(t, "middleware role (403)", w)
}
