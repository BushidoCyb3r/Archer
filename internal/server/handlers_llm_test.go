package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// llm_status reflects the configured provider and reports enabled only when the
// settings actually build a provider — a half-configured provider reads as off
// rather than offering a button that 400s on click.
func TestLLMStatus_ReflectsConfig(t *testing.T) {
	s := newAuditTestServer(t)

	// Default: disabled.
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/llm/status", nil), model.RoleViewer)
	w := httptest.NewRecorder()
	s.handleLLMStatus(w, req)
	var st struct {
		Enabled  bool   `json:"enabled"`
		Provider string `json:"provider"`
		Local    bool   `json:"local"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if st.Enabled {
		t.Error("status should report disabled by default")
	}

	// Enabled but missing the required base URL for ollama → still reports off.
	cfg := config.Default()
	cfg.LLMEnabled = true
	cfg.LLMProvider = "ollama"
	cfg.LLMModel = "llama3.1"
	s.store.SetConfig(cfg)
	w = httptest.NewRecorder()
	s.handleLLMStatus(w, withUser(httptest.NewRequest(http.MethodGet, "/api/llm/status", nil), model.RoleViewer))
	json.Unmarshal(w.Body.Bytes(), &st)
	if st.Enabled {
		t.Error("a provider that fails to build must report enabled=false, not offer a broken button")
	}

	// Fully configured local provider → enabled + local.
	cfg.LLMBaseURL = "http://10.0.0.5:11434/v1"
	s.store.SetConfig(cfg)
	w = httptest.NewRecorder()
	s.handleLLMStatus(w, withUser(httptest.NewRequest(http.MethodGet, "/api/llm/status", nil), model.RoleViewer))
	json.Unmarshal(w.Body.Bytes(), &st)
	if !st.Enabled || !st.Local || st.Provider != "ollama" {
		t.Errorf("expected enabled+local ollama, got %+v", st)
	}
}

// The enrich endpoint must reject a viewer (cannot annotate) and reject when
// enrichment is disabled — neither path should ever reach a provider call.
func TestEnrichEndpoint_Gating(t *testing.T) {
	s := newAuditTestServer(t)

	// Viewer is forbidden regardless of config.
	w := httptest.NewRecorder()
	s.handleEnrich(w, withUser(httptest.NewRequest(http.MethodPost, "/api/findings/1/enrich", nil), model.RoleViewer))
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer enrich = %d, want 403", w.Code)
	}

	// Analyst with enrichment disabled → 400.
	w = httptest.NewRecorder()
	s.handleEnrich(w, withUser(httptest.NewRequest(http.MethodPost, "/api/findings/1/enrich", nil), model.RoleAnalyst))
	if w.Code != http.StatusBadRequest {
		t.Errorf("disabled enrich = %d, want 400", w.Code)
	}
}

// The config PUT boundary check rejects an enabled-but-unbuildable provider so
// the misconfiguration surfaces at save time, not on the first click.
func TestConfigPUT_RejectsBrokenLLM(t *testing.T) {
	s := newAuditTestServer(t)
	body := `{"llm_enabled":true,"llm_provider":"openai","off_hours_start":22,"off_hours_end":6,` +
		`"correlation_min_types":2,"spectral_min_observations":16,"spectral_fap_threshold":12,` +
		`"spectral_rescue_threshold":0.5,"dga_entropy_threshold":3.5,"dga_bigram_threshold":-4.5,` +
		`"beacon_min_connections":4,"http_beacon_min_requests":8,"dns_beacon_min_queries":20}`
	req := withUser(httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body)), model.RoleAdmin)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleConfig(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("enabling openai with no API key should 400, got %d; body=%s", w.Code, w.Body.String())
	}
}

// An out-of-range request timeout is rejected at save time — a hung provider
// must not be able to pin an enrichment goroutine for an unbounded stretch.
func TestConfigPUT_RejectsBadTimeout(t *testing.T) {
	s := newAuditTestServer(t)
	body := `{"llm_enabled":true,"llm_provider":"ollama","llm_model":"llama3.1",` +
		`"llm_base_url":"http://10.0.0.5:11434/v1","llm_timeout_sec":999,` +
		`"off_hours_start":22,"off_hours_end":6,"correlation_min_types":2,` +
		`"spectral_min_observations":16,"spectral_fap_threshold":12,"spectral_rescue_threshold":0.5,` +
		`"dga_entropy_threshold":3.5,"dga_bigram_threshold":-4.5,` +
		`"beacon_min_connections":4,"http_beacon_min_requests":8,"dns_beacon_min_queries":20}`
	req := withUser(httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body)), model.RoleAdmin)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleConfig(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("timeout 999 should 400, got %d; body=%s", w.Code, w.Body.String())
	}
}

// The in-flight guard stops a second concurrent enrichment for the same finding
// from spawning a duplicate briefing; a different finding is independent.
func TestEnrichInFlightGuard(t *testing.T) {
	s := newAuditTestServer(t)
	if !s.acquireEnrich(7) {
		t.Fatal("first acquire should succeed")
	}
	if s.acquireEnrich(7) {
		t.Fatal("second acquire while in flight must fail")
	}
	if !s.acquireEnrich(8) {
		t.Fatal("a different finding must acquire independently")
	}
	s.releaseEnrich(7)
	if !s.acquireEnrich(7) {
		t.Fatal("acquire should succeed again after release")
	}
}

// Dispatching an enrichment writes an egress audit row naming the provider and
// whether the evidence stayed on-network (local) or went off-box (cloud).
func TestEnrichEndpoint_AuditsEgress(t *testing.T) {
	s := newAuditTestServer(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	t.Cleanup(srv.Close)

	cfg := config.Default()
	cfg.LLMEnabled = true
	cfg.LLMProvider = "ollama"
	cfg.LLMModel = "llama3.1"
	cfg.LLMBaseURL = srv.URL + "/v1"
	s.store.SetConfig(cfg)
	s.store.SetFindings([]model.Finding{{
		Type: "Beacon", Severity: model.SevHigh, Score: 80, Status: model.StatusOpen,
		SrcIP: "10.0.0.9", DstIP: "203.0.113.5", DstPort: "443",
	}})
	id := s.store.GetFindings()[0].ID

	w := httptest.NewRecorder()
	path := "/api/findings/" + strconv.Itoa(id) + "/enrich"
	s.handleEnrich(w, withUser(httptest.NewRequest(http.MethodPost, path, nil), model.RoleAnalyst))
	if w.Code != http.StatusOK {
		t.Fatalf("enrich = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var details string
	for _, e := range s.store.ListAuditLog(0, 100) {
		if e.Action == "finding_ai_enrich" {
			details = e.Details
			break
		}
	}
	if details == "" {
		t.Fatal("no finding_ai_enrich audit row written")
	}
	if !strings.Contains(details, "ollama") || !strings.Contains(details, "local") {
		t.Errorf("audit details missing provider/egress posture: %q", details)
	}
}
