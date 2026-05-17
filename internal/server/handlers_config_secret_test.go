package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// secretSentinels is the set of credential values seeded into the test
// config. The invariant: none of these may reach a non-admin over
// /api/config, and none may appear in the index page source for any
// role.
var secretSentinels = map[string]string{
	"otx_api_key":        "OTX-SENTINEL-aaaa",
	"abuseipdb_api_key":  "ABUSE-SENTINEL-bbbb",
	"virustotal_api_key": "VT-SENTINEL-cccc",
	"crowdsec_api_key":   "CS-SENTINEL-dddd",
	"greynoise_api_key":  "GN-SENTINEL-eeee",
	"censys_api_id":      "CENSYS-ID-SENTINEL-ffff",
	"censys_api_secret":  "CENSYS-SECRET-SENTINEL-gggg",
}

func seedSecretConfig(t *testing.T, s *Server) {
	t.Helper()
	cfg := config.Default()
	cfg.OTXAPIKey = secretSentinels["otx_api_key"]
	cfg.AbuseIPDBAPIKey = secretSentinels["abuseipdb_api_key"]
	cfg.VirusTotalAPIKey = secretSentinels["virustotal_api_key"]
	cfg.CrowdSecAPIKey = secretSentinels["crowdsec_api_key"]
	cfg.GreyNoiseAPIKey = secretSentinels["greynoise_api_key"]
	cfg.CensysAPIID = secretSentinels["censys_api_id"]
	cfg.CensysAPISecret = secretSentinels["censys_api_secret"]
	cfg.BeaconMinConnections = 7 // a non-secret marker that must pass through
	s.store.SetConfig(cfg)
}

// TestHandleConfig_RedactsSecretsForNonAdmin codifies the v0.25.1
// privilege-boundary fix. Invariant, not failure case: every
// credential field is blanked for every non-admin role with a
// "<field>_configured" boolean preserved, non-secret fields pass
// through untouched, and an admin still gets the verbatim values so
// the admin-only Settings dialog can prefill + round-trip. A
// regression in the role gate, the key list, or the redaction shape
// fails here.
func TestHandleConfig_RedactsSecretsForNonAdmin(t *testing.T) {
	s := newFeedsTestServer(t)
	seedSecretConfig(t, s)

	for _, role := range []string{model.RoleViewer, model.RoleAnalyst} {
		req := withUser(httptest.NewRequest(http.MethodGet, "/api/config", nil), role)
		w := httptest.NewRecorder()
		s.handleConfig(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s GET /api/config = %d; body %s", role, w.Code, w.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: decode: %v", role, err)
		}
		for key := range secretSentinels {
			if got, _ := m[key].(string); got != "" {
				t.Errorf("%s: %s = %q; want blanked", role, key, got)
			}
			if c, ok := m[key+"_configured"].(bool); !ok || !c {
				t.Errorf("%s: %s_configured = %v; want true", role, key, m[key+"_configured"])
			}
		}
		// Raw body must not contain any sentinel substring, even if a
		// future field re-introduced one outside the known keys.
		body := w.Body.String()
		for _, sv := range secretSentinels {
			if strings.Contains(body, sv) {
				t.Errorf("%s: response body leaked secret %q", role, sv)
			}
		}
		if bmc, ok := m["beacon_min_connections"].(float64); !ok || int(bmc) != 7 {
			t.Errorf("%s: non-secret beacon_min_connections = %v; want 7 (passthrough broken)", role, m["beacon_min_connections"])
		}
	}

	// Admin still gets the real values — the Settings dialog depends
	// on it for prefill + preserve-on-save.
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/config", nil), model.RoleAdmin)
	w := httptest.NewRecorder()
	s.handleConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin GET /api/config = %d", w.Code)
	}
	var cfg config.Config
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("admin: decode: %v", err)
	}
	if cfg.VirusTotalAPIKey != secretSentinels["virustotal_api_key"] ||
		cfg.CensysAPISecret != secretSentinels["censys_api_secret"] {
		t.Errorf("admin must receive verbatim secrets; got vt=%q censys=%q",
			cfg.VirusTotalAPIKey, cfg.CensysAPISecret)
	}
}

// TestHandleIndex_DoesNotEmbedConfigSecrets renders the real index
// template and asserts the bootstrap no longer carries the config at
// all (the page-source half of the leak), while the still-needed
// SCORE_EXPLANATIONS bootstrap survives so the page isn't broken.
func TestHandleIndex_DoesNotEmbedConfigSecrets(t *testing.T) {
	s := newFeedsTestServer(t)
	s.webDir = "../../web"
	seedSecretConfig(t, s)

	for _, role := range []string{model.RoleViewer, model.RoleAnalyst, model.RoleAdmin} {
		req := withUser(httptest.NewRequest(http.MethodGet, "/", nil), role)
		w := httptest.NewRecorder()
		s.handleIndex(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s GET / = %d; body %s", role, w.Code, w.Body.String())
		}
		body := w.Body.String()
		for key, sv := range secretSentinels {
			if strings.Contains(body, sv) {
				t.Fatalf("%s: index page leaked %s in source", role, key)
			}
		}
		if strings.Contains(body, "INIT_CONFIG") {
			t.Errorf("%s: index still defines window.INIT_CONFIG", role)
		}
		if !strings.Contains(body, "SCORE_EXPLANATIONS") {
			t.Errorf("%s: SCORE_EXPLANATIONS bootstrap missing — page bootstrap broken", role)
		}
	}
}
