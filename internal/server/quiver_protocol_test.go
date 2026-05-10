package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

func TestResolveQuiverProtocol_NilResolvesToV1ButRejected(t *testing.T) {
	// v0.12.0 dropped the v1 backwards-compat window: missing
	// protocol_version still resolves to 1 (so the error response
	// surfaces "sensor reported v1; server requires v2") but ok=false
	// because v1 is no longer supported. Pre-v0.12.0 this returned
	// ok=true. Audit 2026-05-10 NEW-16.
	got, ok := resolveQuiverProtocol(nil)
	if ok {
		t.Fatalf("v1 (nil) should no longer be supported in v0.12.0+; got ok=true")
	}
	if got != 1 {
		t.Fatalf("expected resolved=1 for nil input, got %d", got)
	}
}

func TestResolveQuiverProtocol_SupportedVersions(t *testing.T) {
	for v := range supportedQuiverProtocols {
		v := v
		got, ok := resolveQuiverProtocol(&v)
		if !ok {
			t.Errorf("supported version %d resolved to ok=false", v)
		}
		if got != v {
			t.Errorf("supported version %d resolved to %d", v, got)
		}
	}
}

func TestResolveQuiverProtocol_UnsupportedRejected(t *testing.T) {
	for _, v := range []int{0, 1, 99, -1} {
		v := v
		if supportedQuiverProtocols[v] {
			continue // skip if a future bump promotes one of these to supported
		}
		got, ok := resolveQuiverProtocol(&v)
		if ok {
			t.Errorf("unsupported version %d resolved to ok=true", v)
		}
		if got != v {
			t.Errorf("unsupported version %d should round-trip in resolved field, got %d", v, got)
		}
	}
}

func TestSupportedQuiverProtocolList_SortedAndComplete(t *testing.T) {
	got := supportedQuiverProtocolList()
	if len(got) != len(supportedQuiverProtocols) {
		t.Fatalf("supported list length mismatch: got %d, set has %d", len(got), len(supportedQuiverProtocols))
	}
	// Verify sorted and matches the set
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("supported list not sorted: %v", got)
		}
	}
	for _, v := range got {
		if !supportedQuiverProtocols[v] {
			t.Errorf("supported list contained %d which isn't in the set", v)
		}
	}
}

func TestQuiverProtocolErrorJSON_HasCanonicalFields(t *testing.T) {
	body := quiverProtocolErrorJSON(99)
	for _, key := range []string{"error", "sensor_version", "server_version", "supported_versions"} {
		if _, ok := body[key]; !ok {
			t.Errorf("error body missing key %q: %v", key, body)
		}
	}
	if body["sensor_version"] != 99 {
		t.Errorf("sensor_version should echo the rejected version; got %v", body["sensor_version"])
	}
	if body["server_version"] != QuiverProtocolVersion {
		t.Errorf("server_version should be QuiverProtocolVersion=%d; got %v", QuiverProtocolVersion, body["server_version"])
	}
	if !reflect.DeepEqual(body["supported_versions"], supportedQuiverProtocolList()) {
		t.Errorf("supported_versions mismatch: got %v", body["supported_versions"])
	}
}

// newQuiverTestServer builds a minimal Server suitable for protocol-rejection
// testing. Protocol validation runs before any store or broker work, so the
// dependencies just need to be non-nil enough that handler dispatch doesn't
// crash before the rejection path.
func newQuiverTestServer(t *testing.T) *Server {
	t.Helper()
	st := store.New(config.Default())
	return &Server{store: st, broker: NewBroker()}
}

func TestHandleQuiverEnroll_RejectsUnsupportedProtocolVersion(t *testing.T) {
	s := newQuiverTestServer(t)

	body, _ := json.Marshal(map[string]any{
		"token":            "anything",
		"name":             "test-sensor",
		"host":             "test.example",
		"pubkey":           "ssh-ed25519 AAAA test",
		"protocol_version": 99,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/quiver/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleQuiverEnroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported protocol_version; got %d (body: %s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v (body: %s)", err, w.Body.String())
	}
	if _, ok := resp["error"]; !ok {
		t.Errorf("error key missing from rejection body: %v", resp)
	}
	if resp["sensor_version"] != float64(99) {
		t.Errorf("sensor_version should echo 99; got %v", resp["sensor_version"])
	}
}

func TestHandleQuiverEnroll_RejectsMissingProtocolVersion(t *testing.T) {
	// v0.12.0+ dropped the v1 backwards-compat window for enroll. A
	// sensor still on the v1 install path (no protocol_version field
	// in the body) is now rejected with the same protocol-error JSON
	// shape any other unsupported version produces. Audit 2026-05-10
	// NEW-16.
	s := newQuiverTestServer(t)

	body, _ := json.Marshal(map[string]any{
		"token":  "bogus-but-present",
		"name":   "test-sensor",
		"host":   "test.example",
		"pubkey": "ssh-ed25519 AAAA test",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/quiver/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleQuiverEnroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing protocol_version should be rejected as v1 (unsupported); got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp["sensor_version"] != float64(1) {
		t.Errorf("sensor_version should resolve to 1 for missing field; got %v", resp["sensor_version"])
	}
}

func TestHandleQuiverCheckin_RejectsUnsupportedProtocolVersion(t *testing.T) {
	s := newQuiverTestServer(t)

	body, _ := json.Marshal(map[string]any{
		"name":             "test-sensor",
		"protocol_version": 99,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/quiver/checkin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleQuiverCheckin(w, req)

	// Checkin uses HTTP 200 + status discriminator so curl -fsSL doesn't
	// swallow the body. Verify both the status code and the status field.
	if w.Code != http.StatusOK {
		t.Fatalf("checkin protocol mismatch should be 200 (status discriminator); got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v (body: %s)", err, w.Body.String())
	}
	if resp["status"] != "protocol_unsupported" {
		t.Errorf("expected status=protocol_unsupported; got %v", resp["status"])
	}
	if resp["sensor_version"] != float64(99) {
		t.Errorf("sensor_version should echo 99; got %v", resp["sensor_version"])
	}
	for _, key := range []string{"server_version", "supported_versions"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("checkin protocol-rejection missing key %q: %v", key, resp)
		}
	}
}

func TestHandleQuiverCheckin_RejectsMissingProtocolVersion(t *testing.T) {
	// v0.12.0+ a missing protocol_version checkin gets the
	// "protocol_unsupported" status discriminator (HTTP 200 — see
	// quiverProtocolUnsupportedCheckin for why) rather than being
	// silently accepted as v1. Audit 2026-05-10 NEW-16.
	s := newQuiverTestServer(t)

	body, _ := json.Marshal(map[string]any{"name": "unknown-sensor"})
	req := httptest.NewRequest(http.MethodPost, "/api/quiver/checkin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleQuiverCheckin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("checkin protocol mismatch should be 200 (status discriminator); got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp["status"] != "protocol_unsupported" {
		t.Fatalf("missing protocol_version should be rejected; got status=%v", resp["status"])
	}
	if resp["sensor_version"] != float64(1) {
		t.Errorf("sensor_version should resolve to 1 for missing field; got %v", resp["sensor_version"])
	}
}
