package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestHandleIOCFingerprints pins the JA3/JA4 IOC list API contract: GET exposes
// the always-active built-ins separately from operator entries; PUT persists
// only operator additions, silently dropping built-in lines (so deleting one in
// the textarea is a no-op — it re-appears) and comment lines; and the
// "Mark malicious" POST appends one fingerprint, treating a built-in as a
// no-op success. These guard the operator half of Malicious JA3/JA4 detection.
func TestHandleIOCFingerprints(t *testing.T) {
	s := newFeedsTestServer(t)

	var c2JA3 string
	for fp := range analysis.KnownBadJA3 {
		c2JA3 = fp
		break
	}
	if c2JA3 == "" {
		t.Fatal("expected at least one known-bad JA3")
	}

	// GET: built-ins present, operator list empty.
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/ioc?kind=fp", nil), model.RoleAnalyst)
	w := httptest.NewRecorder()
	s.handleIOCFingerprints(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET kind=fp: status = %d, want 200", w.Code)
	}
	var got struct {
		Builtin  []map[string]string `json:"builtin"`
		Operator []string            `json:"operator"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if len(got.Builtin) == 0 {
		t.Errorf("GET builtin is empty, want the KnownBadJA3/JA4 tables")
	}
	if len(got.Operator) != 0 {
		t.Errorf("GET operator = %v, want empty", got.Operator)
	}

	// PUT: a built-in line + a comment + a fresh operator fingerprint. Only the
	// operator fingerprint should persist.
	put := []string{
		c2JA3, // built-in — must be dropped, not double-stored
		"# my section header",
		"AABBCCDDAABBCCDDAABBCCDDAABBCCDD  # custom implant",
	}
	body, _ := json.Marshal(put)
	req = withUser(httptest.NewRequest(http.MethodPut, "/api/ioc?kind=fp", bytes.NewReader(body)), model.RoleAnalyst)
	w = httptest.NewRecorder()
	s.handleIOCFingerprints(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT kind=fp: status = %d, want 200", w.Code)
	}
	if ops := s.store.GetIOCFingerprints(); len(ops) != 1 || ops[0] != "aabbccddaabbccddaabbccddaabbccdd" {
		t.Fatalf("operator list = %v, want [aabbccddaabbccddaabbccddaabbccdd]", ops)
	}

	// Mark malicious: a fresh JA4 appends.
	body, _ = json.Marshal(map[string]string{"fingerprint": "t13d9999h2_cccc_dddd"})
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/ioc-fingerprint", bytes.NewReader(body)), model.RoleAnalyst)
	w = httptest.NewRecorder()
	s.handleMarkFingerprintMalicious(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST mark-malicious: status = %d, want 200", w.Code)
	}
	if ops := s.store.GetIOCFingerprints(); len(ops) != 2 {
		t.Fatalf("after mark-malicious, operator list = %v, want 2 entries", ops)
	}

	// Mark malicious on a built-in is a no-op success (it's already malicious).
	body, _ = json.Marshal(map[string]string{"fingerprint": c2JA3})
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/ioc-fingerprint", bytes.NewReader(body)), model.RoleAnalyst)
	w = httptest.NewRecorder()
	s.handleMarkFingerprintMalicious(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST mark-malicious built-in: status = %d, want 200", w.Code)
	}
	if ops := s.store.GetIOCFingerprints(); len(ops) != 2 {
		t.Errorf("built-in mark-malicious changed list to %v, want unchanged (2)", ops)
	}

	// Viewers are read-only on both surfaces.
	body, _ = json.Marshal([]string{"t13d_x"})
	req = withUser(httptest.NewRequest(http.MethodPut, "/api/ioc?kind=fp", bytes.NewReader(body)), model.RoleViewer)
	w = httptest.NewRecorder()
	s.handleIOCFingerprints(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer PUT: status = %d, want 403", w.Code)
	}
}
