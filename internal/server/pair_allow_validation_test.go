package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestPairAllowlist_ValidatesSides pins the create-side boundary: each
// side of a rule must parse as an IP, a CIDR, a dotted domain, or a
// *.domain wildcard — anything else is a 400, so the store's index
// rebuild never sees a malformed rule from the API path. Domain sides
// are normalized to lowercase on the way in so exact rules match the
// detectors' lowercased output.
func TestPairAllowlist_ValidatesSides(t *testing.T) {
	s := newAuditTestServer(t)

	post := func(body string) int {
		t.Helper()
		req := withUser(httptest.NewRequest(http.MethodPost, "/api/pair-allowlist", strings.NewReader(body)), model.RoleAnalyst)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.handlePairAllowlist(w, req)
		return w.Code
	}

	accepted := []string{
		`{"src":"10.0.0.1","dst":"1.1.1.1","port":"443"}`,
		`{"src":"10.0.0.0/24","dst":"10.0.0.53","port":"53"}`,
		`{"src":"10.0.0.0/24","dst":"192.0.2.0/24","port":"53"}`,
		`{"src":"2001:db8::/32","dst":"2001:db8:1::53","port":"53"}`,
		`{"src":"192.168.20.55","dst":"skype.com","port":"53"}`,
		`{"src":"192.168.20.55","dst":"*.skype.com","port":"53"}`,
		`{"src":"*.corp.internal","dst":"203.0.113.9","port":"22"}`,
		`{"src":"10.0.0.0/24","dst":"*.updates.example.net","port":"80"}`,
		`{"src":"10.0.0.1","dst":"_dmarc.example.com","port":"53"}`, // underscore labels exist in real DNS
	}
	for _, body := range accepted {
		if code := post(body); code != http.StatusOK {
			t.Errorf("valid rule rejected (%d): %s", code, body)
		}
	}

	rejected := []string{
		`{"src":"corp-lan","dst":"1.1.1.1","port":"53"}`,    // bare word, no dot
		`{"src":"10.0.0.0/99","dst":"1.1.1.1","port":"53"}`, // impossible mask
		`{"src":"10.0.0.0/","dst":"1.1.1.1","port":"53"}`,
		`{"src":"10.0.0.1","dst":"*.","port":"53"}`,          // wildcard of nothing
		`{"src":"10.0.0.1","dst":"*.com","port":"53"}`,       // over-broad: suffix must be a dotted domain
		`{"src":"10.0.0.1","dst":"*skype.com","port":"53"}`,  // glob, not a *.domain wildcard
		`{"src":"10.0.0.1","dst":"skype..com","port":"53"}`,  // empty label
		`{"src":"10.0.0.1","dst":"-skype.com","port":"53"}`,  // label edge hyphen
		`{"src":"10.0.0.1","dst":"skype.com:53","port":""}`,  // port belongs in its own field
		`{"src":"10.0.0.1","dst":"sky pe.com","port":"53"}`,  // whitespace inside
		`{"src":"10.0.0.1","dst":"skype.com/x","port":"53"}`, // slash forces the CIDR parse
	}
	for _, body := range rejected {
		if code := post(body); code != http.StatusBadRequest {
			t.Errorf("invalid rule accepted (%d): %s", code, body)
		}
	}

	// Mixed-case domains are normalized to lowercase before storage.
	if code := post(`{"src":"192.168.20.56","dst":"*.Mixed-Case.Example.COM","port":"443"}`); code != http.StatusOK {
		t.Fatalf("mixed-case wildcard rejected (%d)", code)
	}
	for _, rule := range s.store.ListPairAllowlist() {
		if rule.Src == "192.168.20.56" {
			if rule.Dst != "*.mixed-case.example.com" {
				t.Errorf("domain not lowercased on create: %q", rule.Dst)
			}
			return
		}
	}
	t.Error("mixed-case rule not found in list")
}
