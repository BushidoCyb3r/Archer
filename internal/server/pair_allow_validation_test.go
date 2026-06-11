package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestPairAllowlist_ValidatesIPOrCIDR pins the create-side boundary: each
// side of a rule must parse as an IP or a CIDR — anything else is a 400,
// so the store's index rebuild never sees a malformed rule from the API
// path. Valid IPs, valid CIDRs (v4 and v6), and mixed sides are accepted.
func TestPairAllowlist_ValidatesIPOrCIDR(t *testing.T) {
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
	}
	for _, body := range accepted {
		if code := post(body); code != http.StatusOK {
			t.Errorf("valid rule rejected (%d): %s", code, body)
		}
	}

	rejected := []string{
		`{"src":"corp-lan","dst":"1.1.1.1","port":"53"}`,    // hostname, not IP
		`{"src":"10.0.0.0/99","dst":"1.1.1.1","port":"53"}`, // impossible mask
		`{"src":"10.0.0.1","dst":"evil.example","port":"53"}`,
		`{"src":"10.0.0.0/","dst":"1.1.1.1","port":"53"}`,
	}
	for _, body := range rejected {
		if code := post(body); code != http.StatusBadRequest {
			t.Errorf("invalid rule accepted (%d): %s", code, body)
		}
	}
}
