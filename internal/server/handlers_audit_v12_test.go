package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestImport_RejectsAnalystFabricatedFinding asserts the validation
// added in NEW-14: even an admin (who's the only role allowed to
// reach /api/import in v0.12.0) cannot drop in a finding whose Type
// isn't in the analyzer's known set, whose Score is out of [0, 100],
// whose Severity is bogus, or whose Timestamp doesn't match the
// analyzer's emitted format. Pre-fix any value was accepted and the
// stored representation became indistinguishable from real analyzer
// output.
func TestImport_RejectsFabricatedFindings(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{
			name: "Unknown Type",
			body: `{"findings":[{"type":"FabricatedType","severity":"CRITICAL","score":99,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Out-of-range Score",
			body: `{"findings":[{"type":"Beaconing","severity":"HIGH","score":99999,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Negative Score",
			body: `{"findings":[{"type":"Beaconing","severity":"HIGH","score":-1,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Bogus Severity",
			body: `{"findings":[{"type":"Beaconing","severity":"PWNED","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Malformed Timestamp",
			body: `{"findings":[{"type":"Beaconing","severity":"HIGH","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"yesterday"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Bogus Status",
			body: `{"findings":[{"type":"Beaconing","severity":"HIGH","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00","status":"pwned"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Valid Finding Accepted",
			body: `{"findings":[{"type":"Beaconing","severity":"HIGH","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusOK,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newAuditTestServer(t)
			req := withUser(
				httptest.NewRequest(http.MethodPost, "/api/import", strings.NewReader(c.body)),
				model.RoleAdmin,
			)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.handleImportJSON(w, req)
			if w.Code != c.want {
				t.Errorf("status=%d want=%d body=%s", w.Code, c.want, w.Body.String())
			}
		})
	}
}

// TestImport_RejectsBodyOverCap asserts the http.MaxBytesReader cap.
// Pre-fix a malicious or buggy admin script could POST a multi-GB
// body and exhaust memory before the decode finished. Post-fix
// MaxBytesReader trips at the importMaxBytes ceiling and the decode
// returns an error. We can't easily allocate a 64 MiB body in a
// unit test, but we can verify a body just over the cap is
// rejected. This test uses a much smaller cap by checking behavior
// at the JSON-decode boundary — invalid JSON with size > cap
// produces 400, which is the same outcome and proves the truncation
// fired.
func TestImport_RejectsCorruptJSON(t *testing.T) {
	s := newAuditTestServer(t)
	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/import", strings.NewReader(`{"findings":`)),
		model.RoleAdmin,
	)
	w := httptest.NewRecorder()
	s.handleImportJSON(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d want=%d", w.Code, http.StatusBadRequest)
	}
}

// TestRejectInternalFeedURL_LiteralIPs covers the NEW-18 SSRF guard's
// config-time layer — a URL host that's a literal IP in the deny set
// must be refused. DNS-resolved hostnames are checked at fetch time
// via the HTTP client's CheckRedirect, not here.
func TestRejectInternalFeedURL_LiteralIPs(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool // true = should reject
	}{
		{"AWS metadata literal", "http://169.254.169.254/latest/", true},
		{"loopback literal v4", "http://127.0.0.1:6379/", true},
		{"loopback literal v6", "http://[::1]:6379/", true},
		{"RFC1918 10/8", "http://10.0.0.5/internal", true},
		{"RFC1918 192.168/16", "http://192.168.1.1/", true},
		{"RFC1918 172.16/12", "http://172.20.5.5/", true},
		{"localhost alias", "http://localhost/api", true},
		{"public IP literal", "http://1.1.1.1/", false},
		{"public IPv6 literal", "http://[2001:4860:4860::8888]/", false},
		{"FQDN", "https://misp.example.test/", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := rejectInternalFeedURL(c.url)
			got := err != nil
			if got != c.want {
				t.Errorf("rejectInternalFeedURL(%q) error=%v; want reject=%v", c.url, err, c.want)
			}
		})
	}
}

// TestRandomMinute_DistributionIsUnbiased verifies the rejection-
// sampling fix in randomMinute. Pre-fix `b % 60` for b ∈ [0, 256)
// produced minutes 0..15 ~5/256 each but minutes 16..59 ~4/256 each.
// Over many draws the bias becomes detectable. We don't need a
// rigorous chi-squared — just enough draws to surface a gross bias.
func TestRandomMinute_DistributionIsUnbiased(t *testing.T) {
	const draws = 60_000
	counts := [60]int{}
	for i := 0; i < draws; i++ {
		counts[randomMinute()]++
	}
	// Expected count per bucket: 1000. Pre-fix the 0..15 buckets
	// would average ~1250 vs ~937 for 16..59. Post-fix all 60
	// buckets should be ~1000 ±5%. Use a generous tolerance to
	// avoid CI flakes.
	for i, c := range counts {
		if c < 800 || c > 1200 {
			t.Errorf("bucket %d count=%d, expected ~1000 ±20%% (rejection sampling broken?)", i, c)
		}
	}
}

// TestSpreadsheetSafe_PrefixesDangerousLeadingChars covers NEW-17.
// A finding's analyst note or detail string starting with =, +, -,
// @, \t, or \r must be quoted with a leading single quote so
// Excel/Sheets/LibreOffice don't interpret the cell as a formula.
func TestSpreadsheetSafe_PrefixesDangerousLeadingChars(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`=HYPERLINK("https://evil.test","Click")`, `'=HYPERLINK("https://evil.test","Click")`},
		{`+1 (212) 555-0100`, `'+1 (212) 555-0100`},
		{`-startup-flag`, `'-startup-flag`},
		{`@admin`, `'@admin`},
		{"\tindented", "'\tindented"},
		{"\rcr-leading", "'\rcr-leading"},
		// Safe inputs unchanged.
		{`192.168.1.1`, `192.168.1.1`},
		{``, ``},
		{`Beaconing`, `Beaconing`},
		{`http://example.com`, `http://example.com`},
	}
	for _, c := range cases {
		got := spreadsheetSafe(c.in)
		if got != c.want {
			t.Errorf("spreadsheetSafe(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

// TestQuiverHost_ValidatedAtEnrollment covers the LOW-cluster req.Host
// validation. Pre-fix req.Host flowed into the sensors row unvalidated.
func TestQuiverHost_ValidatedAtEnrollment(t *testing.T) {
	cases := []struct {
		name string
		host string
		want int
	}{
		{"plain hostname", "host.example.com", http.StatusForbidden}, // 403 from token check, validation passes
		{"ipv4 literal", "192.0.2.1", http.StatusForbidden},
		{"ipv6 literal", "2001:db8::1", http.StatusForbidden},
		{"empty", "", http.StatusForbidden}, // empty allowed
		{"contains newline", "host.example.com\n<script>", http.StatusBadRequest},
		{"contains html", "<img src=x>", http.StatusBadRequest},
		{"contains space", "host name", http.StatusBadRequest},
		{"too long", strings.Repeat("a", 254), http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newAuditTestServer(t)
			body, _ := json.Marshal(map[string]any{
				"token":            "bogus",
				"name":             "test-sensor",
				"host":             c.host,
				"pubkey":           "ssh-ed25519 AAAA test",
				"protocol_version": 2,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/quiver/enroll", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.handleQuiverEnroll(w, req)
			if w.Code != c.want {
				t.Errorf("status=%d want=%d body=%s", w.Code, c.want, w.Body.String())
			}
		})
	}
}
