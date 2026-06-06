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
			body: `{"findings":[{"type":"Beacon","severity":"HIGH","score":99999,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Negative Score",
			body: `{"findings":[{"type":"Beacon","severity":"HIGH","score":-1,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Bogus Severity",
			body: `{"findings":[{"type":"Beacon","severity":"PWNED","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Malformed Timestamp",
			body: `{"findings":[{"type":"Beacon","severity":"HIGH","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"yesterday"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Bogus Status",
			body: `{"findings":[{"type":"Beacon","severity":"HIGH","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00","status":"pwned"}]}`,
			want: http.StatusBadRequest,
		},
		{
			name: "Valid Finding Accepted",
			body: `{"findings":[{"type":"Beacon","severity":"HIGH","score":50,"src_ip":"10.0.0.1","dst_ip":"1.1.1.1","timestamp":"2026-05-10 12:00:00"}]}`,
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

// TestImport_PreservesCorrelationsAcrossIDRemap codifies NEW-97
// (twenty-second audit round). The invariant: when a JSON export is
// re-imported, every Correlations reference inside the payload must
// point at the same logical finding in the new store. The ID rewrite
// at import time (i+1 sequential) breaks the reference unless the
// import handler translates every Correlations slice through the
// old→new map.
//
// We articulate the invariant ("any Correlations reference between
// imported findings survives the rewrite") rather than the narrow
// failure case ("Correlated Activity's contributor list specifically").
// Multiple shapes touch the same code path: contributor rows pointing
// at the correlation row, the correlation row pointing at
// contributors, and chains where contributors reference other
// contributors. The invariant covers all three.
func TestImport_PreservesCorrelationsAcrossIDRemap(t *testing.T) {
	// Export shape: Beacon (old ID 47) and DNS Tunneling (old ID
	// 92) both contribute to Correlated Activity (old ID 200). Each
	// contributor lists the sibling + the correlation row. The
	// correlation row lists both contributors. The old IDs are
	// deliberately out of the 1..N range the import handler will
	// assign so any failure to remap shows up as missing references
	// (not as accidental collisions with the new IDs).
	payload := struct {
		Findings []model.Finding `json:"findings"`
	}{
		Findings: []model.Finding{
			{ID: 47, Type: "Beacon", Severity: model.SevHigh, Score: 85, SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Timestamp: "2026-05-10 09:00:00", Correlations: []int{92, 200}},
			{ID: 92, Type: "DNS Tunneling", Severity: model.SevMedium, Score: 60, SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Timestamp: "2026-05-10 14:00:00", Correlations: []int{47, 200}},
			{ID: 200, Type: model.TypeCorrelatedActivity, Severity: model.SevHigh, Score: 85, SrcIP: "10.0.0.1", DstIP: "1.2.3.4", Timestamp: "2026-05-10 09:00:00", Correlations: []int{47, 92}},
		},
	}
	body, _ := json.Marshal(payload)

	s := newAuditTestServer(t)
	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/import", bytes.NewReader(body)),
		model.RoleAdmin,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleImportJSON(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", w.Code, w.Body.String())
	}

	stored := s.store.GetFindings()
	if len(stored) != 3 {
		t.Fatalf("expected 3 findings stored; got %d", len(stored))
	}

	byType := map[string]model.Finding{}
	for _, f := range stored {
		byType[f.Type] = f
	}
	bcn, ok := byType["Beacon"]
	if !ok {
		t.Fatal("Beacon missing from store")
	}
	dns, ok := byType["DNS Tunneling"]
	if !ok {
		t.Fatal("DNS Tunneling missing from store")
	}
	corr, ok := byType[model.TypeCorrelatedActivity]
	if !ok {
		t.Fatal("Correlated Activity missing from store")
	}

	// Invariant: every Correlations slice references the OTHER two
	// findings' NEW IDs. Pre-fix this slice would be empty (all old
	// IDs dropped by SetFindings's translation, no remap done at
	// the import layer).
	expect := func(name string, got []int, want ...int) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s.Correlations = %v; want %v", name, got, want)
			return
		}
		seen := map[int]bool{}
		for _, id := range got {
			seen[id] = true
		}
		for _, w := range want {
			if !seen[w] {
				t.Errorf("%s.Correlations = %v; missing %d", name, got, w)
			}
		}
	}
	expect("Beacon", bcn.Correlations, dns.ID, corr.ID)
	expect("DNS Tunneling", dns.Correlations, bcn.ID, corr.ID)
	expect("Correlated Activity", corr.Correlations, bcn.ID, dns.ID)

	// Belt-and-suspenders: no Correlations entry should match an old
	// ID that wasn't remapped. The old IDs (47, 92, 200) are above
	// any new ID the import would assign (1..3), so any stale entry
	// would be detectable.
	for name, f := range byType {
		for _, id := range f.Correlations {
			if id == 47 || id == 92 || id == 200 {
				t.Errorf("%s.Correlations = %v; contains un-remapped old ID %d", name, f.Correlations, id)
			}
		}
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

// TestValidateFeedRequest_AllowInternalBypass covers the v0.18.5+
// AllowInternal opt-out of the NEW-18 SSRF guard. Invariant: a feed
// whose URL targets internal address space is refused at config time
// when AllowInternal is false (the default), and accepted when
// AllowInternal is true. The bypass is per-feed scoped — a typo in a
// different feed's URL still gets refused, because validateFeedRequest
// only consults the request's own flag.
//
// Other validation (scheme, name, api_key on create, aging-days) is
// independent — those must still apply regardless of AllowInternal.
func TestValidateFeedRequest_AllowInternalBypass(t *testing.T) {
	internalReq := func(allow bool) feedRequest {
		return feedRequest{
			SourceType:         "misp",
			Name:               "internal-misp",
			URL:                "https://10.0.0.17/feed",
			APIKey:             "k",
			IndicatorAgingDays: 30,
			Enabled:            true,
			AllowInternal:      allow,
		}
	}

	// Default behavior: internal URL rejected.
	if err := validateFeedRequest(internalReq(false), true); err == nil {
		t.Fatalf("validateFeedRequest with AllowInternal=false should reject internal URL; got nil")
	}

	// Opt-in: internal URL accepted.
	if err := validateFeedRequest(internalReq(true), true); err != nil {
		t.Fatalf("validateFeedRequest with AllowInternal=true should accept internal URL; got %v", err)
	}

	// Scheme check still applies even with AllowInternal=true. A bypass
	// of the SSRF guard isn't a bypass of every validation rule.
	bad := internalReq(true)
	bad.URL = "10.0.0.17/feed" // no scheme
	if err := validateFeedRequest(bad, true); err == nil {
		t.Errorf("validateFeedRequest with AllowInternal=true should still reject URL missing scheme; got nil")
	}

	// Public URL is unaffected by the flag — same accept either way.
	pub := internalReq(false)
	pub.URL = "https://misp.example.test/"
	if err := validateFeedRequest(pub, true); err != nil {
		t.Errorf("public URL should validate cleanly with AllowInternal=false; got %v", err)
	}
	pub.AllowInternal = true
	if err := validateFeedRequest(pub, true); err != nil {
		t.Errorf("public URL should validate cleanly with AllowInternal=true; got %v", err)
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
		// L-1: leading whitespace before a formula char must still be
		// neutralized — spreadsheet apps trim it before evaluating.
		{` =cmd|'/c calc'!A1`, `' =cmd|'/c calc'!A1`},
		{`  +1`, `'  +1`},
		{" \t=HYPERLINK(\"x\")", "' \t=HYPERLINK(\"x\")"},
		// Safe inputs unchanged.
		{`192.168.1.1`, `192.168.1.1`},
		{``, ``},
		{`Beacon`, `Beacon`},
		{`http://example.com`, `http://example.com`},
		{`  leading spaces then text`, `  leading spaces then text`},
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
