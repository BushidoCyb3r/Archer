package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

type campaignRow struct {
	Dst      string   `json:"dst"`
	Port     string   `json:"port"`
	Srcs     []string `json:"srcs"`
	MaxScore int      `json:"max_score"`
	Hosts    int      `json:"hosts"`
	Types    []string `json:"types"`
}

type hostRow struct {
	IP          string   `json:"ip"`
	Score       int      `json:"score"`
	Count       int      `json:"count"`
	BeaconCount int      `json:"beacon_count"`
	TopSev      string   `json:"top_sev"`
	Types       []string `json:"types"`
}

type listRow struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	DstPort string `json:"dst_port"`
	Score   int    `json:"score"`
}

func fetchFindingsList(t *testing.T, s *Server, url string) []listRow {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleFindings(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s: status %d, body %s", url, rec.Code, rec.Body.String())
	}
	var rows []listRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse findings list: %v", err)
	}
	return rows
}

// TestFindingsScopedFetch_DrillDownContract pins the server-side scoping the
// Campaigns/Hosts drill-downs depend on after they stopped holding the whole
// corpus in memory: /api/findings?dst_ip=X&dst_port=Y returns exactly that
// destination's findings, and ?src_ip=X returns every finding for that host
// including its Host Risk Score roll-up (the host pivot surfaces it at top).
func TestFindingsScopedFetch_DrillDownContract(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Score: 80, Severity: model.SevHigh},
		{ID: 2, Type: "HTTP Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", DstPort: "443", Score: 95, Severity: model.SevCritical},
		// Different destination — must not appear in the campaign scope.
		{ID: 3, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "198.51.100.7", DstPort: "8080", Score: 70, Severity: model.SevMedium},
		// Host roll-up for 10.0.0.1 — must appear in the src scope.
		{ID: 4, Type: model.TypeHostRiskScore, SrcIP: "10.0.0.1", Score: 90, Severity: model.SevCritical},
	})

	camp := fetchFindingsList(t, s, "/api/findings?dst_ip=203.0.113.5&dst_port=443")
	if len(camp) != 2 {
		t.Fatalf("campaign scope returned %d findings, want 2: %+v", len(camp), camp)
	}
	for _, f := range camp {
		if f.DstIP != "203.0.113.5" || f.DstPort != "443" {
			t.Errorf("campaign scope leaked %s:%s (id %d)", f.DstIP, f.DstPort, f.ID)
		}
	}

	host := fetchFindingsList(t, s, "/api/findings?src_ip=10.0.0.1")
	if len(host) != 3 {
		t.Fatalf("host scope returned %d findings, want 3 (ids 1,3,4): %+v", len(host), host)
	}
	var sawRollup bool
	for _, f := range host {
		if f.SrcIP != "10.0.0.1" {
			t.Errorf("host scope leaked src %s (id %d)", f.SrcIP, f.ID)
		}
		if f.Type == model.TypeHostRiskScore {
			sawRollup = true
		}
	}
	if !sawRollup {
		t.Error("host scope must include the Host Risk Score roll-up")
	}
}

func fetchCampaigns(t *testing.T, s *Server, url string) []campaignRow {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleCampaigns(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s: status %d, body %s", url, rec.Code, rec.Body.String())
	}
	var resp struct {
		Campaigns []campaignRow `json:"campaigns"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse campaigns response: %v", err)
	}
	return resp.Campaigns
}

func fetchHosts(t *testing.T, s *Server, url string) []hostRow {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleHosts(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s: status %d, body %s", url, rec.Code, rec.Body.String())
	}
	var resp struct {
		Hosts []hostRow `json:"hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse hosts response: %v", err)
	}
	return resp.Hosts
}

// TestCampaignsEndpoint pins the /api/campaigns aggregation contract: a
// destination is a campaign iff ≥2 *distinct, non-dismissed* source IPs
// contacted it. The row carries the full source list, the max score across
// its findings, and the union of finding types. Single-source destinations,
// the synthetic "(network)" destination, and destinations whose only extra
// source is a dismissed finding are all excluded.
func TestCampaignsEndpoint(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		// Campaign: two distinct sources to 203.0.113.5:443.
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Score: 80, Severity: model.SevHigh},
		{ID: 2, Type: "HTTP Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", DstPort: "443", Score: 95, Severity: model.SevCritical},
		// Single source — not a campaign.
		{ID: 3, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.9", DstPort: "80", Score: 70, Severity: model.SevMedium},
		// 203.0.113.20:443 has two sources, but one is dismissed — the
		// dismissed finding must drop out *before* the ≥2 count, leaving a
		// single live source, so this is not a campaign.
		{ID: 4, Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "203.0.113.20", DstPort: "443", Score: 65, Severity: model.SevMedium},
		{ID: 5, Type: "Beacon", SrcIP: "10.0.0.4", DstIP: "203.0.113.20", DstPort: "443", Score: 66, Severity: model.SevMedium, Status: model.StatusDismissed},
		// Synthetic network destination — always excluded.
		{ID: 6, Type: "DNS NXDOMAIN Flood", SrcIP: "10.0.0.1", DstIP: "(network)", DstPort: "53", Score: 50, Severity: model.SevLow},
	})

	got := fetchCampaigns(t, s, "/api/campaigns")
	if len(got) != 1 {
		t.Fatalf("got %d campaigns, want 1: %+v", len(got), got)
	}
	c := got[0]
	if c.Dst != "203.0.113.5" || c.Port != "443" {
		t.Errorf("campaign dst/port = %s:%s, want 203.0.113.5:443", c.Dst, c.Port)
	}
	if want := []string{"10.0.0.1", "10.0.0.2"}; !reflect.DeepEqual(c.Srcs, want) {
		t.Errorf("srcs = %v, want %v (sorted, both live sources)", c.Srcs, want)
	}
	if c.Hosts != 2 {
		t.Errorf("hosts = %d, want 2", c.Hosts)
	}
	if c.MaxScore != 95 {
		t.Errorf("max_score = %d, want 95 (max across the campaign's findings)", c.MaxScore)
	}
	if want := []string{"Beacon", "HTTP Beacon"}; !reflect.DeepEqual(c.Types, want) {
		t.Errorf("types = %v, want %v", c.Types, want)
	}
}

// TestCampaignsEndpoint_DismissedBucket pins that /api/campaigns honors the
// status param so the Dismissed > Campaigns sub-tab works: the default view
// rolls up only open findings, while status=dismissed rolls up only the
// dismissed bucket.
func TestCampaignsEndpoint_DismissedBucket(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Score: 80, Severity: model.SevHigh},
		{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", DstPort: "443", Score: 85, Severity: model.SevHigh},
		{ID: 3, Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "198.51.100.7", DstPort: "8080", Score: 70, Severity: model.SevMedium, Status: model.StatusDismissed},
		{ID: 4, Type: "Beacon", SrcIP: "10.0.0.4", DstIP: "198.51.100.7", DstPort: "8080", Score: 72, Severity: model.SevMedium, Status: model.StatusDismissed},
	})

	open := fetchCampaigns(t, s, "/api/campaigns")
	if len(open) != 1 || open[0].Dst != "203.0.113.5" {
		t.Fatalf("default view = %+v, want only the open campaign 203.0.113.5", open)
	}
	dis := fetchCampaigns(t, s, "/api/campaigns?status=dismissed")
	if len(dis) != 1 || dis[0].Dst != "198.51.100.7" {
		t.Fatalf("dismissed view = %+v, want only the dismissed campaign 198.51.100.7", dis)
	}
}

// TestCampaignsEndpoint_HonorsFilterIgnoresPaging pins that /api/campaigns
// runs the same filter surface as /api/findings (min_score narrows the set)
// while limit/offset are ignored — the campaign set is returned whole so the
// client can sort and paginate it.
func TestCampaignsEndpoint_HonorsFilterIgnoresPaging(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		// Campaign A — both findings score ≥ 60.
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Score: 80, Severity: model.SevHigh},
		{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", DstPort: "443", Score: 95, Severity: model.SevCritical},
		// Campaign B — both findings score < 60, so min_score=60 erases it.
		{ID: 3, Type: "Beacon", SrcIP: "10.0.0.5", DstIP: "198.51.100.7", DstPort: "8080", Score: 50, Severity: model.SevLow},
		{ID: 4, Type: "Beacon", SrcIP: "10.0.0.6", DstIP: "198.51.100.7", DstPort: "8080", Score: 55, Severity: model.SevLow},
	})

	got := fetchCampaigns(t, s, "/api/campaigns?min_score=60&limit=1&offset=5")
	if len(got) != 1 {
		t.Fatalf("got %d campaigns, want 1 (min_score filters B, paging ignored): %+v", len(got), got)
	}
	if got[0].Dst != "203.0.113.5" {
		t.Errorf("campaign dst = %s, want 203.0.113.5", got[0].Dst)
	}
}

// TestCampaignDismiss pins the bulk-dismiss write path: a POST to
// /api/campaigns/dismiss dismisses exactly the open findings matching the
// campaign's (dst_ip, dst_port) — leaving findings to other destinations
// untouched and not re-touching already-dismissed ones — and returns the
// count actually dismissed.
func TestCampaignDismiss(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Score: 80, Severity: model.SevHigh},
		{ID: 2, Type: "HTTP Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", DstPort: "443", Score: 95, Severity: model.SevCritical},
		// Already dismissed — skipped, not re-counted.
		{ID: 3, Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "203.0.113.5", DstPort: "443", Score: 70, Severity: model.SevMedium, Status: model.StatusDismissed},
		// Different destination — must stay open.
		{ID: 4, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "198.51.100.7", DstPort: "8080", Score: 60, Severity: model.SevLow},
		// Same IP, different port — must stay open (port is part of the key).
		{ID: 5, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "80", Score: 65, Severity: model.SevMedium},
	})

	body := `{"dst_ip":"203.0.113.5","dst_port":"443","note":"bulk triage"}`
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/campaigns/dismiss", bytes.NewBufferString(body)), model.RoleAnalyst)
	rec := httptest.NewRecorder()
	s.handleCampaignDismiss(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Dismissed int `json:"dismissed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Dismissed != 2 {
		t.Errorf("dismissed = %d, want 2 (ids 1,2; id 3 already dismissed)", resp.Dismissed)
	}

	status := map[int]model.Status{}
	for _, f := range s.store.GetFindings() {
		status[f.ID] = f.Status
	}
	for _, id := range []int{1, 2, 3} {
		if status[id] != model.StatusDismissed {
			t.Errorf("finding %d status = %q, want dismissed", id, status[id])
		}
	}
	if status[4] == model.StatusDismissed {
		t.Error("finding 4 (other destination) must not be dismissed")
	}
	if status[5] == model.StatusDismissed {
		t.Error("finding 5 (same IP, port 80) must not be dismissed — port is part of the campaign key")
	}
}

// TestHostsEndpoint pins the /api/hosts roll-up: one row per org-internal
// source IP, with finding count, beacon density (only the four beacon types
// tally), risk score (max), and worst severity. Public source IPs and hosts
// whose only finding is dismissed are excluded.
func TestHostsEndpoint(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", Score: 80, Severity: model.SevHigh},
		{ID: 2, Type: "HTTP Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.6", Score: 90, Severity: model.SevCritical},
		{ID: 3, Type: "Data Exfiltration", SrcIP: "10.0.0.1", DstIP: "203.0.113.7", Score: 60, Severity: model.SevMedium},
		// Dismissed-only host — excluded.
		{ID: 4, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", Score: 50, Severity: model.SevLow, Status: model.StatusDismissed},
		// Public source IP — not org-internal, excluded.
		{ID: 5, Type: "Zeek Notice", SrcIP: "203.0.113.99", DstIP: "10.0.0.1", Score: 40, Severity: model.SevLow},
	})

	got := fetchHosts(t, s, "/api/hosts")
	if len(got) != 1 {
		t.Fatalf("got %d hosts, want 1: %+v", len(got), got)
	}
	h := got[0]
	if h.IP != "10.0.0.1" {
		t.Errorf("host ip = %s, want 10.0.0.1", h.IP)
	}
	if h.Count != 3 {
		t.Errorf("count = %d, want 3", h.Count)
	}
	if h.BeaconCount != 2 {
		t.Errorf("beacon_count = %d, want 2 (Beacon + HTTP Beacon; Data Exfiltration is not a beacon)", h.BeaconCount)
	}
	if h.Score != 90 {
		t.Errorf("score = %d, want 90", h.Score)
	}
	if h.TopSev != "CRITICAL" {
		t.Errorf("top_sev = %s, want CRITICAL", h.TopSev)
	}
}
