package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// openCTIPage1 covers the four normalized indicator types plus three
// skip cases: empty STIX value, unsupported observable type (Url),
// and malformed IPv4.
const openCTIPage1 = `{
  "data": {
    "indicators": {
      "edges": [
        {"cursor":"c1","node":{"id":"indicator--ip4","pattern":"[ipv4-addr:value = '203.0.113.1']","x_opencti_main_observable_type":"IPv4-Addr","objectLabel":[{"value":"tlp:white"}]}},
        {"cursor":"c2","node":{"id":"indicator--ip6","pattern":"[ipv6-addr:value = '2001:db8::1']","x_opencti_main_observable_type":"IPv6-Addr","objectLabel":[]}},
        {"cursor":"c3","node":{"id":"indicator--cidr","pattern":"[ipv4-addr:value = '10.0.0.0/8']","x_opencti_main_observable_type":"IPv4-Addr","objectLabel":[]}},
        {"cursor":"c4","node":{"id":"indicator--dom","pattern":"[domain-name:value = 'evil.test']","x_opencti_main_observable_type":"Domain-Name","objectLabel":[{"value":"campaign:trickbot"}]}},
        {"cursor":"c5","node":{"id":"indicator--host","pattern":"[hostname:value = 'c2.evil.test']","x_opencti_main_observable_type":"Hostname","objectLabel":[]}},
        {"cursor":"c6","node":{"id":"indicator--hash","pattern":"[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']","x_opencti_main_observable_type":"StixFile","objectLabel":[]}},
        {"cursor":"c7","node":{"id":"indicator--url","pattern":"[url:value = 'http://evil.test/path']","x_opencti_main_observable_type":"Url","objectLabel":[]}},
        {"cursor":"c8","node":{"id":"indicator--bad","pattern":"[ipv4-addr:value = 'not-an-ip']","x_opencti_main_observable_type":"IPv4-Addr","objectLabel":[]}},
        {"cursor":"c9","node":{"id":"indicator--noval","pattern":"[ipv4-addr:value = ]","x_opencti_main_observable_type":"IPv4-Addr","objectLabel":[]}}
      ],
      "pageInfo": {"hasNextPage": false, "endCursor": "c6"}
    }
  }
}`

// openCTIPagedPage1 advances to page 2; openCTIPagedPage2 ends the walk.
const openCTIPagedPage1 = `{
  "data": {
    "indicators": {
      "edges": [
        {"cursor":"p1","node":{"id":"indicator--p1","pattern":"[ipv4-addr:value = '203.0.113.10']","x_opencti_main_observable_type":"IPv4-Addr","objectLabel":[]}}
      ],
      "pageInfo": {"hasNextPage": true, "endCursor": "AFTER_PAGE_1"}
    }
  }
}`

const openCTIPagedPage2 = `{
  "data": {
    "indicators": {
      "edges": [
        {"cursor":"p2","node":{"id":"indicator--p2","pattern":"[ipv4-addr:value = '203.0.113.20']","x_opencti_main_observable_type":"IPv4-Addr","objectLabel":[]}}
      ],
      "pageInfo": {"hasNextPage": false, "endCursor": "AFTER_PAGE_2"}
    }
  }
}`

func TestOpenCTIClient_Fetch_ParsesAndNormalizes(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, openCTIPage1)
	}))
	defer srv.Close()

	c := NewOpenCTIClient(srv.URL, "test-token", false, true, "")
	res, err := c.Fetch(context.Background(), 0)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	got := res.Indicators

	// 6 valid indicators, 3 skipped (Url, malformed IPv4, missing value).
	if len(got) != 6 {
		t.Fatalf("expected 6 indicators, got %d: %+v", len(got), got)
	}

	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer test-token")
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/graphql") {
		t.Errorf("path = %q, want suffix /graphql", gotPath)
	}
	if _, ok := gotBody["query"].(string); !ok {
		t.Errorf("body should include a `query` string field")
	}

	wantByID := map[string]struct {
		typ IndicatorType
		val string
	}{
		"indicator--ip4":  {IndicatorIP, "203.0.113.1"},
		"indicator--ip6":  {IndicatorIP, "2001:db8::1"},
		"indicator--cidr": {IndicatorCIDR, "10.0.0.0/8"},
		"indicator--dom":  {IndicatorDomain, "evil.test"},
		"indicator--host": {IndicatorDomain, "c2.evil.test"},
		"indicator--hash": {IndicatorHash, "d41d8cd98f00b204e9800998ecf8427e"},
	}
	for _, ind := range got {
		want, ok := wantByID[ind.SourceID]
		if !ok {
			t.Errorf("unexpected indicator: %+v", ind)
			continue
		}
		if ind.Type != want.typ {
			t.Errorf("%s: type = %q, want %q", ind.SourceID, ind.Type, want.typ)
		}
		if ind.Indicator != want.val {
			t.Errorf("%s: value = %q, want %q", ind.SourceID, ind.Indicator, want.val)
		}
	}

	// Tags round-trip on the indicators that had them.
	for _, ind := range got {
		switch ind.SourceID {
		case "indicator--ip4":
			if len(ind.Tags) != 1 || ind.Tags[0] != "tlp:white" {
				t.Errorf("indicator--ip4 tags = %v, want [tlp:white]", ind.Tags)
			}
		case "indicator--dom":
			if len(ind.Tags) != 1 || ind.Tags[0] != "campaign:trickbot" {
				t.Errorf("indicator--dom tags = %v, want [campaign:trickbot]", ind.Tags)
			}
		}
	}
}

func TestOpenCTIClient_Fetch_FollowsPagination(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body openCTIRequest
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		if body.Variables["after"] == nil {
			_, _ = io.WriteString(w, openCTIPagedPage1)
			return
		}
		if got := body.Variables["after"]; got == "AFTER_PAGE_1" {
			_, _ = io.WriteString(w, openCTIPagedPage2)
			return
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{"data":{"indicators":{"edges":[],"pageInfo":{"hasNextPage":false,"endCursor":""}}}, "errors": null}`))
	}))
	defer srv.Close()

	c := NewOpenCTIClient(srv.URL, "tok", false, true, "")
	c.PageSize = 1
	res, err := c.Fetch(context.Background(), 0)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(res.Indicators) != 2 {
		t.Errorf("expected 2 indicators across 2 pages, got %d", len(res.Indicators))
	}
	if calls.Load() != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", calls.Load())
	}
}

func TestOpenCTIClient_Fetch_PageLimitGuard(t *testing.T) {
	// Pretend the server always claims hasNextPage=true. The client must
	// stop after PageLimit calls so a misbehaving deployment can't loop
	// the worker forever.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"data": {"indicators": {
				"edges": [{"cursor":"x","node":{"id":"i--inf","pattern":"[ipv4-addr:value = '1.1.1.1']","x_opencti_main_observable_type":"IPv4-Addr","objectLabel":[]}}],
				"pageInfo": {"hasNextPage": true, "endCursor": "always-more"}
			}}
		}`)
	}))
	defer srv.Close()

	c := NewOpenCTIClient(srv.URL, "tok", false, true, "")
	c.PageLimit = 3
	_, err := c.Fetch(context.Background(), 0)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("expected exactly PageLimit=3 calls, got %d", calls.Load())
	}
}

func TestOpenCTIClient_Fetch_PropagatesGraphQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":[{"message":"unauthorized"}]}`)
	}))
	defer srv.Close()

	c := NewOpenCTIClient(srv.URL, "tok", false, true, "")
	_, err := c.Fetch(context.Background(), 0)
	if err == nil {
		t.Fatalf("expected graphql error, got nil")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("error = %q, want substring 'unauthorized'", err.Error())
	}
}

func TestOpenCTIClient_Fetch_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewOpenCTIClient(srv.URL, "tok", false, true, "")
	_, err := c.Fetch(context.Background(), 0)
	if err == nil {
		t.Fatalf("expected HTTP 403 error, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want substring '403'", err.Error())
	}
}

func TestOpenCTIClient_Fetch_RejectsEmptyConfig(t *testing.T) {
	tests := []struct {
		name   string
		client *OpenCTIClient
	}{
		{"empty URL", &OpenCTIClient{APIKey: "k"}},
		{"empty key", &OpenCTIClient{BaseURL: "https://example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.client.Fetch(context.Background(), 0)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// emptyPage is a minimal GraphQL response for filter-only tests that
// don't need actual indicator data.
const emptyPage = `{"data":{"indicators":{"edges":[],"pageInfo":{"hasNextPage":false,"endCursor":""}}}}`

func TestOpenCTIClient_Fetch_SinceFilter(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, emptyPage)
	}))
	defer srv.Close()

	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	c := NewOpenCTIClient(srv.URL, "tok", false, true, "")
	if _, err := c.Fetch(context.Background(), since); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	var req struct {
		Variables struct {
			Filters struct {
				Mode    string `json:"mode"`
				Filters []struct {
					Key      string   `json:"key"`
					Values   []string `json:"values"`
					Operator string   `json:"operator"`
				} `json:"filters"`
			} `json:"filters"`
		} `json:"variables"`
	}
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	fg := req.Variables.Filters
	if fg.Mode != "and" {
		t.Errorf("filters.mode = %q, want and", fg.Mode)
	}
	if len(fg.Filters) == 0 {
		t.Fatalf("filters.filters empty — since filter not sent")
	}
	f0 := fg.Filters[0]
	if f0.Key != "modified" {
		t.Errorf("filters[0].key = %q, want modified", f0.Key)
	}
	if f0.Operator != "gt" {
		t.Errorf("filters[0].operator = %q, want gt", f0.Operator)
	}
	if len(f0.Values) == 0 || !strings.HasPrefix(f0.Values[0], "2024-01-01T00:00:00") {
		t.Errorf("filters[0].values = %v, want 2024-01-01T00:00:00... prefix", f0.Values)
	}
}

func TestOpenCTIClient_Fetch_QueryFilter(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, emptyPage)
	}))
	defer srv.Close()

	filterJSON := `{"mode":"and","filters":[{"key":"x_opencti_main_observable_type","values":["IPv4-Addr"],"operator":"eq"}],"filterGroups":[]}`
	c := NewOpenCTIClient(srv.URL, "tok", false, true, filterJSON)
	if _, err := c.Fetch(context.Background(), 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	var req struct {
		Variables struct {
			Filters map[string]any `json:"filters"`
		} `json:"variables"`
	}
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if req.Variables.Filters == nil {
		t.Fatal("variables.filters not set when query_filter_json provided")
	}
	if req.Variables.Filters["mode"] != "and" {
		t.Errorf("filters.mode = %v, want and", req.Variables.Filters["mode"])
	}
}

func TestOpenCTIClient_Fetch_SinceAndQueryFilterCombined(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, emptyPage)
	}))
	defer srv.Close()

	filterJSON := `{"mode":"and","filters":[{"key":"x_opencti_main_observable_type","values":["IPv4-Addr"],"operator":"eq"}],"filterGroups":[]}`
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	c := NewOpenCTIClient(srv.URL, "tok", false, true, filterJSON)
	if _, err := c.Fetch(context.Background(), since); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	var req struct {
		Variables struct {
			Filters struct {
				Mode    string `json:"mode"`
				Filters []struct {
					Key string `json:"key"`
				} `json:"filters"`
				FilterGroups []map[string]any `json:"filterGroups"`
			} `json:"filters"`
		} `json:"variables"`
	}
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	fg := req.Variables.Filters
	if fg.Mode != "and" {
		t.Errorf("top-level mode = %q, want and", fg.Mode)
	}
	if len(fg.Filters) == 0 || fg.Filters[0].Key != "modified" {
		t.Errorf("top-level filters should contain modified key: %v", fg.Filters)
	}
	if len(fg.FilterGroups) == 0 {
		t.Errorf("top-level filterGroups should contain operator filter, got none")
	}
}

func TestOpenCTIClient_Fetch_NoFiltersWhenBothAbsent(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, emptyPage)
	}))
	defer srv.Close()

	c := NewOpenCTIClient(srv.URL, "tok", false, true, "")
	if _, err := c.Fetch(context.Background(), 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	var req struct {
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if _, ok := req.Variables["filters"]; ok {
		t.Errorf("variables.filters should be absent when since==0 and no query filter")
	}
}

func TestStixValue(t *testing.T) {
	tests := []struct {
		pattern, want string
	}{
		{"[ipv4-addr:value = '203.0.113.1']", "203.0.113.1"},
		{"[file:hashes.'SHA-256' = 'abcdef']", "abcdef"},
		{"[domain-name:value = 'evil.test']", "evil.test"},
		{"no quotes", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := stixValue(tt.pattern); got != tt.want {
			t.Errorf("stixValue(%q) = %q, want %q", tt.pattern, got, tt.want)
		}
	}
}
