package feeds

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mispCannedAttrs is the universe of attributes the test server can
// return. Fetch is type-sharded — one restSearch request per type —
// so the test handler filters this list against the requested type
// and returns only matching rows. Mirrors what a real MISP would do.
var mispCannedAttrs = []map[string]any{
	{"id": "1", "type": "ip-dst", "value": "203.0.113.1", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{{"name": "tlp:white"}}},
	{"id": "2", "type": "ip-src", "value": "198.51.100.5", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{}},
	{"id": "3", "type": "ip-dst", "value": "10.0.0.0/8", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{}},
	{"id": "4", "type": "domain", "value": "evil.test", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{{"name": "campaign:trickbot"}}},
	{"id": "5", "type": "hostname", "value": "c2.evil.test", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{}},
	{"id": "6", "type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "category": "Payload delivery", "to_ids": true, "Tag": []map[string]any{}},
	{"id": "7", "type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "category": "Payload delivery", "to_ids": true, "Tag": []map[string]any{}},
	// Skipped by the adapter (URL type, malformed IP, empty domain).
	{"id": "8", "type": "url", "value": "http://evil.test/path", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{}},
	{"id": "9", "type": "ip-dst", "value": "not-a-real-ip", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{}},
	{"id": "10", "type": "domain", "value": "", "category": "Network activity", "to_ids": true, "Tag": []map[string]any{}},
}

// mispTestHandler mimics restSearch's type-filter behaviour: the
// request body's `type` array is taken as the filter and only
// attributes whose type is in that list are returned. Captures the
// last seen request body (under mu) so tests can spot-check.
type mispTestHandler struct {
	mu            sync.Mutex
	auth          string
	method        string
	path          string
	body          map[string]any
	calls         int32
	concurrentLog []time.Time
}

func newMISPTestServer(t *testing.T) (*httptest.Server, *mispTestHandler) {
	t.Helper()
	h := &mispTestHandler{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&h.calls, 1)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)

		h.mu.Lock()
		h.auth = r.Header.Get("Authorization")
		h.method = r.Method
		h.path = r.URL.Path
		h.body = body
		h.concurrentLog = append(h.concurrentLog, time.Now())
		h.mu.Unlock()

		// Filter mispCannedAttrs by the requested type set.
		want := map[string]bool{}
		if t, ok := body["type"].([]any); ok {
			for _, v := range t {
				if s, ok := v.(string); ok {
					want[s] = true
				}
			}
		}
		matching := []map[string]any{}
		for _, attr := range mispCannedAttrs {
			if want[attr["type"].(string)] {
				matching = append(matching, attr)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"response": map[string]any{"Attribute": matching},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, h
}

func TestMISPClient_Fetch_ParsesAndNormalizes(t *testing.T) {
	srv, h := newMISPTestServer(t)

	c := NewMISPClient(srv.URL, "test-key", false)
	res, err := c.Fetch(context.Background(), 0)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	got := res.Indicators

	// Adapter contract: 7 valid indicators, 3 skipped (url, malformed IP,
	// empty domain).
	if len(got) != 7 {
		t.Fatalf("expected 7 indicators, got %d: %+v", len(got), got)
	}

	// Spot-check the last seen request (all shards send identical
	// shape modulo type filter).
	h.mu.Lock()
	auth, method, path, body := h.auth, h.method, h.path, h.body
	calls := atomic.LoadInt32(&h.calls)
	h.mu.Unlock()
	if auth != "test-key" {
		t.Errorf("Authorization header = %q, want %q", auth, "test-key")
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if !strings.HasSuffix(path, "/attributes/restSearch") {
		t.Errorf("path = %q, want suffix /attributes/restSearch", path)
	}
	if body["returnFormat"] != "json" {
		t.Errorf("body returnFormat = %v, want json", body["returnFormat"])
	}
	// Sharding: one request per attribute type.
	if int(calls) != len(mispAttributeTypes) {
		t.Errorf("expected %d shard requests, got %d", len(mispAttributeTypes), calls)
	}

	// Spot-check the normalization.
	wantByID := map[string]struct {
		typ IndicatorType
		val string
	}{
		"1": {IndicatorIP, "203.0.113.1"},
		"2": {IndicatorIP, "198.51.100.5"},
		"3": {IndicatorCIDR, "10.0.0.0/8"},
		"4": {IndicatorDomain, "evil.test"},
		"5": {IndicatorDomain, "c2.evil.test"},
		"6": {IndicatorHash, "d41d8cd98f00b204e9800998ecf8427e"},
		"7": {IndicatorHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}
	for _, ind := range got {
		want, ok := wantByID[ind.SourceID]
		if !ok {
			t.Errorf("unexpected indicator with SourceID %q: %+v", ind.SourceID, ind)
			continue
		}
		if ind.Type != want.typ {
			t.Errorf("indicator %q: type = %q, want %q", ind.SourceID, ind.Type, want.typ)
		}
		if ind.Indicator != want.val {
			t.Errorf("indicator %q: value = %q, want %q", ind.SourceID, ind.Indicator, want.val)
		}
	}

	// Tags should round-trip on the indicator that had them.
	for _, ind := range got {
		if ind.SourceID == "1" {
			if len(ind.Tags) != 1 || ind.Tags[0] != "tlp:white" {
				t.Errorf("indicator 1 tags = %v, want [tlp:white]", ind.Tags)
			}
		}
		if ind.SourceID == "4" {
			if len(ind.Tags) != 1 || ind.Tags[0] != "campaign:trickbot" {
				t.Errorf("indicator 4 tags = %v, want [campaign:trickbot]", ind.Tags)
			}
		}
	}
}

func TestMISPClient_Fetch_PassesTimestampFilterWhenSinceSet(t *testing.T) {
	srv, h := newMISPTestServer(t)

	c := NewMISPClient(srv.URL, "test-key", false)
	const since int64 = 1700000000
	if _, err := c.Fetch(context.Background(), since); err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	h.mu.Lock()
	body := h.body
	h.mu.Unlock()
	v, ok := body["timestamp"]
	if !ok {
		t.Fatalf("expected timestamp filter in request body, got %+v", body)
	}
	// JSON unmarshals numeric values to float64.
	if got := int64(v.(float64)); got != since {
		t.Errorf("timestamp filter = %d, want %d", got, since)
	}
}

func TestMISPClient_Fetch_OmitsTimestampFilterWhenSinceZero(t *testing.T) {
	srv, h := newMISPTestServer(t)

	c := NewMISPClient(srv.URL, "test-key", false)
	if _, err := c.Fetch(context.Background(), 0); err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	h.mu.Lock()
	body := h.body
	h.mu.Unlock()
	if _, ok := body["timestamp"]; ok {
		t.Errorf("timestamp filter should be absent on full pull, got %+v", body["timestamp"])
	}
}

// TestMISPClient_Fetch_RespectsConcurrencyCap verifies that no more
// than mispShardConcurrency requests run simultaneously even when
// every type-shard would otherwise overlap. The server holds each
// request open for a short window and tracks max in-flight.
func TestMISPClient_Fetch_RespectsConcurrencyCap(t *testing.T) {
	var (
		mu          sync.Mutex
		inFlight    int
		maxInFlight int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()

		// Hold the connection long enough that the orchestrator must
		// wait on the semaphore for any shards beyond concurrency.
		time.Sleep(50 * time.Millisecond)

		mu.Lock()
		inFlight--
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"response":{"Attribute":[]}}`)
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "test-key", false)
	if _, err := c.Fetch(context.Background(), 0); err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	mu.Lock()
	got := maxInFlight
	mu.Unlock()
	if got > mispShardConcurrency {
		t.Errorf("max in-flight requests = %d, want <= %d", got, mispShardConcurrency)
	}
	// Sanity: with concurrency=4 and 7 shards each held 50ms, at
	// least 2 shards should overlap.
	if got < 2 {
		t.Errorf("max in-flight = %d, expected at least 2 concurrent shards", got)
	}
}

func TestMISPClient_Fetch_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "bad-key", false)
	_, err := c.Fetch(context.Background(), 0)
	if err == nil {
		t.Fatalf("expected error on HTTP 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want substring 401", err.Error())
	}
}

func TestMISPClient_Fetch_RejectsEmptyConfig(t *testing.T) {
	tests := []struct {
		name   string
		client *MISPClient
	}{
		{"empty URL", &MISPClient{APIKey: "k"}},
		{"empty key", &MISPClient{BaseURL: "https://example.com"}},
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

func TestNormalizeMISPAttribute_RejectsUnknownTypes(t *testing.T) {
	for _, typ := range []string{"url", "filename", "regkey", "comment", ""} {
		_, ok := normalizeMISPAttribute(mispAttribute{Type: typ, Value: "x"})
		if ok {
			t.Errorf("type %q should not normalize", typ)
		}
	}
}
