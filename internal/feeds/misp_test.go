package feeds

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// canned mimics a single-page MISP /attributes/restSearch response
// covering every indicator type the adapter handles plus a couple
// it must skip.
const cannedMISPBody = `{
  "response": {
    "Attribute": [
      {"id":"1","type":"ip-dst","value":"203.0.113.1","category":"Network activity","to_ids":true,"Tag":[{"name":"tlp:white"}]},
      {"id":"2","type":"ip-src","value":"198.51.100.5","category":"Network activity","to_ids":true,"Tag":[]},
      {"id":"3","type":"ip-dst","value":"10.0.0.0/8","category":"Network activity","to_ids":true,"Tag":[]},
      {"id":"4","type":"domain","value":"evil.test","category":"Network activity","to_ids":true,"Tag":[{"name":"campaign:trickbot"}]},
      {"id":"5","type":"hostname","value":"c2.evil.test","category":"Network activity","to_ids":true,"Tag":[]},
      {"id":"6","type":"md5","value":"d41d8cd98f00b204e9800998ecf8427e","category":"Payload delivery","to_ids":true,"Tag":[]},
      {"id":"7","type":"sha256","value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","category":"Payload delivery","to_ids":true,"Tag":[]},
      {"id":"8","type":"url","value":"http://evil.test/path","category":"Network activity","to_ids":true,"Tag":[]},
      {"id":"9","type":"ip-dst","value":"not-a-real-ip","category":"Network activity","to_ids":true,"Tag":[]},
      {"id":"10","type":"domain","value":"","category":"Network activity","to_ids":true,"Tag":[]}
    ]
  }
}`

func TestMISPClient_Fetch_ParsesAndNormalizes(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, cannedMISPBody)
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "test-key")
	got, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	// Adapter contract: 7 valid indicators, 3 skipped (url, malformed IP,
	// empty domain).
	if len(got) != 7 {
		t.Fatalf("expected 7 indicators, got %d: %+v", len(got), got)
	}

	// Spot-check the request the adapter sent.
	if gotAuth != "test-key" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "test-key")
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/attributes/restSearch") {
		t.Errorf("path = %q, want suffix /attributes/restSearch", gotPath)
	}
	if gotBody["returnFormat"] != "json" {
		t.Errorf("body returnFormat = %v, want json", gotBody["returnFormat"])
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

func TestMISPClient_Fetch_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "bad-key")
	_, err := c.Fetch(context.Background())
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
			_, err := tt.client.Fetch(context.Background())
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
