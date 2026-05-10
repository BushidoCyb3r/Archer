package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
)

// stubFeedProvider returns a fixed slice of SourcedIndicators for tests.
type stubFeedProvider struct {
	out []feeds.SourcedIndicators
}

func (s *stubFeedProvider) EnabledFeedIndicators() []feeds.SourcedIndicators {
	return s.out
}

// TestPrefetchPopulatesFeedSources verifies that prefetchFeeds copies
// the FeedProvider's snapshot onto the analyzer for the duration of
// the run.
func TestPrefetchPopulatesFeedSources(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}

	a.SetFeedProvider(&stubFeedProvider{
		out: []feeds.SourcedIndicators{{
			Source: "feed:demo",
			IPs:    map[string]bool{"203.0.113.7": true},
		}},
	})
	a.prefetchFeeds(nil)

	if len(a.feedSources) != 1 {
		t.Fatalf("want 1 feed source, got %d", len(a.feedSources))
	}
	if !a.feedSources[0].IPs["203.0.113.7"] {
		t.Errorf("feed IP not propagated to analyzer")
	}
}

// TestFeedIPIndicatorEmitsThreatIntelHit writes a minimal conn.log
// with a single external dst, registers that dst as an indicator on a
// stub feed, and asserts the analyzer emits a Threat Intel Hit
// attributed to the feed.
func TestFeedIPIndicatorEmitsThreatIntelHit(t *testing.T) {
	dir := t.TempDir()
	connLog := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(connLog, []byte(
		`{"ts":1705320000.0,"uid":"T0000001","id.orig_h":"192.168.8.10","id.orig_p":50000,"id.resp_h":"198.51.100.42","id.resp_p":443,"proto":"tcp","duration":1.0,"orig_bytes":500,"resp_bytes":2000,"orig_ip_bytes":540,"resp_ip_bytes":2040,"conn_state":"SF"}`+"\n",
	), 0o644); err != nil {
		t.Fatalf("write conn.log: %v", err)
	}

	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	a.SetFeedProvider(&stubFeedProvider{
		out: []feeds.SourcedIndicators{{
			Source: "feed:smoke-test",
			IPs:    map[string]bool{"198.51.100.42": true},
			Tags:   map[string][]string{"198.51.100.42": {"malware:emotet"}},
		}},
	})

	findings := a.Analyze([]string{connLog})

	hit := false
	for _, f := range findings {
		if f.Type != "TI Hit (IP)" {
			continue
		}
		if f.SourceFile != "feed:smoke-test" {
			continue
		}
		if f.DstIP != "198.51.100.42" {
			continue
		}
		if !strings.Contains(f.Detail, "smoke-test indicator match") {
			t.Errorf("detail missing feed-attribution prefix: %q", f.Detail)
		}
		if !strings.Contains(f.Detail, "malware:emotet") {
			t.Errorf("detail missing tag: %q", f.Detail)
		}
		hit = true
		break
	}
	if !hit {
		var got []string
		for _, f := range findings {
			got = append(got, f.Type+" "+f.SrcIP+"→"+f.DstIP+" ["+f.SourceFile+"]")
		}
		t.Fatalf("no TI Hit (IP) attributed to feed:smoke-test; got: %v", got)
	}
}

// TestFeedDomainIndicatorEmitsThreatIntelHit writes a minimal dns.log
// for a single query, registers that domain as a feed indicator, and
// asserts a Threat Intel Hit with the feed's source label.
func TestFeedDomainIndicatorEmitsThreatIntelHit(t *testing.T) {
	dir := t.TempDir()
	dnsLog := filepath.Join(dir, "dns.log")
	if err := os.WriteFile(dnsLog, []byte(
		`{"ts":1705320000.0,"uid":"D0000001","id.orig_h":"192.168.8.10","id.orig_p":52000,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"badguy.example","qtype_name":"A","rcode_name":"NOERROR"}`+"\n",
	), 0o644); err != nil {
		t.Fatalf("write dns.log: %v", err)
	}

	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}
	a.SetFeedProvider(&stubFeedProvider{
		out: []feeds.SourcedIndicators{{
			Source:  "feed:smoke-test",
			Domains: map[string]bool{"badguy.example": true},
		}},
	})

	findings := a.Analyze([]string{dnsLog})

	hit := false
	for _, f := range findings {
		if f.Type == "TI Hit (Domain)" && f.SourceFile == "feed:smoke-test" && f.DstIP == "badguy.example" {
			hit = true
			break
		}
	}
	if !hit {
		var got []string
		for _, f := range findings {
			got = append(got, f.Type+" "+f.SrcIP+"→"+f.DstIP+" ["+f.SourceFile+"]")
		}
		t.Fatalf("no TI Hit (Domain) attributed to feed:smoke-test for domain match; got: %v", got)
	}
}
