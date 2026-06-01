package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestCheckTI_DNSAttribution_NormalizesQuery is F-COR-2: a winning bad
// domain present in dns.log only in Zeek-normal form (uppercase + trailing
// dot) must still attribute the querying host. Phase A builds the winner
// set from the normalized query; Phase B's per-source lookup must normalize
// identically or the host attribution is lost and the TI Hit emits with the
// SrcIP="(TI)" placeholder for a confirmed malicious-domain contact.
func TestCheckTI_DNSAttribution_NormalizesQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns.log")
	rec := `{"ts":1700000000.0,"id.orig_h":"192.168.1.50","id.resp_h":"10.0.0.1","query":"EVIL.COM.","qtype_name":"A"}` + "\n"
	if err := os.WriteFile(path, []byte(rec), 0o644); err != nil {
		t.Fatalf("write dns.log: %v", err)
	}

	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{"evil.com": true}

	a.checkTI([]string{path})

	f := findingOfType(a.findings, model.TypeTIHitDomain)
	if f == nil {
		t.Fatalf("expected a TI Hit (Domain) finding for evil.com; got types: %v", findingTypes(a.findings))
	}
	if f.SrcIP != "192.168.1.50" {
		t.Errorf("SrcIP = %q, want 192.168.1.50 — host attribution lost to the (TI) placeholder", f.SrcIP)
	}
	if f.DstIP != "evil.com" {
		t.Errorf("DstIP = %q, want evil.com", f.DstIP)
	}
}

// TestPrefetchFeedsRespectsPrepopulated verifies that the test-injection guard
// in prefetchFeeds skips network fetches when caches are already populated.
// Without this guard, golden-file tests would hit Feodo Tracker and URLhaus
// over the live internet, making them flaky and network-dependent.
func TestPrefetchFeedsRespectsPrepopulated(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{"203.0.113.1": true}
	a.urlhausIPs = map[string]bool{"203.0.113.2": true}
	a.urlhausHosts = map[string]bool{"malware.test": true}

	a.prefetchFeeds(nil)

	if !a.feodoIPs["203.0.113.1"] {
		t.Errorf("feodoIPs lost the injected entry — fetch ran and overwrote it")
	}
	if !a.urlhausIPs["203.0.113.2"] {
		t.Errorf("urlhausIPs lost the injected entry — fetch ran and overwrote it")
	}
	if !a.urlhausHosts["malware.test"] {
		t.Errorf("urlhausHosts lost the injected entry — fetch ran and overwrote it")
	}
	// Sanity: no other entries were appended (proves the fetch was skipped).
	if len(a.feodoIPs) != 1 || len(a.urlhausIPs) != 1 || len(a.urlhausHosts) != 1 {
		t.Errorf("feed sizes drifted: feodo=%d urlhausIPs=%d urlhausHosts=%d",
			len(a.feodoIPs), len(a.urlhausIPs), len(a.urlhausHosts))
	}
}

// TestPrefetchFeedsEmptyMapStillCounts ensures an injected *empty* map
// is honored as "loaded, no entries" rather than re-triggering a fetch.
// Tests that want zero TI hits set the maps to empty (not nil) to neutralize
// the feeds without taking a network round-trip.
func TestPrefetchFeedsEmptyMapStillCounts(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}

	a.prefetchFeeds(nil)

	if a.feodoIPs == nil || a.urlhausIPs == nil || a.urlhausHosts == nil {
		t.Errorf("prefetchFeeds nilled an injected empty map")
	}
	if len(a.feodoIPs) != 0 || len(a.urlhausIPs) != 0 || len(a.urlhausHosts) != 0 {
		t.Errorf("prefetchFeeds appended to empty injected maps — network call ran")
	}
}
