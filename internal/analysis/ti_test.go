package analysis

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

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
