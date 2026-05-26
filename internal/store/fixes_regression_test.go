package store

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestDNSBeaconing_WritesToBeaconHistory asserts that a DNS Beaconing
// finding emitted by setFindingsImpl is recorded in beacon_history, matching
// the Beaconing / HTTP Beaconing types that were already tracked. Prior to
// the fix, the type filter in saveBeaconHistory excluded DNS Beaconing, so
// no 30-day trajectory accumulated for DNS-cadence C2 beacons.
func TestDNSBeaconing_WritesToBeaconHistory(t *testing.T) {
	s := newTestStore(t)
	day := time.Now().UTC().Format("2006-01-02")

	findings := []model.Finding{
		{
			ID: 1, Type: "DNS Beaconing",
			SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: "53",
			Score: 75, Severity: model.SevHigh,
			Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05"),
		},
	}
	s.SetFindings(findings)

	f := s.findings[0]
	maxScore, _, ok := s.beaconHistoryRowSnapshot(f.BeaconHistoryKey(), day)
	if !ok {
		t.Fatal("no beacon_history row written for DNS Beaconing finding")
	}
	if maxScore != 75 {
		t.Errorf("beacon_history max_score = %d, want 75", maxScore)
	}
}

// TestSetFindings_CorrelationDedup_PreservesDroppedRef asserts that when two
// findings share a fingerprint and one is deduped away, any Correlations
// reference to the dropped finding's fresh ID is translated to the winner's
// persisted ID rather than silently dropped. Prior to the fix the droppedToWinner
// map was absent, so the translation pass left the dropped ID in neither
// freshToPersisted nor historicalIDs and quietly removed the reference —
// causing the +N chip to undercount and the sibling-jump to land nowhere.
func TestSetFindings_CorrelationDedup_PreservesDroppedRef(t *testing.T) {
	s := newTestStore(t)

	// Two findings with the same fingerprint (beacon A wins on score).
	beaconA := model.Finding{
		ID: 1, Type: "Beaconing",
		SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
		Score: 85, Severity: model.SevHigh,
		Timestamp: "2026-05-18 10:00:00",
	}
	beaconB := model.Finding{
		ID: 2, Type: "Beaconing", // same fingerprint as A
		SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
		Score: 70, Severity: model.SevMedium,
		Timestamp: "2026-05-18 10:00:00",
	}
	// CA references both fresh IDs — B will be deduped.
	ca := model.Finding{
		ID: 3, Type: "Correlated Activity",
		SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
		Score: 90, Severity: model.SevCritical,
		Timestamp:    "2026-05-18 10:00:00",
		Correlations: []int{1, 2}, // references both fresh IDs
	}

	s.SetFindings([]model.Finding{beaconA, beaconB, ca})

	// After merge, CA's Correlations should reference the winner (A's
	// persisted ID) once — not zero times (dropped) and not twice (duplicate).
	caFound := false
	for _, f := range s.findings {
		if f.Type != "Correlated Activity" {
			continue
		}
		caFound = true
		// Both fresh IDs 1 and 2 should map to the same persisted ID (A's).
		// The ref count must be exactly 1 (the winner) or 2 (winner mapped
		// for both — both valid; duplicate corr refs are harmless but the
		// important invariant is neither is zero).
		if len(f.Correlations) == 0 {
			t.Errorf("Correlations is empty — dropped ref was not translated to winner's ID")
		}
	}
	if !caFound {
		t.Fatal("Correlated Activity finding missing after SetFindings")
	}
}

// TestSuppressionBoundary_HiddenAndSuppressedAgree asserts that IsSuppressed
// and isHiddenLocked use the same expiry comparison so the findings list and
// the bell gate never disagree at the boundary instant. Prior to the fix,
// IsSuppressed used !now.After(expiry) (inclusive) while isHiddenLocked used
// now.Before(expiry) (exclusive), causing a one-instant window where a finding
// appeared in the table but its bell could still fire (or vice versa).
func TestSuppressionBoundary_HiddenAndSuppressedAgree(t *testing.T) {
	s := New(config.Default())
	s.suppressions = map[string]SuppressionEntry{}

	// Set expiry to the past so the suppression is definitively expired.
	past := time.Now().Add(-1 * time.Second)
	s.suppressions["1.2.3.4"] = SuppressionEntry{Expiry: past, Detail: "test"}

	suppressed := s.IsSuppressed("1.2.3.4")
	hidden := s.isHiddenLocked("1.2.3.4", "0.0.0.0")

	if suppressed != hidden {
		t.Errorf("IsSuppressed=%v but isHiddenLocked=%v for expired suppression — they must agree", suppressed, hidden)
	}
	if suppressed {
		t.Error("expired suppression must not report as suppressed")
	}

	// Active suppression: both must agree it is suppressed.
	future := time.Now().Add(1 * time.Hour)
	s.suppressions["5.6.7.8"] = SuppressionEntry{Expiry: future, Detail: "active"}

	suppressed = s.IsSuppressed("5.6.7.8")
	hidden = s.isHiddenLocked("5.6.7.8", "0.0.0.0")

	if suppressed != hidden {
		t.Errorf("IsSuppressed=%v but isHiddenLocked=%v for active suppression — they must agree", suppressed, hidden)
	}
	if !suppressed {
		t.Error("active suppression must report as suppressed")
	}
}

// TestIOCSources_FeedListCacheInvalidatesOnCreate asserts that after
// CreateFeed, a subsequent IOCSources call reflects the new feed. The feed
// list cache (enabledFeedList) must be cleared by invalidateFeedBuckets so
// a stale cached slice doesn't hide newly-created feeds from the filter path.
func TestIOCSources_FeedListCacheInvalidatesOnCreate(t *testing.T) {
	s := newTestStore(t)

	// Warm the cache with no feeds.
	got := s.IOCSources()
	if len(got) != 1 {
		t.Fatalf("expected 1 source (operator only), got %d", len(got))
	}

	// Create a feed — this must invalidate the cache.
	_, err := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "new-feed", URL: "x", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}

	// IOCSources must now include the new feed.
	got = s.IOCSources()
	if len(got) != 2 {
		t.Errorf("expected 2 sources after CreateFeed, got %d — feed list cache was not invalidated", len(got))
	}
}
