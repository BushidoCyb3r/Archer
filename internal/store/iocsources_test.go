package store

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/feeds"
)

func TestIOCSources_OperatorOnly(t *testing.T) {
	s := newTestStore(t)
	s.SetIOCList([]string{"203.0.113.10", "10.0.0.0/8"})

	got := s.IOCSources()
	if len(got) != 1 {
		t.Fatalf("expected 1 source (operator only), got %d", len(got))
	}
	if got[0].Source != "Operator IOC list" {
		t.Errorf("source = %q, want %q", got[0].Source, "Operator IOC list")
	}
	if !got[0].Matcher.Matches("203.0.113.10") {
		t.Errorf("operator matcher should match 203.0.113.10")
	}
	if !got[0].Matcher.Matches("10.5.6.7") {
		t.Errorf("operator matcher should match 10.5.6.7 via 10.0.0.0/8")
	}
}

func TestIOCSources_IncludesEnabledFeedsOnly(t *testing.T) {
	s := newTestStore(t)
	s.SetIOCList([]string{"1.1.1.1"})

	enabledID, _ := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "enabled-feed", URL: "x",
		RefreshCadenceMinutes: 60, Enabled: true,
	})
	disabledID, _ := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "disabled-feed", URL: "y",
		RefreshCadenceMinutes: 60, Enabled: false,
	})

	_, _, _ = s.UpsertFeedIndicators(enabledID, []feeds.Indicator{
		{Indicator: "203.0.113.20", Type: feeds.IndicatorIP, SourceID: "e1"},
	}, 1000)
	_, _, _ = s.UpsertFeedIndicators(disabledID, []feeds.Indicator{
		{Indicator: "203.0.113.30", Type: feeds.IndicatorIP, SourceID: "d1"},
	}, 1000)

	got := s.IOCSources()
	if len(got) != 2 {
		t.Fatalf("expected 2 sources (operator + enabled feed), got %d: %+v", len(got), sourcesNames(got))
	}
	if got[0].Source != "Operator IOC list" {
		t.Errorf("first source = %q, want %q", got[0].Source, "Operator IOC list")
	}
	if got[1].Source != "Feed: enabled-feed" {
		t.Errorf("second source = %q, want %q", got[1].Source, "Feed: enabled-feed")
	}

	if got[1].Matcher.Matches("203.0.113.30") {
		t.Errorf("disabled feed indicator must not match through any source")
	}
	if !got[1].Matcher.Matches("203.0.113.20") {
		t.Errorf("enabled feed indicator should match through its source")
	}
}

func TestIOCSources_FeedMatcherInvalidatesOnUpsert(t *testing.T) {
	s := newTestStore(t)
	id, _ := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f", URL: "x",
		RefreshCadenceMinutes: 60, Enabled: true,
	})

	// First snapshot: 1.2.3.4 only.
	_, _, _ = s.UpsertFeedIndicators(id, []feeds.Indicator{
		{Indicator: "1.2.3.4", Type: feeds.IndicatorIP},
	}, 1000)
	got := s.IOCSources()
	if !got[1].Matcher.Matches("1.2.3.4") || got[1].Matcher.Matches("5.6.7.8") {
		t.Fatalf("expected snapshot 1: 1.2.3.4 matches, 5.6.7.8 does not")
	}

	// Second snapshot: only 5.6.7.8 — 1.2.3.4 ages out below.
	_, _, _ = s.UpsertFeedIndicators(id, []feeds.Indicator{
		{Indicator: "5.6.7.8", Type: feeds.IndicatorIP},
	}, 2000)
	_, _ = s.RemoveStaleIndicators(id, 1500)

	got = s.IOCSources()
	if got[1].Matcher.Matches("1.2.3.4") {
		t.Errorf("matcher cache wasn't invalidated: 1.2.3.4 still matches after prune")
	}
	if !got[1].Matcher.Matches("5.6.7.8") {
		t.Errorf("matcher missing the new indicator 5.6.7.8")
	}
}

func TestIOCSources_FeedMatcherDropsOnDelete(t *testing.T) {
	s := newTestStore(t)
	id, _ := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f", URL: "x",
		RefreshCadenceMinutes: 60, Enabled: true,
	})
	_, _, _ = s.UpsertFeedIndicators(id, []feeds.Indicator{
		{Indicator: "9.9.9.9", Type: feeds.IndicatorIP},
	}, 1000)

	if got := s.IOCSources(); len(got) != 2 {
		t.Fatalf("setup: expected 2 sources, got %d", len(got))
	}

	if err := s.DeleteFeed(id); err != nil {
		t.Fatalf("DeleteFeed: %v", err)
	}

	got := s.IOCSources()
	if len(got) != 1 {
		t.Fatalf("expected 1 source after delete (operator only), got %d", len(got))
	}
}

func sourcesNames(sources []SourcedMatcher) []string {
	out := make([]string, 0, len(sources))
	for _, sm := range sources {
		out = append(out, sm.Source)
	}
	return out
}
