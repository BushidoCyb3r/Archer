package store

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
)

// newTestStore returns a Store wired to a fresh in-memory SQLite DB
// with all migrations applied. Mirrors what NewUserStore does for
// users.db in production.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	db := openTestDB(t)
	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)
	return s
}

func TestFeedCRUD(t *testing.T) {
	s := newTestStore(t)

	id, err := s.CreateFeed(feeds.Feed{
		SourceType:            feeds.SourceMISP,
		Name:                  "test-misp",
		URL:                   "https://misp.example.test",
		APIKey:                "key",
		RefreshCadenceMinutes: 60,
		IndicatorAgingDays:    30,
		Enabled:               true,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	if id == 0 {
		t.Fatalf("expected non-zero feed id")
	}

	got, err := s.GetFeed(id)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if got.Name != "test-misp" || got.SourceType != feeds.SourceMISP || !got.Enabled {
		t.Errorf("GetFeed mismatch: %+v", got)
	}

	got.LastIndicatorCount = 42
	got.Status = "ok"
	got.LastRefreshAt = 1234567890
	if err := s.UpdateFeed(got); err != nil {
		t.Fatalf("UpdateFeed: %v", err)
	}
	again, _ := s.GetFeed(id)
	if again.LastIndicatorCount != 42 || again.Status != "ok" || again.LastRefreshAt != 1234567890 {
		t.Errorf("UpdateFeed didn't persist: %+v", again)
	}

	all := s.ListFeeds()
	if len(all) != 1 || all[0].ID != id {
		t.Errorf("ListFeeds returned %+v", all)
	}

	if err := s.DeleteFeed(id); err != nil {
		t.Fatalf("DeleteFeed: %v", err)
	}
	if all := s.ListFeeds(); len(all) != 0 {
		t.Errorf("expected empty list after delete, got %+v", all)
	}
}

func TestFeedIndicators_UpsertAndPrune(t *testing.T) {
	s := newTestStore(t)

	id, err := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f1", URL: "x",
		RefreshCadenceMinutes: 60, IndicatorAgingDays: 30,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}

	first := []feeds.Indicator{
		{Indicator: "203.0.113.1", Type: feeds.IndicatorIP, SourceID: "s1", Tags: []string{"tlp:white"}},
		{Indicator: "evil.test", Type: feeds.IndicatorDomain, SourceID: "s2"},
	}
	added, refreshed, err := s.UpsertFeedIndicators(id, first, 1000)
	if err != nil {
		t.Fatalf("UpsertFeedIndicators: %v", err)
	}
	if added != 2 || refreshed != 0 {
		t.Errorf("first upsert added=%d refreshed=%d, want 2/0", added, refreshed)
	}

	second := []feeds.Indicator{
		// Re-observe with the same tags — upstream is the source of
		// truth for tags, so the upsert path overwrites them. Pass
		// the same set so this acts as a refresh, not a tag deletion.
		{Indicator: "203.0.113.1", Type: feeds.IndicatorIP, SourceID: "s1", Tags: []string{"tlp:white"}},
		{Indicator: "10.0.0.0/8", Type: feeds.IndicatorCIDR, SourceID: "s3"}, // new
	}
	added, refreshed, err = s.UpsertFeedIndicators(id, second, 2000)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if added != 1 || refreshed != 1 {
		t.Errorf("second upsert added=%d refreshed=%d, want 1/1", added, refreshed)
	}

	// Pruning at cutoff=1500 should drop only "evil.test" (last_seen=1000).
	// 203.0.113.1 last_seen bumped to 2000, 10.0.0.0/8 inserted at 2000.
	removed, err := s.RemoveStaleIndicators(id, 1500)
	if err != nil {
		t.Fatalf("RemoveStaleIndicators: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed=%d, want 1", removed)
	}

	got := s.ListFeedIndicators(id)
	if len(got) != 2 {
		t.Errorf("post-prune: got %d indicators, want 2: %+v", len(got), got)
	}

	// Tags round-trip on the surviving 203.0.113.1.
	for _, ind := range got {
		if ind.Indicator == "203.0.113.1" {
			if len(ind.Tags) != 1 || ind.Tags[0] != "tlp:white" {
				t.Errorf("tags didn't round-trip: %v", ind.Tags)
			}
		}
	}
}

func TestFeedDelete_CascadesIndicators(t *testing.T) {
	s := newTestStore(t)

	id, _ := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f1", URL: "x",
		RefreshCadenceMinutes: 60,
	})
	_, _, _ = s.UpsertFeedIndicators(id, []feeds.Indicator{
		{Indicator: "1.2.3.4", Type: feeds.IndicatorIP},
	}, 100)

	if got := s.ListFeedIndicators(id); len(got) != 1 {
		t.Fatalf("setup: expected 1 indicator, got %d", len(got))
	}

	if err := s.DeleteFeed(id); err != nil {
		t.Fatalf("DeleteFeed: %v", err)
	}

	if got := s.ListFeedIndicators(id); len(got) != 0 {
		t.Errorf("indicators not cascaded on feed delete: %+v", got)
	}
}
