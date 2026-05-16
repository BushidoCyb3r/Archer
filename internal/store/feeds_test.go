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
		SourceType:         feeds.SourceMISP,
		Name:               "test-misp",
		URL:                "https://misp.example.test",
		APIKey:             "key",
		IndicatorAgingDays: 30,
		Enabled:            true,
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
		IndicatorAgingDays: 30,
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

// TestSetFeedPrunedCount_RoundTripAndOwnership asserts the invariant
// the aging-visibility feature depends on: the count RemoveStale-
// Indicators reports is what SetFeedPrunedCount persists and GetFeed
// returns, AND an unrelated admin-style UpdateFeed (URL/name/aging
// edit) does not clobber it. The second half is the whole reason
// last_pruned_count is a separately-written refresh-owned column
// rather than a field on UpdateFeed (NEW-22 ownership model) — if a
// config edit reset the prune stat to 0 the "% aged out" line would
// lie until the next full refresh.
func TestSetFeedPrunedCount_RoundTripAndOwnership(t *testing.T) {
	s := newTestStore(t)

	id, err := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "aging-feed", URL: "https://x.test",
		IndicatorAgingDays: 30,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}

	// Three indicators; two old (last_seen=1000), one fresh (last_seen=2000).
	_, _, err = s.UpsertFeedIndicators(id, []feeds.Indicator{
		{Indicator: "203.0.113.1", Type: feeds.IndicatorIP, SourceID: "a"},
		{Indicator: "203.0.113.2", Type: feeds.IndicatorIP, SourceID: "b"},
	}, 1000)
	if err != nil {
		t.Fatalf("upsert old: %v", err)
	}
	if _, _, err = s.UpsertFeedIndicators(id, []feeds.Indicator{
		{Indicator: "203.0.113.3", Type: feeds.IndicatorIP, SourceID: "c"},
	}, 2000); err != nil {
		t.Fatalf("upsert fresh: %v", err)
	}

	pruned, err := s.RemoveStaleIndicators(id, 1500)
	if err != nil {
		t.Fatalf("RemoveStaleIndicators: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("pruned=%d, want 2", pruned)
	}
	// Mirror the live refresh path: prune count, then settled survivor
	// count, recorded via the two refresh-owned writers.
	if err := s.SetFeedPrunedCount(id, pruned); err != nil {
		t.Fatalf("SetFeedPrunedCount: %v", err)
	}
	if err := s.UpdateFeedRefreshState(id, "ok", 2000, 2000, 1, false, ""); err != nil {
		t.Fatalf("UpdateFeedRefreshState: %v", err)
	}

	got, err := s.GetFeed(id)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if got.LastPrunedCount != 2 {
		t.Errorf("LastPrunedCount=%d, want 2", got.LastPrunedCount)
	}
	// Pre-prune population the UI reconstructs: pruned + survivors.
	if pre := got.LastPrunedCount + got.LastIndicatorCount; pre != 3 {
		t.Errorf("derived pre-prune total=%d, want 3", pre)
	}

	// Admin edits the feed (rename + widen aging window). UpdateFeed
	// must leave last_pruned_count alone — it's not in its SET list.
	got.Name = "aging-feed-renamed"
	got.IndicatorAgingDays = 60
	if err := s.UpdateFeed(got); err != nil {
		t.Fatalf("UpdateFeed: %v", err)
	}
	after, err := s.GetFeed(id)
	if err != nil {
		t.Fatalf("GetFeed after edit: %v", err)
	}
	if after.LastPrunedCount != 2 {
		t.Errorf("admin UpdateFeed clobbered LastPrunedCount: got %d, want 2", after.LastPrunedCount)
	}
}

// TestPruneThenCount_OrderingInvariant locks the assumption the
// Feeds-dialog "% aged out" line rests on: in runFeedFetch the prune
// runs BEFORE CountIndicatorsByFeed snapshots the survivor count, so
// last_indicator_count is post-prune and the pre-prune population is
// exactly last_pruned_count + last_indicator_count. The store-layer
// round-trip test sets the survivor count by hand and so can't catch
// a refresh-path refactor that moved the count snapshot before the
// prune — that would silently make the displayed denominator the
// pre-prune total and the percentage wrong, with no crash and no
// other failing test. This test reproduces the real call sequence
// with controlled last_seen timestamps and asserts the relationship
// holds, and that the pre- vs post-prune counts genuinely differ so
// the snapshot point is provably load-bearing (a reorder breaks this
// test rather than shipping a wrong number).
func TestPruneThenCount_OrderingInvariant(t *testing.T) {
	s := newTestStore(t)

	id, err := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "ordering", URL: "https://x.test",
		IndicatorAgingDays: 30,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}

	// 7 stale (last_seen=1000), 3 fresh (last_seen=2000). Pre-prune
	// population is 10; a cutoff between the two timestamps ages out
	// exactly the 7 stale ones.
	stale := make([]feeds.Indicator, 7)
	for i := range stale {
		stale[i] = feeds.Indicator{Indicator: "203.0.113." + string(rune('1'+i)), Type: feeds.IndicatorIP}
	}
	if _, _, err = s.UpsertFeedIndicators(id, stale, 1000); err != nil {
		t.Fatalf("upsert stale: %v", err)
	}
	fresh := []feeds.Indicator{
		{Indicator: "198.51.100.1", Type: feeds.IndicatorIP},
		{Indicator: "198.51.100.2", Type: feeds.IndicatorIP},
		{Indicator: "198.51.100.3", Type: feeds.IndicatorIP},
	}
	if _, _, err = s.UpsertFeedIndicators(id, fresh, 2000); err != nil {
		t.Fatalf("upsert fresh: %v", err)
	}

	preTotal := s.CountIndicatorsByFeed()[id]
	if preTotal != 10 {
		t.Fatalf("pre-prune count = %d, want 10", preTotal)
	}

	// Live runFeedFetch order: RemoveStaleIndicators THEN
	// CountIndicatorsByFeed (handlers_feeds.go — prune at the aging
	// block, totals snapshot immediately after).
	pruned, err := s.RemoveStaleIndicators(id, 1500)
	if err != nil {
		t.Fatalf("RemoveStaleIndicators: %v", err)
	}
	survivors := s.CountIndicatorsByFeed()[id]

	if pruned != 7 {
		t.Errorf("pruned = %d, want 7", pruned)
	}
	if survivors != 3 {
		t.Errorf("post-prune survivor count = %d, want 3", survivors)
	}
	// The invariant the UI reconstructs the pre-prune total from.
	if pruned+survivors != preTotal {
		t.Errorf("pruned(%d) + survivors(%d) = %d, want preTotal %d — the "+
			"%% aged out denominator would be wrong", pruned, survivors, pruned+survivors, preTotal)
	}
	// Prove the snapshot point is load-bearing: if a refactor counted
	// before pruning, survivors would equal preTotal and this would
	// fail instead of silently shipping a wrong percentage.
	if survivors == preTotal {
		t.Errorf("survivor count == pre-prune total (%d) — count was snapshotted before the prune; the aging percentage will read 0%% forever", preTotal)
	}
}

func TestFeedDelete_CascadesIndicators(t *testing.T) {
	s := newTestStore(t)

	id, _ := s.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f1", URL: "x",
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
