package server

import (
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/BushidoCyb3r/Archer/internal/feeds"
)

// TestFeedHealth_AlarmsOnFailureStreak codifies the invariant: a
// feed with consecutive_failures >= feedFailureStreakThreshold emits
// exactly one alarm per unhealthy episode (transition-edge dedup
// matches the sensor heartbeat pattern).
func TestFeedHealth_AlarmsOnFailureStreak(t *testing.T) {
	s := newAuditTestServer(t)
	id := mustCreateFeed(t, s, "misp-prod", true)

	// Three back-to-back error refreshes → consecutive_failures = 3.
	for i := 0; i < 3; i++ {
		if err := s.store.UpdateFeedRefreshState(id, "error",
			time.Now().Unix(), 0, 0, false, "upstream 500"); err != nil {
			t.Fatalf("UpdateFeedRefreshState (error %d): %v", i, err)
		}
	}
	feed, err := s.store.GetFeed(id)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if feed.ConsecutiveFailures != 3 {
		t.Fatalf("ConsecutiveFailures = %d, want 3 (one increment per error)", feed.ConsecutiveFailures)
	}

	active := make(map[string]bool)
	var mu sync.Mutex
	s.scanFeedHealth(active, &mu)
	notifs := s.store.GetNotifications()
	if len(notifs) != 1 {
		t.Fatalf("first scan emitted %d notifications, want 1; got %+v", len(notifs), notifs)
	}
	if notifs[0].Kind != "feed" || notifs[0].Target != "misp-prod" {
		t.Errorf("notification = %+v; want Kind=feed Target=misp-prod", notifs[0])
	}
	if notifs[0].Type != "Feed unhealthy" {
		t.Errorf("notification Type = %q, want Feed unhealthy", notifs[0].Type)
	}

	// Second scan: dedup — no new alarm even though feed is still failing.
	s.scanFeedHealth(active, &mu)
	if got := len(s.store.GetNotifications()); got != 1 {
		t.Errorf("duplicate alarm on second scan; total = %d, want 1", got)
	}

	// Successful refresh resets the counter — the feed becomes healthy,
	// the active flag clears, and a subsequent streak fires a fresh
	// alarm.
	if err := s.store.UpdateFeedRefreshState(id, "ok",
		time.Now().Unix(), time.Now().Unix(), 100, false, ""); err != nil {
		t.Fatalf("UpdateFeedRefreshState (recover): %v", err)
	}
	feed, _ = s.store.GetFeed(id)
	if feed.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after successful refresh, want 0", feed.ConsecutiveFailures)
	}
	s.scanFeedHealth(active, &mu)
	if active["misp-prod"] {
		t.Error("active['misp-prod'] still set after recovery")
	}
	// Three more failures → fresh episode → second alarm.
	for i := 0; i < 3; i++ {
		_ = s.store.UpdateFeedRefreshState(id, "error",
			time.Now().Unix(), 0, 0, false, "upstream 502")
	}
	s.scanFeedHealth(active, &mu)
	if got := len(s.store.GetNotifications()); got != 2 {
		t.Errorf("re-failure episode didn't fire fresh alarm; total = %d, want 2", got)
	}
}

// TestFeedHealth_AlarmsOnStaleness verifies the second unhealthy
// criterion: even with consecutive_failures == 0, a feed that hasn't
// refreshed in > 24h gets an alarm. This catches the case where the
// refresh path is silently not running (no errors *because* no
// fetches are being attempted).
func TestFeedHealth_AlarmsOnStaleness(t *testing.T) {
	s := newAuditTestServer(t)
	id := mustCreateFeed(t, s, "opencti-stale", true)
	// Last successful refresh 30h ago, no failure streak.
	stale := time.Now().Unix() - int64(30*time.Hour.Seconds())
	if err := s.store.UpdateFeedRefreshState(id, "ok", stale, stale, 100, false, ""); err != nil {
		t.Fatalf("UpdateFeedRefreshState: %v", err)
	}

	active := make(map[string]bool)
	var mu sync.Mutex
	s.scanFeedHealth(active, &mu)
	notifs := s.store.GetNotifications()
	if len(notifs) != 1 {
		t.Fatalf("expected 1 staleness alarm; got %d (notifs=%+v)", len(notifs), notifs)
	}
	if notifs[0].Target != "opencti-stale" {
		t.Errorf("notification Target = %q, want opencti-stale", notifs[0].Target)
	}
}

// TestFeedHealth_DisabledFeedDoesNotAlarm verifies an explicitly
// disabled feed never alarms regardless of failure count or
// staleness — the operator already knows that feed isn't running.
func TestFeedHealth_DisabledFeedDoesNotAlarm(t *testing.T) {
	s := newAuditTestServer(t)
	id := mustCreateFeed(t, s, "misp-disabled", false)
	for i := 0; i < 5; i++ {
		_ = s.store.UpdateFeedRefreshState(id, "error",
			time.Now().Unix(), 0, 0, false, "old failure")
	}
	active := make(map[string]bool)
	var mu sync.Mutex
	s.scanFeedHealth(active, &mu)
	if got := len(s.store.GetNotifications()); got != 0 {
		t.Errorf("disabled feed alarmed; got %d notifications, want 0", got)
	}
}

// TestUpdateFeedRefreshState_StreakSemantics verifies the SQL
// CASE-WHEN: error increments, ok resets, transient statuses
// preserve. (The "fetching" path uses UpdateFeedStatus and
// shouldn't reach this method, but the CASE-WHEN's ELSE branch
// guarantees the counter stays intact if it ever did.)
func TestUpdateFeedRefreshState_StreakSemantics(t *testing.T) {
	s := newAuditTestServer(t)
	id := mustCreateFeed(t, s, "misp-streak", true)

	steps := []struct {
		status string
		want   int
		label  string
	}{
		{"error", 1, "first error"},
		{"error", 2, "second error"},
		{"error", 3, "third error"},
		{"ok", 0, "successful recovery"},
		{"error", 1, "post-recovery error"},
		{"ok", 0, "second recovery"},
	}
	for _, step := range steps {
		var lastErr string
		if step.status == "error" {
			lastErr = step.label
		}
		if err := s.store.UpdateFeedRefreshState(id, step.status,
			time.Now().Unix(), 0, 0, false, lastErr); err != nil {
			t.Fatalf("step %q: %v", step.label, err)
		}
		feed, err := s.store.GetFeed(id)
		if err != nil {
			t.Fatalf("GetFeed after %q: %v", step.label, err)
		}
		if feed.ConsecutiveFailures != step.want {
			t.Errorf("after %q: ConsecutiveFailures = %d, want %d", step.label, feed.ConsecutiveFailures, step.want)
		}
	}
}

// TestTruncate_RespectsUTF8RuneBoundary codifies NEW-101. The
// invariant: truncate's output is always valid UTF-8, regardless
// of where the byte cap falls relative to multi-byte UTF-8
// sequences in the input. Pre-fix a cap that landed mid-multi-byte
// sequence emitted invalid UTF-8 bytes; json.Marshal escaped them
// as � on the wire and the SPA rendered the replacement
// character.
//
// We articulate the invariant ("output is always valid UTF-8")
// rather than the failure case ("em-dash at byte 2"). The test
// sweeps cap values across a multi-byte string so every interior
// rune-mid byte is exercised.
func TestTruncate_RespectsUTF8RuneBoundary(t *testing.T) {
	// "—" is U+2014 (em-dash), 3 bytes in UTF-8 (E2 80 94). "→" is
	// U+2192, also 3 bytes. The string has ASCII prefixes/suffixes
	// around each so a sweep across cap values lands inside and
	// outside multi-byte sequences.
	s := "unauthorized: token expired — refresh → retry"

	for cap := 1; cap < len(s); cap++ {
		got := truncate(s, cap)
		if !utf8.ValidString(got) {
			t.Errorf("truncate(s, %d) = %q is not valid UTF-8 (pre-fix would emit a partial multi-byte sequence here)", cap, got)
		}
	}

	// Belt-and-suspenders: cap >= len(s) returns the input unchanged.
	if got := truncate(s, len(s)); got != s {
		t.Errorf("cap >= len: got %q, want %q", got, s)
	}
	if got := truncate(s, len(s)+50); got != s {
		t.Errorf("cap > len: got %q, want %q", got, s)
	}

	// The original failure shape from the audit narrative: a 3-byte
	// em-dash starting at a known offset, cap landing on byte 2 of
	// that sequence. Result must contain only the ASCII prefix +
	// the trailing ellipsis, with no garbage codepoint.
	prefix := "abc"
	em := "—" // 3 bytes
	suffix := "xyz"
	test := prefix + em + suffix
	emByte0 := len(prefix)
	got := truncate(test, emByte0+2) // land on byte 2 of em-dash
	if !utf8.ValidString(got) {
		t.Fatalf("mid-em-dash truncate produced invalid UTF-8: %q", got)
	}
	// The output should end with the ellipsis and not contain any
	// fragment of the em-dash bytes.
	if got[len(got)-len("…"):] != "…" {
		t.Errorf("expected trailing ellipsis; got %q", got)
	}
}

func mustCreateFeed(t *testing.T, s *Server, name string, enabled bool) int64 {
	t.Helper()
	id, err := s.store.CreateFeed(feeds.Feed{
		SourceType:         feeds.SourceMISP,
		Name:               name,
		URL:                "https://misp.test/events/restSearch",
		APIKey:             "k",
		IndicatorAgingDays: 30,
		Enabled:            enabled,
	})
	if err != nil {
		t.Fatalf("CreateFeed(%s): %v", name, err)
	}
	return id
}
