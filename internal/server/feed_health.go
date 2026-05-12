package server

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/feeds"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Feed reliability alarm — a silently failing feed only surfaces if
// an operator opens the Feeds dialog. This loop watches the feeds
// table for two unhealthy signals and emits a Kind=feed notification
// when either crosses:
//
//   1. consecutive_failures >= feedFailureStreakThreshold (3 by
//      default). Set in UpdateFeedRefreshState as the refresh worker
//      records each cycle's outcome.
//   2. last_refresh_at > 0 AND now - last_refresh_at >= feedStaleThreshold
//      (24h). Catches the case where the refresh path isn't running
//      at all — the failure counter wouldn't be incrementing because
//      no fetch is being attempted.
//
// Disabled feeds and feeds that have never refreshed (last_refresh_at == 0)
// are skipped. The dedup pattern matches sensor_heartbeat.go: an
// in-memory map of currently-alerting feed names so the loop emits
// only on the healthy → unhealthy transition.

const (
	feedFailureStreakThreshold = 3
	feedStaleThreshold         = 24 * time.Hour
	feedHealthCheckInterval    = 5 * time.Minute
)

// startFeedHealthLoop kicks off the feed-reliability watcher. Runs
// once at startup then on the check interval forever.
func (s *Server) startFeedHealthLoop() {
	active := make(map[string]bool)
	var mu sync.Mutex

	go func() {
		s.scanFeedHealth(active, &mu)
		t := time.NewTicker(feedHealthCheckInterval)
		defer t.Stop()
		for range t.C {
			s.scanFeedHealth(active, &mu)
		}
	}()
}

// scanFeedHealth walks every configured feed, emits alarms for feeds
// that newly meet either unhealthy criterion, and clears the active
// flag for feeds that have recovered. The reason string baked into
// the alarm Detail tells the operator which condition fired so they
// can decide whether to investigate the upstream or restart the
// refresh.
func (s *Server) scanFeedHealth(active map[string]bool, mu *sync.Mutex) {
	allFeeds := s.store.ListFeeds()
	now := time.Now().Unix()
	staleSec := int64(feedStaleThreshold.Seconds())

	mu.Lock()
	defer mu.Unlock()

	stillUnhealthy := make(map[string]bool, len(active))
	for _, f := range allFeeds {
		if !f.Enabled {
			continue
		}
		reason, unhealthy := evaluateFeedHealth(f, now, staleSec)
		if !unhealthy {
			continue
		}
		stillUnhealthy[f.Name] = true
		if active[f.Name] {
			continue
		}
		alarm := model.Notification{
			Kind:     "feed",
			Target:   f.Name,
			Severity: string(model.SevHigh),
			Type:     "Feed unhealthy",
			Detail:   "Feed " + f.Name + ": " + reason,
		}
		n := s.store.AddAlarm(alarm)
		if data, err := json.Marshal(n); err == nil {
			s.broker.Publish(SSEEvent{Type: "notification", Data: string(data)})
		}
		active[f.Name] = true
	}

	for name := range active {
		if !stillUnhealthy[name] {
			delete(active, name)
		}
	}
}

// evaluateFeedHealth applies the two unhealthy criteria and returns
// the human-readable reason (or "" if healthy). The streak check has
// precedence over the staleness check — a feed that's both
// chronically failing AND not recently refreshed gets the more-
// specific failure-count message.
func evaluateFeedHealth(f feeds.Feed, now, staleSec int64) (string, bool) {
	if f.ConsecutiveFailures >= feedFailureStreakThreshold {
		return strconv.Itoa(f.ConsecutiveFailures) + " consecutive refresh failures (last error: " + truncate(f.LastError, 120) + ")", true
	}
	if f.LastRefreshAt > 0 && now-f.LastRefreshAt >= staleSec {
		age := now - f.LastRefreshAt
		return "no successful refresh in " + humanDuration(age), true
	}
	return "", false
}

// truncate clips a string at n runes with a trailing "…" so the
// alarm Detail line in the bell panel doesn't blow up on multi-line
// upstream error blobs (curl's full TLS handshake transcript, for
// instance). n is a byte budget rather than a rune count — the
// detail is rendered in a fixed-width panel and bytes ≈ visual
// width for the ASCII the adapter errors emit.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
