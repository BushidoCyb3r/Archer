package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/feeds"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// feedResponse is the wire shape for /api/feeds responses. Mirrors
// feeds.Feed but deliberately omits APIKey — secrets are write-only.
// Operators send API keys via POST/PUT bodies; the GET path never
// echoes them back, so a stolen session cookie can't be used to
// scrape feed credentials.
type feedResponse struct {
	ID                 int64  `json:"id"`
	SourceType         string `json:"source_type"`
	Name               string `json:"name"`
	URL                string `json:"url"`
	IndicatorAgingDays int    `json:"indicator_aging_days"`
	LastRefreshAt      int64  `json:"last_refresh_at"`
	// LastFullRefreshAt is the most recent full pull (incrementals
	// don't update it). UI renders it as a tooltip on the refresh-
	// time cell so operators can tell which fetches were cheap
	// incrementals vs the periodic deep sync.
	LastFullRefreshAt  int64 `json:"last_full_refresh_at"`
	LastIndicatorCount int   `json:"last_indicator_count"`
	// LiveIndicatorCount is the current row count in feed_indicators
	// for this feed, computed at request time. Equals LastIndicatorCount
	// when a fetch has settled; climbs visibly during a fetch while
	// status="fetching" so operators see progress on slow MISP imports
	// instead of staring at a yellow status pill for several minutes.
	LiveIndicatorCount int    `json:"live_indicator_count"`
	LastFetchTruncated bool   `json:"last_fetch_truncated"`
	LastError          string `json:"last_error,omitempty"`
	Status             string `json:"status"`
	Enabled            bool   `json:"enabled"`
	TLSSkipVerify      bool   `json:"tls_skip_verify"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
	HasAPIKey          bool   `json:"has_api_key"`
}

func toFeedResponse(f feeds.Feed) feedResponse {
	return feedResponse{
		ID:                 f.ID,
		SourceType:         string(f.SourceType),
		Name:               f.Name,
		URL:                f.URL,
		IndicatorAgingDays: f.IndicatorAgingDays,
		LastRefreshAt:      f.LastRefreshAt,
		LastFullRefreshAt:  f.LastFullRefreshAt,
		LastIndicatorCount: f.LastIndicatorCount,
		LastFetchTruncated: f.LastFetchTruncated,
		LastError:          f.LastError,
		Status:             f.Status,
		Enabled:            f.Enabled,
		TLSSkipVerify:      f.TLSSkipVerify,
		CreatedAt:          f.CreatedAt,
		UpdatedAt:          f.UpdatedAt,
		HasAPIKey:          f.APIKey != "",
	}
}

// feedRequest is the wire shape POST/PUT accepts. APIKey is the only
// write-only field; an empty string in PUT means "keep the existing
// key", not "clear it" — clearing requires a separate PUT with the
// caller explicitly setting it. This avoids the foot-gun where an
// admin re-saves a feed config without the api_key field and
// accidentally blanks out their secret.
type feedRequest struct {
	SourceType         string `json:"source_type"`
	Name               string `json:"name"`
	URL                string `json:"url"`
	APIKey             string `json:"api_key"`
	IndicatorAgingDays int    `json:"indicator_aging_days"`
	Enabled            bool   `json:"enabled"`
	TLSSkipVerify      bool   `json:"tls_skip_verify"`
}

// handleFeeds dispatches GET (list) and POST (create) on /api/feeds.
// GET is open to any authenticated user (read-only visibility into
// what feeds are configured). POST is admin-only — adding a feed
// changes detection-input surface.
func (s *Server) handleFeeds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		all := s.store.ListFeeds()
		counts := s.store.CountIndicatorsByFeed()
		out := make([]feedResponse, 0, len(all))
		for _, f := range all {
			resp := toFeedResponse(f)
			resp.LiveIndicatorCount = counts[f.ID]
			out = append(out, resp)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"feeds": out})

	case http.MethodPost:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req feedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := validateFeedRequest(req, true); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := s.store.CreateFeed(feeds.Feed{
			SourceType:         feeds.SourceType(req.SourceType),
			Name:               strings.TrimSpace(req.Name),
			URL:                strings.TrimSpace(req.URL),
			APIKey:             req.APIKey,
			IndicatorAgingDays: req.IndicatorAgingDays,
			Enabled:            req.Enabled,
			TLSSkipVerify:      req.TLSSkipVerify,
		})
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFeedItem dispatches PUT/DELETE on /api/feeds/{id} and
// POST on /api/feeds/{id}/refresh. The per-feed refresh is admin-only
// and synchronous — the typical use is verifying connectivity right
// after configuring a feed, where waiting for the next watch tick is
// inconvenient. Watch-tick refreshes still run automatically.
func (s *Server) handleFeedItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/feeds/")
	parts := strings.SplitN(rest, "/", 2)
	idStr := parts[0]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	if len(parts) > 1 && parts[1] == "refresh" {
		s.handleFeedRefresh(w, r, id)
		return
	}

	switch r.Method {
	case http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		current, err := s.store.GetFeed(id)
		if err != nil {
			jsonError(w, "feed not found", http.StatusNotFound)
			return
		}
		var req feedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := validateFeedRequest(req, false); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Empty api_key in PUT keeps the existing one. Setting a new
		// non-empty key replaces it. To clear, the operator deletes
		// and recreates the feed (rare and intentional enough to
		// not need its own affordance).
		current.SourceType = feeds.SourceType(req.SourceType)
		current.Name = strings.TrimSpace(req.Name)
		current.URL = strings.TrimSpace(req.URL)
		if req.APIKey != "" {
			current.APIKey = req.APIKey
		}
		current.IndicatorAgingDays = req.IndicatorAgingDays
		current.Enabled = req.Enabled
		current.TLSSkipVerify = req.TLSSkipVerify
		if err := s.store.UpdateFeed(current); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w)

	case http.MethodDelete:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		if _, err := s.store.GetFeed(id); err != nil {
			jsonError(w, "feed not found", http.StatusNotFound)
			return
		}
		if err := s.store.DeleteFeed(id); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFeedRefresh runs an immediate fetch+upsert+prune cycle for
// one feed, bypassing the watch-tick cadence. Synchronous — capped at
// 5 minutes — so the admin gets prompt feedback in the Feeds dialog
// while still allowing fetches against larger MISPs (whose offset-based
// pagination degrades with depth: a 100k-attribute MISP can take 2-3
// minutes for a full sweep). Beyond 5 minutes the upstream is more
// likely stuck than slow; the dialog reports the timeout so the admin
// can narrow the source-side filter or pursue incremental sync (queued
// in TODO.md / MATURATION_PLAN as the long-term correct fix).
// Used to verify connectivity after configuring a new feed without
// waiting for the next watch tick.
func (s *Server) handleFeedRefresh(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	feed, err := s.store.GetFeed(id)
	if err != nil {
		jsonError(w, "feed not found", http.StatusNotFound)
		return
	}
	if !feed.Enabled {
		jsonError(w, "feed is disabled — enable it before triggering a refresh", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	// Manual refresh is always a full pull. Operators clicking Refresh
	// are expressing intent to verify upstream state; an incremental
	// here would defeat that. Watch ticks (refreshAllFeedsForWatch)
	// pass forceFull=false and let runFeedFetch decide via cadence.
	added, refreshed, err := s.runFeedFetch(ctx, feed, true)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                   true,
		"indicators_added":     added,
		"indicators_refreshed": refreshed,
	})
}

// runFeedFetch is the fetch+upsert+prune body shared between the
// watch scheduler's pre-full-pass refresh and the per-feed manual
// refresh handler. Updates the feed row's status / last_refresh_at /
// last_error around the fetch so the Feeds dialog reflects what
// happened.
//
// When forceFull is true the fetch is unconditionally a full pull
// (manual refresh, or the very first pull on a brand-new feed). When
// forceFull is false runFeedFetch picks full vs incremental based on
// fullRefreshDue: if the gap since LastFullRefreshAt has exceeded the
// per-feed cadence, this fetch is full; otherwise it's incremental
// against MISP's restSearch `timestamp` filter, asking only for
// attributes modified since LastRefreshAt minus an overlap.
//
// Aging-prune only runs on full pulls. Incrementals don't see the
// indicators that haven't changed upstream, so pruning by last_seen
// after an incremental would erroneously delete current-but-stable
// indicators. The full-refresh cadence is sized below the aging
// window to guarantee unchanged-but-still-current indicators get
// last_seen bumped before they age out.
func (s *Server) runFeedFetch(ctx context.Context, feed feeds.Feed, forceFull bool) (added, refreshed int, err error) {
	adapter, err := s.buildFeedAdapter(feed)
	if err != nil {
		return 0, 0, err
	}

	full := forceFull || fullRefreshDue(feed, time.Now().Unix())
	var since int64
	if !full {
		// 5-minute overlap absorbs upstream clock skew and any boundary
		// attribute that was being written exactly at LastRefreshAt.
		// The upsert dedupes on (feed_id, indicator), so re-observing a
		// few attributes is harmless.
		since = feed.LastRefreshAt - 300
		if since < 0 {
			since = 0
		}
	}

	mark := feed
	mark.Status = "fetching"
	_ = s.store.UpdateFeed(mark)

	res, fetchErr := adapter.Fetch(ctx, since)
	if fetchErr != nil {
		failed := feed
		failed.Status = "error"
		failed.LastError = fetchErr.Error()
		_ = s.store.UpdateFeed(failed)
		return 0, 0, fetchErr
	}

	now := time.Now().Unix()
	added, refreshed, err = s.store.UpsertFeedIndicators(feed.ID, res.Indicators, now)
	if err != nil {
		return added, refreshed, err
	}
	if full && feed.IndicatorAgingDays > 0 {
		cutoff := now - int64(feed.IndicatorAgingDays)*86400
		_, _ = s.store.RemoveStaleIndicators(feed.ID, cutoff)
	}

	totals := s.store.CountIndicatorsByFeed()

	done := feed
	done.LastRefreshAt = now
	if full {
		done.LastFullRefreshAt = now
	}
	done.LastIndicatorCount = totals[feed.ID]
	done.LastFetchTruncated = res.Truncated
	done.LastError = ""
	done.Status = "ok"
	_ = s.store.UpdateFeed(done)
	return added, refreshed, nil
}

// fullRefreshDue reports whether the next fetch for this feed should
// be a full pull rather than an incremental. Forced full when no full
// has ever happened (LastFullRefreshAt == 0) or when the gap since the
// last full has exceeded the per-feed full-refresh cadence.
func fullRefreshDue(f feeds.Feed, now int64) bool {
	if f.LastFullRefreshAt == 0 {
		return true
	}
	return now-f.LastFullRefreshAt >= fullRefreshCadenceSeconds(f)
}

// fullRefreshCadenceSeconds derives the per-feed full-refresh cadence
// from the aging window. Half the aging window: ensures indicators
// that haven't changed in MISP still get last_seen bumped before
// the aging sweep deletes them. Floored at 24 hours so a 1-day-aging
// feed doesn't try to full-refresh every 12 hours and blow back the
// incremental win. When aging is disabled (IndicatorAgingDays == 0),
// defaults to weekly — without aging there's no correctness deadline,
// but a periodic full sweep still catches deletes/replacements
// happening upstream that incremental wouldn't see.
func fullRefreshCadenceSeconds(f feeds.Feed) int64 {
	if f.IndicatorAgingDays > 0 {
		half := int64(f.IndicatorAgingDays) * 86400 / 2
		if half < 86400 {
			return 86400
		}
		return half
	}
	return 7 * 86400
}

// refreshAllFeedsForWatch fetches every enabled feed in parallel and
// blocks until they all finish (or the supplied context times out).
// Called from the watch scheduler immediately before a full-pass
// analysis so MISP/OpenCTI indicators are current when the analyzer
// runs against them. The auto-cadence worker is intentionally
// disabled (see server.go's New comment), and there is no manual
// refresh endpoint, so this is the only path that brings indicators
// current. A failed/timed-out feed is logged but does not block the
// analysis; the analyzer falls back to whatever indicators are
// already cached for that feed.
func (s *Server) refreshAllFeedsForWatch(ctx context.Context) {
	allFeeds := s.store.ListFeeds()
	enabled := 0
	for _, f := range allFeeds {
		if f.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return
	}
	msg, _ := json.Marshal(map[string]string{
		"msg": fmt.Sprintf("Watch: refreshing %d feed(s) before full pass.", enabled),
	})
	s.broker.Publish(SSEEvent{Type: "status", Data: string(msg)})

	var wg sync.WaitGroup
	for _, f := range allFeeds {
		if !f.Enabled {
			continue
		}
		wg.Add(1)
		go func(feed feeds.Feed) {
			defer wg.Done()
			// Watch ticks let runFeedFetch decide full vs incremental
			// based on the cadence — most ticks are cheap incrementals;
			// the periodic full keeps the aging window honest.
			if _, _, err := s.runFeedFetch(ctx, feed, false); err != nil {
				log.Printf("watch: feed refresh failed for %s: %v", feed.Name, err)
			}
		}(f)
	}
	wg.Wait()
}

// buildFeedAdapter is the AdapterFor switch shared by the fetcher
// worker (server.go's startFeedWorker) and the manual-refresh
// endpoint. New source-types add one case here.
func (s *Server) buildFeedAdapter(f feeds.Feed) (feeds.Adapter, error) {
	switch f.SourceType {
	case feeds.SourceMISP:
		return feeds.NewMISPClient(f.URL, f.APIKey, f.TLSSkipVerify), nil
	case feeds.SourceOpenCTI:
		return feeds.NewOpenCTIClient(f.URL, f.APIKey, f.TLSSkipVerify), nil
	default:
		return nil, fmt.Errorf("unsupported feed source_type: %q", f.SourceType)
	}
}

// validateFeedRequest enforces the constraints the SQL CHECK doesn't
// catch (or catches with a less helpful error). On create
// (requireAPIKey=true), an API key is required up-front. On update
// it's optional (empty = keep existing).
func validateFeedRequest(req feedRequest, requireAPIKey bool) error {
	switch req.SourceType {
	case "misp", "opencti":
		// ok
	default:
		return fmt.Errorf("source_type must be one of: misp, opencti")
	}
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(req.URL) == "" {
		return fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		return fmt.Errorf("url must include scheme (http:// or https://)")
	}
	if requireAPIKey && strings.TrimSpace(req.APIKey) == "" {
		return fmt.Errorf("api_key is required")
	}
	if req.IndicatorAgingDays < 0 {
		return fmt.Errorf("indicator_aging_days must be >= 0 (0 = no aging)")
	}
	return nil
}
