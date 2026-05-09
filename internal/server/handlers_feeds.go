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
	LastIndicatorCount int    `json:"last_indicator_count"`
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
		LastIndicatorCount: f.LastIndicatorCount,
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
		out := make([]feedResponse, 0, len(all))
		for _, f := range all {
			out = append(out, toFeedResponse(f))
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
// 60s — so the admin gets immediate feedback in the Feeds dialog.
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

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	added, refreshed, err := s.runFeedFetch(ctx, feed)
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
func (s *Server) runFeedFetch(ctx context.Context, feed feeds.Feed) (added, refreshed int, err error) {
	adapter, err := s.buildFeedAdapter(feed)
	if err != nil {
		return 0, 0, err
	}

	mark := feed
	mark.Status = "fetching"
	_ = s.store.UpdateFeed(mark)

	inds, fetchErr := adapter.Fetch(ctx)
	if fetchErr != nil {
		failed := feed
		failed.Status = "error"
		failed.LastError = fetchErr.Error()
		_ = s.store.UpdateFeed(failed)
		return 0, 0, fetchErr
	}

	now := time.Now().Unix()
	added, refreshed, err = s.store.UpsertFeedIndicators(feed.ID, inds, now)
	if err != nil {
		return added, refreshed, err
	}
	if feed.IndicatorAgingDays > 0 {
		cutoff := now - int64(feed.IndicatorAgingDays)*86400
		_, _ = s.store.RemoveStaleIndicators(feed.ID, cutoff)
	}

	done := feed
	done.LastRefreshAt = now
	done.LastIndicatorCount = added + refreshed
	done.LastError = ""
	done.Status = "ok"
	_ = s.store.UpdateFeed(done)
	return added, refreshed, nil
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
			if _, _, err := s.runFeedFetch(ctx, feed); err != nil {
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
