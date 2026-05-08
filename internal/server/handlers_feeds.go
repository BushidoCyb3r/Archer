package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	ID                    int64  `json:"id"`
	SourceType            string `json:"source_type"`
	Name                  string `json:"name"`
	URL                   string `json:"url"`
	RefreshCadenceMinutes int    `json:"refresh_cadence_minutes"`
	IndicatorAgingDays    int    `json:"indicator_aging_days"`
	LastRefreshAt         int64  `json:"last_refresh_at"`
	LastIndicatorCount    int    `json:"last_indicator_count"`
	LastError             string `json:"last_error,omitempty"`
	Status                string `json:"status"`
	Enabled               bool   `json:"enabled"`
	CreatedAt             int64  `json:"created_at"`
	UpdatedAt             int64  `json:"updated_at"`
	HasAPIKey             bool   `json:"has_api_key"`
}

func toFeedResponse(f feeds.Feed) feedResponse {
	return feedResponse{
		ID:                    f.ID,
		SourceType:            string(f.SourceType),
		Name:                  f.Name,
		URL:                   f.URL,
		RefreshCadenceMinutes: f.RefreshCadenceMinutes,
		IndicatorAgingDays:    f.IndicatorAgingDays,
		LastRefreshAt:         f.LastRefreshAt,
		LastIndicatorCount:    f.LastIndicatorCount,
		LastError:             f.LastError,
		Status:                f.Status,
		Enabled:               f.Enabled,
		CreatedAt:             f.CreatedAt,
		UpdatedAt:             f.UpdatedAt,
		HasAPIKey:             f.APIKey != "",
	}
}

// feedRequest is the wire shape POST/PUT accepts. APIKey is the only
// write-only field; an empty string in PUT means "keep the existing
// key", not "clear it" — clearing requires a separate PUT with the
// caller explicitly setting it. This avoids the foot-gun where an
// admin re-saves a feed config without the api_key field and
// accidentally blanks out their secret.
type feedRequest struct {
	SourceType            string `json:"source_type"`
	Name                  string `json:"name"`
	URL                   string `json:"url"`
	APIKey                string `json:"api_key"`
	RefreshCadenceMinutes int    `json:"refresh_cadence_minutes"`
	IndicatorAgingDays    int    `json:"indicator_aging_days"`
	Enabled               bool   `json:"enabled"`
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
			SourceType:            feeds.SourceType(req.SourceType),
			Name:                  strings.TrimSpace(req.Name),
			URL:                   strings.TrimSpace(req.URL),
			APIKey:                req.APIKey,
			RefreshCadenceMinutes: req.RefreshCadenceMinutes,
			IndicatorAgingDays:    req.IndicatorAgingDays,
			Enabled:               req.Enabled,
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
// POST on /api/feeds/{id}/refresh.
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
		current.RefreshCadenceMinutes = req.RefreshCadenceMinutes
		current.IndicatorAgingDays = req.IndicatorAgingDays
		current.Enabled = req.Enabled
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
// one feed, bypassing the worker's per-feed schedule. Returns the
// added/refreshed counts so the admin UI can show what just happened.
// Synchronous — the response waits for the upstream fetch — so the
// admin gets immediate feedback. The worker keeps running on its
// schedule independently; concurrent ticks are safe because
// UpsertFeedIndicators wraps each upsert in a transaction.
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

	adapter, err := s.buildFeedAdapter(feed)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Cap the manual-refresh fetch at 60s so a hung upstream doesn't
	// keep the admin's HTTP request open indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// Status flips to "fetching" for the duration. The worker's own
	// loop also flips status; concurrent refresh + scheduled tick are
	// both safe because UpdateFeed serializes through the DB.
	mark := feed
	mark.Status = "fetching"
	_ = s.store.UpdateFeed(mark)

	inds, err := adapter.Fetch(ctx)
	if err != nil {
		failed := feed
		failed.Status = "error"
		failed.LastError = err.Error()
		_ = s.store.UpdateFeed(failed)
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}

	now := time.Now().Unix()
	added, refreshed, err := s.store.UpsertFeedIndicators(feed.ID, inds, now)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                   true,
		"indicators_added":     added,
		"indicators_refreshed": refreshed,
	})
}

// buildFeedAdapter is the AdapterFor switch shared by the fetcher
// worker (server.go's startFeedWorker) and the manual-refresh
// endpoint. New source-types add one case here.
func (s *Server) buildFeedAdapter(f feeds.Feed) (feeds.Adapter, error) {
	switch f.SourceType {
	case feeds.SourceMISP:
		return feeds.NewMISPClient(f.URL, f.APIKey), nil
	case feeds.SourceOpenCTI:
		return feeds.NewOpenCTIClient(f.URL, f.APIKey), nil
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
	if req.RefreshCadenceMinutes < 1 {
		return fmt.Errorf("refresh_cadence_minutes must be >= 1")
	}
	if req.IndicatorAgingDays < 0 {
		return fmt.Errorf("indicator_aging_days must be >= 0 (0 = no aging)")
	}
	return nil
}
