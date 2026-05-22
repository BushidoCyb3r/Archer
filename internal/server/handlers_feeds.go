package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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
	// LastPrunedCount is how many indicators the most recent full
	// refresh aged out. Pre-prune population is LastPrunedCount +
	// LastIndicatorCount; the Feeds dialog renders the ratio as a
	// per-feed "% aged out" so the aging-window knob is calibratable.
	// Stale on incrementals / aging-disabled feeds — the UI gates the
	// line on indicator_aging_days > 0 && last_full_refresh_at > 0.
	LastPrunedCount int `json:"last_pruned_count"`
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
	AllowInternal      bool   `json:"allow_internal"`
	QueryFilterJSON    string `json:"query_filter_json"`
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
		LastPrunedCount:    f.LastPrunedCount,
		LastFetchTruncated: f.LastFetchTruncated,
		LastError:          f.LastError,
		Status:             f.Status,
		Enabled:            f.Enabled,
		TLSSkipVerify:      f.TLSSkipVerify,
		AllowInternal:      f.AllowInternal,
		QueryFilterJSON:    f.QueryFilterJSON,
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
	AllowInternal      bool   `json:"allow_internal"`
	QueryFilterJSON    string `json:"query_filter_json"`
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
		if err := decodeJSONBody(w, r, &req, 16<<10); err != nil {
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
			AllowInternal:      req.AllowInternal,
			QueryFilterJSON:    req.QueryFilterJSON,
		})
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.recordAudit(r, "feed_create", auditEvent{
			TargetType: "feed",
			TargetID:   fmt.Sprintf("%d", id),
			TargetName: req.Name,
			AfterValue: map[string]any{
				"source_type": req.SourceType, "name": req.Name, "url": req.URL,
				"enabled": req.Enabled, "tls_skip_verify": req.TLSSkipVerify,
				"allow_internal":       req.AllowInternal,
				"indicator_aging_days": req.IndicatorAgingDays,
			},
		})
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
		if err := decodeJSONBody(w, r, &req, 16<<10); err != nil {
			return
		}
		if err := validateFeedRequest(req, false); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		before := map[string]any{
			"source_type": string(current.SourceType), "name": current.Name, "url": current.URL,
			"enabled": current.Enabled, "tls_skip_verify": current.TLSSkipVerify,
			"allow_internal":       current.AllowInternal,
			"indicator_aging_days": current.IndicatorAgingDays,
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
		current.AllowInternal = req.AllowInternal
		current.QueryFilterJSON = req.QueryFilterJSON
		if err := s.store.UpdateFeed(current); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.recordAudit(r, "feed_update", auditEvent{
			TargetType:  "feed",
			TargetID:    fmt.Sprintf("%d", id),
			TargetName:  current.Name,
			BeforeValue: before,
			AfterValue: map[string]any{
				"source_type": string(current.SourceType), "name": current.Name, "url": current.URL,
				"enabled": current.Enabled, "tls_skip_verify": current.TLSSkipVerify,
				"allow_internal":       current.AllowInternal,
				"indicator_aging_days": current.IndicatorAgingDays,
			},
		})
		jsonOK(w)

	case http.MethodDelete:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		feed, err := s.store.GetFeed(id)
		if err != nil {
			jsonError(w, "feed not found", http.StatusNotFound)
			return
		}
		if err := s.store.DeleteFeed(id); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.recordAudit(r, "feed_delete", auditEvent{
			TargetType: "feed",
			TargetID:   fmt.Sprintf("%d", id),
			TargetName: feed.Name,
			BeforeValue: map[string]any{
				"source_type": string(feed.SourceType), "name": feed.Name, "url": feed.URL,
				"enabled": feed.Enabled,
			},
		})
		jsonOK(w)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFeedRefresh runs an immediate full fetch+upsert+prune cycle
// for one feed, bypassing the watch-tick cadence. Always full —
// operators clicking Refresh are expressing intent to verify upstream
// state, and an incremental here would defeat that. Synchronous,
// capped at 10 minutes; type-shard parallelism and the larger
// PageSize keep large MISP fetches under that cap on most realistic
// feeds. Used to verify connectivity after configuring a new feed
// without waiting for the next watch tick.
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

	// Detached from r.Context() so a browser disconnect (dialog closed,
	// page reload, intervening proxy timeout) doesn't cancel an in-flight
	// MISP/OpenCTI pull mid-sync. The 10-minute hard cap still bounds it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Manual refresh is always a full pull. Operators clicking Refresh
	// are expressing intent to verify upstream state; an incremental
	// here would defeat that. Watch ticks (refreshAllFeedsForWatch)
	// pass forceFull=false and let runFeedFetch decide via cadence.
	added, refreshed, err := s.runFeedFetch(ctx, feed, true)
	if err != nil {
		s.recordAudit(r, "feed_refresh", auditEvent{
			TargetType: "feed",
			TargetID:   fmt.Sprintf("%d", id),
			TargetName: feed.Name,
			Details:    map[string]any{"ok": false, "error": err.Error()},
		})
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.recordAudit(r, "feed_refresh", auditEvent{
		TargetType: "feed",
		TargetID:   fmt.Sprintf("%d", id),
		TargetName: feed.Name,
		Details:    map[string]any{"ok": true, "added": added, "refreshed": refreshed},
	})

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
	// OpenCTI's adapter accepts the since argument to satisfy the
	// interface but ignores it — every OpenCTI fetch is structurally
	// a full pull. Treating it as "incremental" would skip the
	// aging-prune on every tick that isn't a periodic full sync,
	// which would let stale indicators linger for half the aging
	// window instead of clearing every watch tick. Force full for
	// any source that doesn't actually honour the timestamp filter.
	if feed.SourceType != feeds.SourceMISP {
		full = true
	}
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

	// Refresh-state mutations all go through targeted UPDATEs that
	// only touch the columns the refresh path owns (status,
	// last_refresh_at, last_full_refresh_at, last_indicator_count,
	// last_fetch_truncated, last_error). Pre-fix this code used
	// UpdateFeed, which rewrites the entire mutable row from a
	// pre-fetch snapshot — a concurrent admin PUT to /api/feeds/{id}
	// (URL rotation, API-key rollover) landing mid-fetch was
	// silently reverted when the fetch finished and wrote back the
	// stale snapshot. Audit 2026-05-10 NEW-22.
	_ = s.store.UpdateFeedStatus(feed.ID, "fetching")

	res, fetchErr := adapter.Fetch(ctx, since)
	if fetchErr != nil {
		_ = s.store.UpdateFeedRefreshState(
			feed.ID, "error",
			feed.LastRefreshAt, feed.LastFullRefreshAt,
			feed.LastIndicatorCount, feed.LastFetchTruncated,
			fetchErr.Error(),
		)
		return 0, 0, fetchErr
	}

	now := time.Now().Unix()
	added, refreshed, err = s.store.UpsertFeedIndicators(feed.ID, res.Indicators, now)
	if err != nil {
		return added, refreshed, err
	}
	if full && feed.IndicatorAgingDays > 0 {
		cutoff := now - int64(feed.IndicatorAgingDays)*86400
		// Record what the aging window actually removed so the Feeds
		// dialog can show a per-feed "% aged out" instead of leaving
		// the knob blind. Only persisted when the prune itself
		// succeeded — a delete error must not overwrite the last
		// good count with a bogus 0. A clean run that aged out
		// nothing legitimately writes 0 ("window is loose enough").
		if pruned, perr := s.store.RemoveStaleIndicators(feed.ID, cutoff); perr == nil {
			_ = s.store.SetFeedPrunedCount(feed.ID, pruned)
		}
	}

	totals := s.store.CountIndicatorsByFeed()
	lastFullRefreshAt := feed.LastFullRefreshAt
	if full {
		lastFullRefreshAt = now
	}
	_ = s.store.UpdateFeedRefreshState(
		feed.ID, "ok",
		now, lastFullRefreshAt,
		totals[feed.ID], res.Truncated, "",
	)
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
				slog.Warn("watch: feed refresh failed", "feed", feed.Name, "err", err)
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
		return feeds.NewMISPClient(f.URL, f.APIKey, f.TLSSkipVerify, f.AllowInternal, f.QueryFilterJSON), nil
	case feeds.SourceOpenCTI:
		return feeds.NewOpenCTIClient(f.URL, f.APIKey, f.TLSSkipVerify, f.AllowInternal, f.QueryFilterJSON), nil
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
	// SSRF guard runs unless the operator explicitly opted this feed
	// into the internal-address bypass. Per-feed scope means a typo
	// in another feed's URL still gets refused. Audit-arc shape from
	// NEW-18 holds for every feed unless allow_internal=true. v0.18.5+.
	if !req.AllowInternal {
		if err := rejectInternalFeedURL(req.URL); err != nil {
			return err
		}
	}
	if requireAPIKey && strings.TrimSpace(req.APIKey) == "" {
		return fmt.Errorf("api_key is required")
	}
	if req.IndicatorAgingDays < 0 {
		return fmt.Errorf("indicator_aging_days must be >= 0 (0 = no aging)")
	}
	if req.QueryFilterJSON != "" {
		var obj map[string]any
		if err := json.Unmarshal([]byte(req.QueryFilterJSON), &obj); err != nil {
			return fmt.Errorf("query_filter_json must be a valid JSON object: %v", err)
		}
	}
	return nil
}

// rejectInternalFeedURL refuses feed URLs that obviously target
// loopback / link-local / RFC1918 / cloud-metadata address space at
// config time. The SSRF threat: a compromised admin (or one pasting
// the wrong URL from a tutorial) can configure a feed at
// http://169.254.169.254/latest/meta-data/iam/security-credentials/
// (AWS metadata), http://localhost:6379 (Redis if exposed on the
// host), or http://10.0.0.5/internal-api — and the feed worker will
// fetch from inside the host's network with whatever credentials the
// admin attached as api_key.
//
// Two-layer defense:
//
//  1. Config-time (this function): refuse URL hosts that are
//     SYNTACTIC IP literals in the deny set. No DNS lookup — DNS
//     failure during config (transient nameserver hiccup, captive
//     portal, slow upstream) shouldn't block valid public URLs.
//
//  2. Fetch-time: feeds.httpClientWithTLS's CheckRedirect resolves
//     redirect targets and refuses any that land in internal space.
//     That's the layer that catches a public-looking hostname
//     redirecting to 169.254.169.254.
//
// Audit 2026-05-10 NEW-18.
func rejectInternalFeedURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("url parse: %v", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url must have a host")
	}
	// Reject hosts that look like loopback regardless of DNS — a
	// literal "localhost" can be aliased in /etc/hosts to anywhere
	// but the operator-facing semantic is "the local machine."
	switch strings.ToLower(host) {
	case "localhost", "ip6-localhost", "ip6-loopback":
		return fmt.Errorf("url host %q is a loopback alias; refused to prevent SSRF", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if isInternalIP(ip) {
			return fmt.Errorf("url host %s is an internal address; refused to prevent SSRF", host)
		}
	}
	return nil
}

// isInternalIP reports whether the given IP is in any of the address
// ranges Archer refuses to fetch feeds from: loopback, link-local
// (incl. cloud metadata 169.254.169.254), unspecified, RFC1918
// private, IPv6 unique-local (fc00::/7) and IPv6 link-local
// (fe80::/10). These are the standard SSRF deny-list ranges from
// OWASP guidance.
func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	return false
}
