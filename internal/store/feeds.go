package store

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/feeds"
)

// Feed CRUD methods. The feeds table is independent of the central
// settings blob — feeds are a list (multiple rows), settings is a map
// (single row). Schema lives in migrations/0002_feeds.sql.

// CreateFeed persists a new feed configuration. Returns the assigned
// row id. The caller is responsible for validating source_type / URL
// shape before calling — the table-level CHECK constraint catches
// invalid source_type but URL shape is application-layer.
func (s *Store) CreateFeed(f feeds.Feed) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("store: db not initialized")
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`INSERT INTO feeds (
			source_type, name, url, api_key,
			indicator_aging_days,
			last_refresh_at, last_full_refresh_at,
			last_indicator_count, last_fetch_truncated,
			last_error, status, enabled, tls_skip_verify, allow_internal,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, '', 'idle', ?, ?, ?, ?, ?)`,
		string(f.SourceType), f.Name, f.URL, f.APIKey,
		f.IndicatorAgingDays,
		boolToInt(f.Enabled), boolToInt(f.TLSSkipVerify), boolToInt(f.AllowInternal), now, now,
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert feed: %w", err)
	}
	s.invalidateFeedBuckets()
	return res.LastInsertId()
}

// GetFeed loads one feed by id. Returns sql.ErrNoRows if not found.
func (s *Store) GetFeed(id int64) (feeds.Feed, error) {
	if s.db == nil {
		return feeds.Feed{}, fmt.Errorf("store: db not initialized")
	}
	row := s.db.QueryRow(`
		SELECT id, source_type, name, url, api_key,
			indicator_aging_days,
			last_refresh_at, last_full_refresh_at,
			last_indicator_count, last_fetch_truncated, last_error,
			status, enabled, tls_skip_verify, allow_internal, created_at, updated_at,
			consecutive_failures, last_pruned_count
		FROM feeds WHERE id = ?`, id)
	return scanFeed(row)
}

// ListFeeds returns all configured feeds, ordered by id. Empty slice
// when no feeds are configured (no error).
func (s *Store) ListFeeds() []feeds.Feed {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`
		SELECT id, source_type, name, url, api_key,
			indicator_aging_days,
			last_refresh_at, last_full_refresh_at,
			last_indicator_count, last_fetch_truncated, last_error,
			status, enabled, tls_skip_verify, allow_internal, created_at, updated_at,
			consecutive_failures, last_pruned_count
		FROM feeds ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []feeds.Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			continue
		}
		out = append(out, f)
	}
	return out
}

// UpdateFeed writes back the mutable fields of a feed row. The
// fetcher worker calls this to record refresh status / counts /
// errors after a fetch cycle.
func (s *Store) UpdateFeed(f feeds.Feed) error {
	if s.db == nil {
		return fmt.Errorf("store: db not initialized")
	}
	_, err := s.db.Exec(`
		UPDATE feeds SET
			source_type = ?, name = ?, url = ?, api_key = ?,
			indicator_aging_days = ?,
			last_refresh_at = ?, last_full_refresh_at = ?,
			last_indicator_count = ?, last_fetch_truncated = ?, last_error = ?,
			status = ?, enabled = ?, tls_skip_verify = ?, allow_internal = ?, updated_at = ?
		WHERE id = ?`,
		string(f.SourceType), f.Name, f.URL, f.APIKey,
		f.IndicatorAgingDays,
		f.LastRefreshAt, f.LastFullRefreshAt,
		f.LastIndicatorCount, boolToInt(f.LastFetchTruncated), f.LastError,
		f.Status, boolToInt(f.Enabled), boolToInt(f.TLSSkipVerify), boolToInt(f.AllowInternal),
		time.Now().Unix(), f.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update feed %d: %w", f.ID, err)
	}
	s.invalidateFeedBuckets()
	return nil
}

// UpdateFeedRefreshState writes back ONLY the columns the refresh
// worker mutates: status, last_refresh_at, last_full_refresh_at,
// last_indicator_count, last_fetch_truncated, last_error. Pre-fix
// the refresh path used UpdateFeed, which rewrites every mutable
// column from a snapshot taken before the fetch began. A concurrent
// admin PUT to /api/feeds/{id} that landed mid-fetch (e.g. URL or
// API-key rotation during a 90-second MISP page) was silently
// reverted when the refresh finished and wrote back the stale
// snapshot's URL/APIKey. Targeted updates touch only the columns
// the refresh actually owns; admin-owned columns (URL, APIKey,
// Name, IndicatorAgingDays, Enabled, TLSSkipVerify) flow exclusively
// through UpdateFeed. Audit 2026-05-10 NEW-22.
func (s *Store) UpdateFeedRefreshState(id int64, status string, lastRefreshAt, lastFullRefreshAt int64, lastIndicatorCount int, lastFetchTruncated bool, lastError string) error {
	if s.db == nil {
		return fmt.Errorf("store: db not initialized")
	}
	// consecutive_failures: reset to 0 on "ok", increment on "error",
	// unchanged for any other status (e.g. "fetching" mid-cycle marks
	// don't reach this method anyway — they use UpdateFeedStatus).
	// Encoding the toggle in SQL avoids a read-modify-write race
	// between two concurrent refreshes of the same feed.
	_, err := s.db.Exec(`
		UPDATE feeds SET
			status = ?,
			last_refresh_at = ?,
			last_full_refresh_at = ?,
			last_indicator_count = ?,
			last_fetch_truncated = ?,
			last_error = ?,
			consecutive_failures = CASE
				WHEN ? = 'ok'    THEN 0
				WHEN ? = 'error' THEN consecutive_failures + 1
				ELSE consecutive_failures
			END,
			updated_at = ?
		WHERE id = ?`,
		status, lastRefreshAt, lastFullRefreshAt, lastIndicatorCount,
		boolToInt(lastFetchTruncated), lastError,
		status, status,
		time.Now().Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: update feed refresh state %d: %w", id, err)
	}
	s.invalidateFeedBuckets()
	return nil
}

// SetFeedPrunedCount records how many indicators the most recent
// full refresh aged out. Refresh-owned column written only by the
// prune step in runFeedFetch, so it follows the NEW-22 ownership
// model (a separate targeted UPDATE rather than a column on
// UpdateFeed, which an admin edit would clobber). It's a plain
// assignment, not a read-modify-write, so it carries none of the
// concurrent-refresh race that made UpdateFeedRefreshState encode
// its streak toggle in SQL — last-writer-wins is the same semantics
// it would have inside the combined refresh-state UPDATE.
func (s *Store) SetFeedPrunedCount(id int64, pruned int) error {
	if s.db == nil {
		return fmt.Errorf("store: db not initialized")
	}
	_, err := s.db.Exec(
		`UPDATE feeds SET last_pruned_count = ?, updated_at = ? WHERE id = ?`,
		pruned, time.Now().Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: set feed pruned count %d: %w", id, err)
	}
	s.invalidateFeedBuckets()
	return nil
}

// UpdateFeedStatus writes only the status column (and updated_at).
// Used by the refresh path's "fetching" mark so a concurrent admin
// edit can't be clobbered by a transient status update either. Same
// motivation as UpdateFeedRefreshState. Audit 2026-05-10 NEW-22.
func (s *Store) UpdateFeedStatus(id int64, status string) error {
	if s.db == nil {
		return fmt.Errorf("store: db not initialized")
	}
	_, err := s.db.Exec(
		`UPDATE feeds SET status = ?, updated_at = ? WHERE id = ?`,
		status, time.Now().Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: update feed status %d: %w", id, err)
	}
	return nil
}

// DeleteFeed removes a feed and (via FK ON DELETE CASCADE) its
// indicators. Use UpdateFeed to disable instead of delete when the
// operator wants the feed to come back later.
func (s *Store) DeleteFeed(id int64) error {
	if s.db == nil {
		return fmt.Errorf("store: db not initialized")
	}
	_, err := s.db.Exec(`DELETE FROM feeds WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete feed %d: %w", id, err)
	}
	s.invalidateFeedMatcher(id)
	s.invalidateFeedBuckets()
	return nil
}

// UpsertFeedIndicators writes a fresh indicator snapshot for a feed.
// New (feed_id, indicator) pairs become INSERTs; existing pairs have
// their last_seen / tags updated. Returns counts for telemetry.
//
// Stale-indicator removal is intentionally NOT folded in here — the
// worker calls RemoveStaleIndicators with the same snapshot timestamp
// after the upsert so the aging window is operator-configurable per
// feed, not pinned to the upsert call.
//
// Chunked: indicators are committed in batches of upsertBatchSize so
// the writer's lock window stays short. WAL mode lets readers run
// concurrently with the writer regardless, but smaller transactions
// keep CPU and memory pressure off any single fsync. On a partial
// failure (batch N succeeds, batch N+1 errors), prior batches stay
// committed and the error is returned with the running totals — the
// next refresh re-attempts from upstream's full snapshot, so partial
// progress is durable rather than lost.
func (s *Store) UpsertFeedIndicators(feedID int64, inds []feeds.Indicator, now int64) (added, refreshed int, err error) {
	if s.db == nil {
		return 0, 0, fmt.Errorf("store: db not initialized")
	}
	if len(inds) == 0 {
		return 0, 0, nil
	}

	const upsertBatchSize = 1000
	for start := 0; start < len(inds); start += upsertBatchSize {
		end := start + upsertBatchSize
		if end > len(inds) {
			end = len(inds)
		}
		a, r, batchErr := s.upsertFeedIndicatorBatch(feedID, inds[start:end], now)
		added += a
		refreshed += r
		if batchErr != nil {
			s.invalidateFeedMatcher(feedID)
			s.invalidateFeedBuckets()
			return added, refreshed, batchErr
		}
	}
	s.invalidateFeedMatcher(feedID)
	s.invalidateFeedBuckets()
	return added, refreshed, nil
}

// upsertFeedIndicatorBatch processes one slice of indicators in a single
// transaction. Pulled out of UpsertFeedIndicators so the batch loop can
// commit between batches without leaving prepared statements open across
// commit boundaries (each batch gets its own tx + prepared stmts).
//
// Pre-v0.12.0 the implementation issued one SELECT per indicator
// (existence check) followed by either INSERT or UPDATE — three round
// trips per row, 3M queries on a 1M-attribute MISP refresh. The
// SQLite ON CONFLICT clause collapses that to one INSERT-or-UPDATE
// per row. The added/refreshed split previously came from separate
// statement paths; SQLite's CHANGES() doesn't distinguish "insert"
// from "update on conflict," so we rely on whether first_seen ==
// last_seen post-statement (true on insert, false on update). RETURNING
// keeps that read in the same round trip. Audit 2026-05-10 LOW.
func (s *Store) upsertFeedIndicatorBatch(feedID int64, inds []feeds.Indicator, now int64) (added, refreshed int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	upsert, err := tx.Prepare(`
		INSERT INTO feed_indicators (feed_id, indicator, indicator_type, first_seen, last_seen, source_id, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(feed_id, indicator) DO UPDATE SET
			last_seen = excluded.last_seen,
			tags = excluded.tags,
			source_id = excluded.source_id
		RETURNING first_seen`)
	if err != nil {
		return 0, 0, fmt.Errorf("store: prepare upsert: %w", err)
	}
	defer upsert.Close()

	for _, ind := range inds {
		tagsJSON, _ := json.Marshal(ind.Tags)
		var firstSeen int64
		if err := upsert.QueryRow(
			feedID, ind.Indicator, string(ind.Type), now, now, ind.SourceID, string(tagsJSON),
		).Scan(&firstSeen); err != nil {
			return added, refreshed, fmt.Errorf("store: upsert indicator: %w", err)
		}
		if firstSeen == now {
			added++
		} else {
			refreshed++
		}
	}

	if err := tx.Commit(); err != nil {
		return added, refreshed, fmt.Errorf("store: commit: %w", err)
	}
	return added, refreshed, nil
}

// RemoveStaleIndicators deletes feed_indicators rows whose last_seen
// is older than `before`. The worker computes `before` as
// `now - aging_days*86400` so each feed's aging window is honored.
// Returns the count removed.
func (s *Store) RemoveStaleIndicators(feedID int64, before int64) (int, error) {
	if s.db == nil {
		return 0, fmt.Errorf("store: db not initialized")
	}
	res, err := s.db.Exec(`DELETE FROM feed_indicators WHERE feed_id = ? AND last_seen < ?`, feedID, before)
	if err != nil {
		return 0, fmt.Errorf("store: prune indicators: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.invalidateFeedMatcher(feedID)
		s.invalidateFeedBuckets()
	}
	return int(n), nil
}

// CountIndicatorsByFeed returns the live indicator count for every
// feed_id present in feed_indicators, in a single GROUP BY query.
// Used by /api/feeds to surface live progress during a long fetch —
// the count reflects what's currently in the table, not the
// last_indicator_count snapshot frozen at the previous successful
// fetch. Feeds with zero indicators (never fetched, just-deleted)
// are absent from the map; callers should default to 0.
func (s *Store) CountIndicatorsByFeed() map[int64]int {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT feed_id, COUNT(*) FROM feed_indicators GROUP BY feed_id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make(map[int64]int)
	for rows.Next() {
		var id int64
		var c int
		if err := rows.Scan(&id, &c); err != nil {
			continue
		}
		out[id] = c
	}
	return out
}

// ListFeedIndicators returns every current indicator for a feed.
// Used by the matcher composer (slice 4) to build the union matcher
// over operator IOC list + all enabled feeds. Returns empty slice
// (not nil) when the feed has no indicators.
func (s *Store) ListFeedIndicators(feedID int64) []feeds.Indicator {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`
		SELECT indicator, indicator_type, source_id, tags
		FROM feed_indicators WHERE feed_id = ?`, feedID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]feeds.Indicator, 0)
	for rows.Next() {
		var ind feeds.Indicator
		var typ, tagsJSON string
		if err := rows.Scan(&ind.Indicator, &typ, &ind.SourceID, &tagsJSON); err != nil {
			continue
		}
		ind.Type = feeds.IndicatorType(typ)
		if strings.TrimSpace(tagsJSON) != "" {
			_ = json.Unmarshal([]byte(tagsJSON), &ind.Tags)
		}
		out = append(out, ind)
	}
	return out
}

// EnabledFeedIndicators returns one SourcedIndicators bucket per
// enabled feed. Indicators are typed: ip → IPs, cidr → CIDRs (parsed
// once here so the caller doesn't re-parse on every match check),
// domain → Domains (lowercased to make match insensitive to case),
// hash → skipped (no analyzer field today carries a hash candidate).
//
// Tags are carried alongside on the Tags map keyed by indicator value.
// The analyzer surfaces them in finding Detail when present so the
// analyst sees the upstream label (e.g. "tlp:white", "malware:emotet")
// without having to cross-reference back to MISP.
//
// Disabled feeds are skipped entirely — operators turning a feed off
// should immediately stop seeing matches from it on the next analysis.
//
// Cached: the rebuild cost (ListFeeds + per-feed ListFeedIndicators +
// CIDR-parse) ran on every analyze tick before. invalidateFeedBuckets
// drops the cache on feed CRUD and indicator writes; everything else
// hits the cache.
func (s *Store) EnabledFeedIndicators() []feeds.SourcedIndicators {
	if s.db == nil {
		return nil
	}
	s.feedBucketsMu.Lock()
	if s.feedBucketsOK {
		out := s.feedBuckets
		s.feedBucketsMu.Unlock()
		return out
	}
	s.feedBucketsMu.Unlock()

	rebuilt := s.buildEnabledFeedIndicators()

	s.feedBucketsMu.Lock()
	s.feedBuckets = rebuilt
	s.feedBucketsOK = true
	s.feedBucketsMu.Unlock()
	return rebuilt
}

// buildEnabledFeedIndicators is the uncached body of
// EnabledFeedIndicators. Held separate so the cache front can stay
// minimal. Caller (the cache front) is responsible for storing the
// result.
func (s *Store) buildEnabledFeedIndicators() []feeds.SourcedIndicators {
	all := s.ListFeeds()
	out := make([]feeds.SourcedIndicators, 0, len(all))
	for _, f := range all {
		if !f.Enabled {
			continue
		}
		inds := s.ListFeedIndicators(f.ID)
		bucket := feeds.SourcedIndicators{
			Source:  "feed:" + f.Name,
			IPs:     make(map[string]bool),
			Domains: make(map[string]bool),
			Hashes:  make(map[string]bool),
			Tags:    make(map[string][]string),
		}
		for _, ind := range inds {
			val := strings.TrimSpace(ind.Indicator)
			if val == "" {
				continue
			}
			switch ind.Type {
			case feeds.IndicatorIP:
				bucket.IPs[val] = true
			case feeds.IndicatorCIDR:
				if _, ipnet, err := net.ParseCIDR(val); err == nil {
					bucket.CIDRs = append(bucket.CIDRs, ipnet)
				}
			case feeds.IndicatorDomain:
				bucket.Domains[strings.ToLower(val)] = true
			case feeds.IndicatorHash:
				bucket.Hashes[strings.ToLower(val)] = true
			default:
				continue
			}
			if len(ind.Tags) > 0 {
				key := val
				switch ind.Type {
				case feeds.IndicatorDomain, feeds.IndicatorHash:
					key = strings.ToLower(val)
				}
				bucket.Tags[key] = ind.Tags
			}
		}
		out = append(out, bucket)
	}
	return out
}

// invalidateFeedBuckets drops the EnabledFeedIndicators() cache so
// the next read rebuilds. Called by every feed CRUD and indicator-
// write path.
func (s *Store) invalidateFeedBuckets() {
	s.feedBucketsMu.Lock()
	s.feedBuckets = nil
	s.feedBucketsOK = false
	s.enabledFeedList = nil
	s.feedListOK = false
	s.feedBucketsMu.Unlock()
}

// scanFeed unifies the row-scan for QueryRow and Query callers.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanFeed(r rowScanner) (feeds.Feed, error) {
	var f feeds.Feed
	var sourceType string
	var enabled, tlsSkipVerify, allowInternal, lastFetchTruncated int
	if err := r.Scan(
		&f.ID, &sourceType, &f.Name, &f.URL, &f.APIKey,
		&f.IndicatorAgingDays,
		&f.LastRefreshAt, &f.LastFullRefreshAt,
		&f.LastIndicatorCount, &lastFetchTruncated, &f.LastError,
		&f.Status, &enabled, &tlsSkipVerify, &allowInternal, &f.CreatedAt, &f.UpdatedAt,
		&f.ConsecutiveFailures, &f.LastPrunedCount,
	); err != nil {
		return feeds.Feed{}, err
	}
	f.SourceType = feeds.SourceType(sourceType)
	f.Enabled = enabled != 0
	f.TLSSkipVerify = tlsSkipVerify != 0
	f.AllowInternal = allowInternal != 0
	f.LastFetchTruncated = lastFetchTruncated != 0
	return f, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
