package feeds

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// mispShardConcurrency caps how many type-shard requests are in
// flight against MISP simultaneously. Splitting the fetch into one
// query per attribute type collapses MISP's offset-pagination
// degradation (each shard restarts at page 1 of just its type), but
// running all 7 shards at once on a large MISP saturates it in bursts
// — field experience with a 38M-attribute instance showed 4 concurrent
// shards at 25k-attribute pages (~30 MB each) drove load to 6+,
// causing per-page timeouts on the slower shards while the server was
// still assembling responses. Serialised (=1) the total fetch wall time
// is nearly the same because MISP processes each sequential shard faster
// under lower load than it processes 4 concurrent ones under saturation.
// Incrementals (since > 0) are tiny regardless, so concurrency=1 only
// adds latency on infrequent full pulls against well-resourced MISP
// boxes — an acceptable trade-off for correctness on the common case.
const mispShardConcurrency = 1

// mispAttributeTypes is the per-shard work list. One restSearch
// request goes out per type, in parallel up to mispShardConcurrency.
// Each shard restarts pagination from page 1 of just its type, so
// the deep-page slowdown that hits a unified 7-type walk gets
// distributed across 7 shallower walks.
var mispAttributeTypes = []string{
	"ip-src", "ip-dst",
	"domain", "hostname",
	"md5", "sha1", "sha256",
	"ja3-fingerprint-md5",
}

// MISPClient adapts a single MISP instance to the Adapter interface.
// The query endpoint is /attributes/restSearch (POST) which accepts a
// JSON body specifying filters and returns a JSON envelope containing
// the matching attributes.
//
// The default request asks for the network-indicator attribute types
// that map cleanly into our four IndicatorType buckets. File hashes
// are bucketed under IndicatorHash regardless of algorithm — the
// matcher doesn't currently distinguish md5 vs sha1 vs sha256. URLs
// from MISP are skipped at this slice (they need parser logic to
// pull the host/path, which is fed-into per-finding correlation;
// punt to a follow-up).
//
// Pagination: the adapter walks `restSearch`'s `page` + `limit`
// parameters until either a short page returns (we've reached the
// end) or PageLimit pages have been fetched (safety cap on
// misconfigured queries against huge tenants). Every page hits the
// same /attributes/restSearch endpoint with an incrementing `page`.
type MISPClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client

	// PageSize is the `limit` argument MISP accepts on /attributes/restSearch.
	// Default 5000 — reduced from 25000 after field experience showed
	// large MISP instances return ~30 MB per 25k-attribute page, which
	// can exceed the per-page timeout under load. At 5k the response is
	// ~6 MB and assembles quickly even on a loaded box.
	PageSize int

	// PageLimit caps the page walk per shard. Default 500; with
	// PageSize 5000 that's 2.5M attributes per type. With seven
	// types the aggregate per-fetch cap is well above any realistic
	// feed. When the walk hits this cap on any shard and the last
	// page of that shard was full, the fetch is reported as truncated.
	PageLimit int

	// QueryFilter holds the operator's per-feed restSearch filter,
	// pre-parsed from Feed.QueryFilterJSON. Merged into every
	// fetchShard request body before Archer's required keys are
	// written, so operator entries can narrow the result set but
	// cannot override type sharding, pagination, or IDS-flag logic.
	// Nil means no extra filter.
	QueryFilter map[string]any
}

// NewMISPClient constructs a client with safe defaults: 4-minute
// per-page timeout, 5k attributes per page, 100-page cap per type-shard.
// tlsSkipVerify=true disables certificate verification on the
// upstream HTTPS request — opt-in per feed for internal MISP
// deployments running self-signed or internal-CA certs.
// allowInternal=true loosens the CheckRedirect SSRF guard for this
// client so redirects can resolve to internal addresses — paired
// with the admin-side validateFeedRequest bypass for a feed whose
// URL itself targets an internal MISP.
// queryFilterJSON is an optional JSON object string (empty = no
// filter); if non-empty and valid it is parsed into QueryFilter and
// merged into every fetchShard request.
func NewMISPClient(baseURL, apiKey string, tlsSkipVerify, allowInternal bool, queryFilterJSON string) *MISPClient {
	c := &MISPClient{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		APIKey:    apiKey,
		HTTP:      httpClientWithTLS(tlsSkipVerify, allowInternal),
		PageSize:  5000,
		PageLimit: 500,
	}
	if queryFilterJSON != "" {
		var f map[string]any
		if err := json.Unmarshal([]byte(queryFilterJSON), &f); err != nil {
			log.Printf("feeds: misp: query_filter_json is not valid JSON (%v) — filter ignored", err)
		} else {
			c.QueryFilter = f
		}
	}
	return c
}

// httpClientWithTLS builds an *http.Client whose Transport honors the
// per-feed tls_skip_verify flag. Cloned from the stdlib default so we
// keep its connection-pool and proxy behavior; only TLSClientConfig is
// rewritten when the operator opts into bypass.
//
// Per-request Timeout caps a single page fetch. PageSize dropped from
// 25k to 5k after field experience with a 38M-attribute MISP: 25k
// ip-dst attributes serialize to ~30 MB and take >90s for the server
// to assemble under load, causing Client.Timeout. At 5k the response
// is ~6 MB and assembles in a few seconds even on a loaded box. The
// timeout is raised to 4 minutes to stay well inside MISP's own PHP
// max_execution_time (typically 300s) while giving large responses
// ample room. The parent context (5-minute manual refresh,
// 10-minute watch full-pass) still caps total fetch time across pages.
//
// CheckRedirect enforces the same SSRF guard the admin-side
// validateFeedRequest applies: a redirect target whose host resolves
// to loopback / link-local / RFC1918 / IPv6 unique-local space is
// refused. Without this, an attacker who controls an external feed
// URL pointed at by the admin's config could redirect to
// http://169.254.169.254/... or http://10.0.0.5/... and reach
// internal services with whatever credentials the admin attached.
// Stdlib's default CheckRedirect follows up to 10 redirects with no
// host validation; we bound it at 5 and validate each hop. Audit
// 2026-05-10 NEW-18.
func httpClientWithTLS(skipVerify, allowInternal bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if skipVerify {
		// InsecureSkipVerify governs cert trust (the operator's
		// skip-TLS-verify option for self-signed internal MISP).
		// MinVersion is orthogonal — it only makes Go 1.22+'s default
		// TLS 1.2 floor explicit, so the skip-verify path still
		// connects to any modern MISP unchanged.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	// Close the DNS-rebinding gap in the redirect-only SSRF guard: the
	// CheckRedirect hook below only sees redirect hops, not the initial
	// request. A feed hostname that resolves to a public IP at config
	// time but to an internal IP at fetch time (DNS rebinding, or a
	// legitimately-misconfigured domain that switches A records) would
	// reach internal services with whatever API key the admin attached.
	// DialContext resolves DNS once, checks every returned address, then
	// connects to the first allowed IP directly — subsequent layers see
	// a stable IP and DNS cannot re-resolve under them.
	// allowInternal bypasses the check for explicitly-internal feeds
	// (MISP/OpenCTI hosted on RFC1918 with allow_internal=true).
	if !allowInternal {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("feed: invalid address %q: %w", addr, err)
			}
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("feed: DNS lookup %s: %w", host, err)
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("feed: no addresses for %s", host)
			}
			for _, a := range addrs {
				if isInternalAddr(a.IP) {
					return nil, fmt.Errorf("feed: refused connection to internal address %s (%s)", a.IP, host)
				}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(addrs[0].IP.String(), port))
		}
	}
	return &http.Client{
		Timeout:   4 * time.Minute,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("feed: too many redirects (>5)")
			}
			// allowInternal=true short-circuits the redirect host check.
			// Paired with the admin-side validateFeedRequest bypass for
			// a feed whose URL itself targets an internal MISP / OpenCTI
			// — the operator explicitly accepted internal-address
			// traffic for this feed, so a redirect from
			// https://misp.internal/ to https://misp.internal/login is
			// the legitimate auth flow and not an SSRF.
			if allowInternal {
				return nil
			}
			host := req.URL.Hostname()
			if host == "" {
				return nil
			}
			addrs, err := net.LookupIP(host)
			if err != nil {
				return fmt.Errorf("feed redirect host lookup failed: %v", err)
			}
			for _, ip := range addrs {
				if isInternalAddr(ip) {
					return fmt.Errorf("feed: refused redirect to internal address %s (%s)", ip, host)
				}
			}
			return nil
		},
	}
}

// isInternalAddr matches the same deny-list as the admin-side
// rejectInternalFeedURL — kept duplicated here so the feeds package
// doesn't import server. The set: loopback, link-local (incl.
// cloud-metadata 169.254.169.254), unspecified, RFC1918 private,
// IPv6 unique-local. Audit 2026-05-10 NEW-18.
func isInternalAddr(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	return false
}

// Source satisfies Adapter.Source.
func (c *MISPClient) Source() SourceType { return SourceMISP }

// mispAttribute is the per-attribute shape MISP's REST API returns.
// Field names follow MISP's JSON convention (Pascal-cased keys); only
// the fields we actually consume are declared.
type mispAttribute struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Category  string    `json:"category"`
	ToIDs     bool      `json:"to_ids"`
	Timestamp string    `json:"timestamp"`
	Tag       []mispTag `json:"Tag"`
}

type mispTag struct {
	Name string `json:"name"`
}

// mispResponse is the envelope shape for MISP's attributes/restSearch
// endpoint: `{"response":{"Attribute":[...]}}`.
type mispResponse struct {
	Response struct {
		Attribute []mispAttribute `json:"Attribute"`
	} `json:"response"`
}

// Fetch satisfies Adapter.Fetch. Splits the work into one
// restSearch request per attribute type and runs them in parallel,
// capped at mispShardConcurrency in flight. Each shard does its own
// pagination starting from page 1 of just its type, which collapses
// the offset-pagination cost — instead of one walk that gets slower
// with depth, we get N shallower walks running concurrently. On
// any shard error the sibling shards are cancelled and the first
// error is returned.
//
// When since > 0, every shard sets MISP's restSearch `timestamp`
// filter so the upstream returns only attributes whose timestamp is
// >= since. Combined with sharding, an incremental fetch on a large
// feed is typically a handful of fast shallow-page round trips
// rather than a deep multi-minute walk.
func (c *MISPClient) Fetch(ctx context.Context, since int64) (FetchResult, error) {
	if c.BaseURL == "" {
		return FetchResult{}, fmt.Errorf("misp: empty base URL")
	}
	if c.APIKey == "" {
		return FetchResult{}, fmt.Errorf("misp: empty API key")
	}

	shardCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan string, len(mispAttributeTypes))
	for _, t := range mispAttributeTypes {
		jobs <- t
	}
	close(jobs)

	concurrency := mispShardConcurrency
	if concurrency > len(mispAttributeTypes) {
		concurrency = len(mispAttributeTypes)
	}

	var (
		mu        sync.Mutex
		out       []Indicator
		truncated bool
		firstErr  error
	)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if shardCtx.Err() != nil {
					return
				}
				inds, shardTrunc, err := c.fetchShard(shardCtx, t, since)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					cancel()
					return
				}
				out = append(out, inds...)
				if shardTrunc {
					truncated = true
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return FetchResult{Indicators: out, Truncated: truncated}, firstErr
	}
	return FetchResult{Indicators: out, Truncated: truncated}, nil
}

// fetchShard walks restSearch for a single MISP attribute type,
// paginating until a short page (real end of data) or PageLimit is
// reached. Hitting PageLimit with the last page full sets the
// truncated return so the caller can surface that to operators.
func (c *MISPClient) fetchShard(ctx context.Context, mispType string, since int64) ([]Indicator, bool, error) {
	out := make([]Indicator, 0, c.PageSize)
	truncated := false
	for page := 1; page <= c.PageLimit; page++ {
		// Operator's filter lands first; Archer's required keys always
		// overwrite so type-sharding, pagination, IDS flag, and the
		// incremental timestamp filter cannot be altered per-feed.
		body := make(map[string]any, 10+len(c.QueryFilter))
		for k, v := range c.QueryFilter {
			body[k] = v
		}
		body["returnFormat"] = "json"
		body["type"] = []string{mispType}
		body["to_ids"] = true // MISP convention: only indicators meant for IDS
		body["deleted"] = false
		body["limit"] = c.PageSize
		body["page"] = page
		body["includeContext"] = false
		body["enforceWarninglist"] = true
		if since > 0 {
			// MISP's restSearch `timestamp` filter: returns attributes
			// whose timestamp >= this value (Unix seconds). Caller
			// supplies the floor with overlap, so a missed or
			// double-counted boundary attribute is fine — the upsert
			// logic dedupes on (feed_id, indicator).
			body["timestamp"] = since
		}
		buf, err := json.Marshal(body)
		if err != nil {
			return out, truncated, fmt.Errorf("misp: marshal request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.BaseURL+"/attributes/restSearch", bytes.NewReader(buf))
		if err != nil {
			return out, truncated, fmt.Errorf("misp: build request: %w", err)
		}
		req.Header.Set("Authorization", c.APIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return out, truncated, fmt.Errorf("misp: request failed (type=%s): %w", mispType, err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 200<<20)) // 200 MiB safety cap
		_ = resp.Body.Close()
		if readErr != nil {
			return out, truncated, fmt.Errorf("misp: read response (type=%s): %w", mispType, readErr)
		}
		if resp.StatusCode != http.StatusOK {
			preview := string(raw)
			if len(preview) > 1024 {
				preview = preview[:1024]
			}
			return out, truncated, fmt.Errorf("misp: HTTP %d (type=%s): %s", resp.StatusCode, mispType, strings.TrimSpace(preview))
		}

		var parsed mispResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return out, truncated, fmt.Errorf("misp: decode response (type=%s): %w", mispType, err)
		}

		got := len(parsed.Response.Attribute)
		for _, attr := range parsed.Response.Attribute {
			ind, ok := normalizeMISPAttribute(attr)
			if !ok {
				continue
			}
			out = append(out, ind)
		}

		if got < c.PageSize {
			break
		}
		if page == c.PageLimit {
			truncated = true
			break
		}
	}
	return out, truncated, nil
}

// normalizeMISPAttribute translates a single MISP attribute into our
// normalized Indicator shape. Returns ok=false to skip indicators we
// can't classify (URLs at this slice, malformed values, empty values).
func normalizeMISPAttribute(a mispAttribute) (Indicator, bool) {
	val := strings.TrimSpace(a.Value)
	if val == "" {
		return Indicator{}, false
	}
	var typ IndicatorType
	switch a.Type {
	case "ip-src", "ip-dst":
		// MISP allows both bare IPs and CIDR notation in ip-* fields.
		// Disambiguate by checking for `/`.
		if strings.Contains(val, "/") {
			if _, _, err := net.ParseCIDR(val); err != nil {
				return Indicator{}, false
			}
			typ = IndicatorCIDR
		} else {
			if net.ParseIP(val) == nil {
				return Indicator{}, false
			}
			typ = IndicatorIP
		}
	case "domain", "hostname":
		// Refuse anything that doesn't fit the RFC1035-ish shape.
		// Pre-fix any non-empty string was accepted, including HTML
		// payloads. Audit 2026-05-10 NEW-28.
		if !validDomain(val) {
			return Indicator{}, false
		}
		typ = IndicatorDomain
	case "md5", "sha1", "sha256":
		// Hash indicators must be hex-of-fixed-length — same NEW-28
		// shape control. MD5=32, SHA1=40, SHA256=64.
		if !validHash(val) {
			return Indicator{}, false
		}
		typ = IndicatorHash
	case "ja3-fingerprint-md5":
		// JA3 fingerprints are 32-char MD5 hex strings. Kept in a
		// dedicated bucket (IndicatorJA3) so they aren't accidentally
		// matched against file hashes in files.log.
		if !validHash(val) {
			return Indicator{}, false
		}
		typ = IndicatorJA3
	default:
		return Indicator{}, false
	}

	tags := make([]string, 0, len(a.Tag))
	for _, t := range a.Tag {
		if t.Name != "" {
			tags = append(tags, t.Name)
		}
	}

	return Indicator{
		Indicator: val,
		Type:      typ,
		SourceID:  a.ID,
		Tags:      tags,
	}, true
}
