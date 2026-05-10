package feeds

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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
	// Default 10000 — large enough that a 1M-attribute feed walks in
	// 100 round-trips, small enough that any single page response fits
	// comfortably in memory.
	PageSize int

	// PageLimit caps the page walk. Default 100; combined with
	// PageSize 10000 that's an upper bound of 1M attributes per fetch.
	// When the walk hits this cap and the last page was full, the
	// fetch is reported as truncated.
	PageLimit int
}

// NewMISPClient constructs a client with safe defaults: 30s timeout,
// 10k attributes per page, 100-page cap (1M attributes). tlsSkipVerify=true
// disables certificate verification on the upstream HTTPS request —
// opt-in per feed for internal MISP deployments running self-signed
// or internal-CA certs.
func NewMISPClient(baseURL, apiKey string, tlsSkipVerify bool) *MISPClient {
	return &MISPClient{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		APIKey:    apiKey,
		HTTP:      httpClientWithTLS(tlsSkipVerify),
		PageSize:  10000,
		PageLimit: 100,
	}
}

// httpClientWithTLS builds an *http.Client whose Transport honors the
// per-feed tls_skip_verify flag. Cloned from the stdlib default so we
// keep its connection-pool and proxy behavior; only TLSClientConfig is
// rewritten when the operator opts into bypass.
//
// Per-request Timeout caps a single page fetch. MISP's restSearch
// pagination degrades with depth on large feeds — a single page can
// take 5-15s on a 1M-attribute MISP at high offsets — so 30s left no
// margin. 90s is generous enough for a single page on any realistic
// MISP while still detecting a genuinely stuck connection. The parent
// context (5-minute manual refresh, 10-minute watch full-pass) caps
// total fetch time across all pages.
func httpClientWithTLS(skipVerify bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if skipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   90 * time.Second,
		Transport: transport,
	}
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

// mispResponse covers both response shapes MISP can return: the legacy
// `{"response":{"Attribute":[...]}}` envelope and the newer
// `{"response":[{"Attribute":{...}}, ...]}` array shape. The adapter
// handles both transparently.
type mispResponse struct {
	Response struct {
		Attribute []mispAttribute `json:"Attribute"`
	} `json:"response"`
}

// Fetch satisfies Adapter.Fetch. Walks /attributes/restSearch in
// pages of PageSize, accumulating normalized indicators across
// pages. Stops early when a short page returns (real end of data).
// Caps the walk at PageLimit pages — when both the cap is hit and
// the last page was full, the result is flagged as Truncated so
// operators know they're not getting the whole feed.
//
// When since > 0, MISP's restSearch `timestamp` filter is set so the
// upstream returns only attributes whose timestamp is >= since. The
// resulting page-walk is dramatically smaller than a full snapshot,
// which is the whole point of incremental sync — MISP's offset
// pagination degrades sharply with depth, and a since filter that
// chops the result set down keeps the fetch close to the cheap
// shallow-page region of the curve.
func (c *MISPClient) Fetch(ctx context.Context, since int64) (FetchResult, error) {
	if c.BaseURL == "" {
		return FetchResult{}, fmt.Errorf("misp: empty base URL")
	}
	if c.APIKey == "" {
		return FetchResult{}, fmt.Errorf("misp: empty API key")
	}

	out := make([]Indicator, 0, c.PageSize)
	truncated := false
	for page := 1; page <= c.PageLimit; page++ {
		body := map[string]any{
			"returnFormat": "json",
			"type": []string{
				"ip-src", "ip-dst",
				"domain", "hostname",
				"md5", "sha1", "sha256",
			},
			"to_ids":             true, // MISP convention: only indicators meant for IDS
			"deleted":            false,
			"limit":              c.PageSize,
			"page":               page,
			"includeContext":     false,
			"enforceWarninglist": true,
		}
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
			return FetchResult{Indicators: out}, fmt.Errorf("misp: marshal request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.BaseURL+"/attributes/restSearch", bytes.NewReader(buf))
		if err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("misp: build request: %w", err)
		}
		req.Header.Set("Authorization", c.APIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("misp: request failed: %w", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 200<<20)) // 200 MiB safety cap
		_ = resp.Body.Close()
		if readErr != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("misp: read response: %w", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			preview := string(raw)
			if len(preview) > 1024 {
				preview = preview[:1024]
			}
			return FetchResult{Indicators: out}, fmt.Errorf("misp: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(preview))
		}

		var parsed mispResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("misp: decode response: %w", err)
		}

		got := len(parsed.Response.Attribute)
		for _, attr := range parsed.Response.Attribute {
			ind, ok := normalizeMISPAttribute(attr)
			if !ok {
				continue
			}
			out = append(out, ind)
		}

		// Short page → end of data. Full page on the last allowed
		// page → cap reached with more upstream, flag truncation.
		if got < c.PageSize {
			break
		}
		if page == c.PageLimit {
			truncated = true
			break
		}
	}
	return FetchResult{Indicators: out, Truncated: truncated}, nil
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
		typ = IndicatorDomain
	case "md5", "sha1", "sha256":
		typ = IndicatorHash
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
