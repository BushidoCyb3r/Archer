package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// OpenCTIClient adapts a single OpenCTI instance to the Adapter
// interface. OpenCTI exposes a GraphQL endpoint at /graphql with bearer
// authentication. The Indicators query returns nodes with a STIX
// pattern string and a mainObservableType — both used to derive our
// normalized IndicatorType bucket.
//
// Pagination: cursor-based via `first` + `after`. The adapter walks
// the cursor until pageInfo.hasNextPage is false, capped at PageLimit
// pages so a misconfigured query against a huge tenant can't OOM the
// process.
type OpenCTIClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client

	// PageSize is the GraphQL `first` argument (rows per page).
	PageSize int
	// PageLimit caps the cursor walk. Default 100; with PageSize 1000
	// that's 100k indicators per fetch — enough for most internal-team
	// deployments.
	PageLimit int
	// QueryFilter holds the operator's per-feed FilterGroup, pre-parsed
	// from Feed.QueryFilterJSON. Merged into every Fetch request alongside
	// any since-derived modified filter. Nil means no extra filter.
	QueryFilter map[string]any
}

// NewOpenCTIClient constructs a client with safe defaults: 30s
// timeout, 1000 indicators per page, 100-page cap. tlsSkipVerify=true
// disables certificate verification on the upstream HTTPS request —
// opt-in per feed for internal OpenCTI deployments running self-signed
// or internal-CA certs. allowInternal=true loosens the CheckRedirect
// SSRF guard for internal OpenCTI URLs. queryFilterJSON is an optional
// OpenCTI FilterGroup JSON object (empty = no filter); if non-empty and
// valid it is parsed into QueryFilter and merged into every Fetch request.
func NewOpenCTIClient(baseURL, apiKey string, tlsSkipVerify, allowInternal bool, queryFilterJSON string) *OpenCTIClient {
	c := &OpenCTIClient{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		APIKey:    apiKey,
		HTTP:      httpClientWithTLS(tlsSkipVerify, allowInternal),
		PageSize:  1000,
		PageLimit: 100,
	}
	if queryFilterJSON != "" {
		var f map[string]any
		if err := json.Unmarshal([]byte(queryFilterJSON), &f); err != nil {
			log.Printf("feeds: opencti: query_filter_json is not valid JSON (%v) — filter ignored", err)
		} else {
			c.QueryFilter = f
		}
	}
	return c
}

// Source satisfies Adapter.Source.
func (c *OpenCTIClient) Source() SourceType { return SourceOpenCTI }

// buildFilters assembles the GraphQL FilterGroup for a Fetch call. Four
// cases:
//   - since == 0, no QueryFilter → nil (omit filters from variables)
//   - since > 0, no QueryFilter → simple AND group with modified filter
//   - since == 0, QueryFilter set → operator filter passed as-is
//   - both → AND-wrap: modified filter in filters[], operator filter in filterGroups[]
func (c *OpenCTIClient) buildFilters(since int64) map[string]any {
	var sinceFilter map[string]any
	if since > 0 {
		sinceFilter = map[string]any{
			"key":      "modified",
			"values":   []string{time.Unix(since, 0).UTC().Format(time.RFC3339)},
			"operator": "gt",
		}
	}
	switch {
	case sinceFilter == nil && c.QueryFilter == nil:
		return nil
	case sinceFilter != nil && c.QueryFilter == nil:
		return map[string]any{
			"mode":         "and",
			"filters":      []any{sinceFilter},
			"filterGroups": []any{},
		}
	case sinceFilter == nil:
		return c.QueryFilter
	default:
		return map[string]any{
			"mode":         "and",
			"filters":      []any{sinceFilter},
			"filterGroups": []any{c.QueryFilter},
		}
	}
}

// openCTIQuery is the GraphQL query the adapter sends. Pinned to the
// fields we actually consume; OpenCTI's schema is stable for these.
// $filters is the optional FilterGroup input — nil when no operator
// filter is set and since == 0; OpenCTI ignores the argument when null.
const openCTIQuery = `query Indicators($first: Int, $after: ID, $filters: FilterGroup) {
  indicators(first: $first, after: $after, filters: $filters) {
    edges {
      cursor
      node {
        id
        pattern
        x_opencti_main_observable_type
        objectLabel {
          value
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

// openCTIRequest is the GraphQL POST body shape.
type openCTIRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// openCTIResponse covers the indicators query response.
type openCTIResponse struct {
	Data struct {
		Indicators struct {
			Edges []struct {
				Cursor string `json:"cursor"`
				Node   struct {
					ID                         string `json:"id"`
					Pattern                    string `json:"pattern"`
					XOpenCTIMainObservableType string `json:"x_opencti_main_observable_type"`
					ObjectLabel []struct {
						Value string `json:"value"`
					} `json:"objectLabel"`
				} `json:"node"`
			} `json:"edges"`
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
		} `json:"indicators"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// stixValue extracts the single-quoted value from a STIX pattern. The
// canonical STIX pattern form is `[<obj-type>:<prop> = '<value>']`.
// For property paths that are themselves quoted — e.g.
// `file:hashes.'SHA-256' = 'abcdef'` — a regex over the whole pattern
// would grab the first quoted substring, which is the algorithm name,
// not the value. Splitting on the rightmost `=` first scopes the
// quoted-value match to the right-hand side. Returns empty string
// when no quoted value is found; caller treats that as a skip.
var stixValueRe = regexp.MustCompile(`'([^']+)'`)

func stixValue(pattern string) string {
	eq := strings.LastIndex(pattern, "=")
	if eq < 0 {
		return ""
	}
	rhs := pattern[eq+1:]
	if m := stixValueRe.FindStringSubmatch(rhs); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// Fetch satisfies Adapter.Fetch. Walks the cursor, accumulating
// normalized indicators across pages. On any per-page error the
// accumulated set is returned alongside the error so partial
// progress isn't lost.
//
// When since > 0, a modified > ISO(since) filter is AND-ed with any
// operator QueryFilter via the GraphQL FilterGroup input. On full
// fetches (since == 0) the QueryFilter is applied alone if set.
func (c *OpenCTIClient) Fetch(ctx context.Context, since int64) (FetchResult, error) {
	if c.BaseURL == "" {
		return FetchResult{}, fmt.Errorf("opencti: empty base URL")
	}
	if c.APIKey == "" {
		return FetchResult{}, fmt.Errorf("opencti: empty API key")
	}

	out := make([]Indicator, 0, c.PageSize)
	truncated := false
	var cursor string
	pageFilters := c.buildFilters(since)
	for page := 0; page < c.PageLimit; page++ {
		vars := map[string]any{"first": c.PageSize}
		if cursor != "" {
			vars["after"] = cursor
		}
		if pageFilters != nil {
			vars["filters"] = pageFilters
		}

		body, err := json.Marshal(openCTIRequest{Query: openCTIQuery, Variables: vars})
		if err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("opencti: marshal request: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/graphql", bytes.NewReader(body))
		if err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("opencti: build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("opencti: request failed: %w", err)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50 MiB safety cap
		_ = resp.Body.Close()
		if err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("opencti: read response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			preview := string(raw)
			if len(preview) > 1024 {
				preview = preview[:1024]
			}
			return FetchResult{Indicators: out}, fmt.Errorf("opencti: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(preview))
		}

		var parsed openCTIResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return FetchResult{Indicators: out}, fmt.Errorf("opencti: decode response: %w", err)
		}
		if len(parsed.Errors) > 0 {
			return FetchResult{Indicators: out}, fmt.Errorf("opencti: graphql error: %s", parsed.Errors[0].Message)
		}

		for _, edge := range parsed.Data.Indicators.Edges {
			ind, ok := normalizeOpenCTINode(edge.Node)
			if !ok {
				continue
			}
			out = append(out, ind)
		}

		if !parsed.Data.Indicators.PageInfo.HasNextPage {
			break
		}
		cursor = parsed.Data.Indicators.PageInfo.EndCursor
		if cursor == "" {
			// Defensive: hasNextPage=true with no cursor would loop forever.
			break
		}
		// Hit the page-walk cap with hasNextPage still true → upstream
		// has more, flag truncation so the operator sees they're
		// under-fetching.
		if page == c.PageLimit-1 {
			truncated = true
		}
	}
	return FetchResult{Indicators: out, Truncated: truncated}, nil
}

// normalizeOpenCTINode translates one OpenCTI indicator node into the
// normalized Indicator shape. Returns ok=false to skip indicators we
// can't classify (URL, unrecognized observable types, malformed
// values).
func normalizeOpenCTINode(node struct {
	ID                         string `json:"id"`
	Pattern                    string `json:"pattern"`
	XOpenCTIMainObservableType string `json:"x_opencti_main_observable_type"`
	ObjectLabel                []struct {
		Value string `json:"value"`
	} `json:"objectLabel"`
}) (Indicator, bool) {
	val := stixValue(node.Pattern)
	if val == "" {
		return Indicator{}, false
	}

	var typ IndicatorType
	switch node.XOpenCTIMainObservableType {
	case "IPv4-Addr", "IPv6-Addr":
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
	case "Domain-Name", "Hostname":
		// Same shape control as MISP. Audit 2026-05-10 NEW-28.
		if !validDomain(val) {
			return Indicator{}, false
		}
		typ = IndicatorDomain
	case "StixFile":
		if !validHash(val) {
			return Indicator{}, false
		}
		typ = IndicatorHash
	default:
		return Indicator{}, false
	}

	tags := make([]string, 0, len(node.ObjectLabel))
	for _, l := range node.ObjectLabel {
		if l.Value != "" {
			tags = append(tags, l.Value)
		}
	}

	return Indicator{
		Indicator: val,
		Type:      typ,
		SourceID:  node.ID,
		Tags:      tags,
	}, true
}
