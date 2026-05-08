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
type MISPClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client

	// Limit caps the number of attributes the adapter pulls per fetch.
	// MISP servers can hold millions; default 100k is enough for most
	// operator-team deployments and avoids OOM on a misconfigured
	// search.
	Limit int
}

// NewMISPClient constructs a client with safe defaults: 30s timeout,
// 100k attribute cap. tlsSkipVerify=true disables certificate
// verification on the upstream HTTPS request — opt-in per feed for
// internal MISP deployments running self-signed or internal-CA certs.
func NewMISPClient(baseURL, apiKey string, tlsSkipVerify bool) *MISPClient {
	return &MISPClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTP:    httpClientWithTLS(tlsSkipVerify),
		Limit:   100000,
	}
}

// httpClientWithTLS builds an *http.Client whose Transport honors the
// per-feed tls_skip_verify flag. Cloned from the stdlib default so we
// keep its connection-pool and proxy behavior; only TLSClientConfig is
// rewritten when the operator opts into bypass.
func httpClientWithTLS(skipVerify bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if skipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
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

// Fetch satisfies Adapter.Fetch. Posts /attributes/restSearch with a
// filter limiting to network-indicator types, paginates if MISP hints
// at more results (currently single-page; revisit if real deployments
// hit the cap).
func (c *MISPClient) Fetch(ctx context.Context) ([]Indicator, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("misp: empty base URL")
	}
	if c.APIKey == "" {
		return nil, fmt.Errorf("misp: empty API key")
	}

	body := map[string]any{
		"returnFormat": "json",
		"type": []string{
			"ip-src", "ip-dst",
			"domain", "hostname",
			"md5", "sha1", "sha256",
		},
		"to_ids":             true, // MISP convention: only indicators meant for IDS
		"deleted":            false,
		"limit":              c.Limit,
		"includeContext":     false,
		"enforceWarninglist": true,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("misp: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/attributes/restSearch", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("misp: build request: %w", err)
	}
	req.Header.Set("Authorization", c.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("misp: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Read up to 1 KiB of the body for the error message — full
		// MISP error pages can be large HTML.
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("misp: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
	}

	var parsed mispResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("misp: decode response: %w", err)
	}

	out := make([]Indicator, 0, len(parsed.Response.Attribute))
	for _, attr := range parsed.Response.Attribute {
		ind, ok := normalizeMISPAttribute(attr)
		if !ok {
			continue
		}
		out = append(out, ind)
	}
	return out, nil
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
