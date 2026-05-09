// Package feeds is the source-agnostic threat-intelligence-feed
// integration layer. It defines the normalized indicator type, the
// adapter interface that MISP / OpenCTI / future source-types must
// satisfy, and the fetcher worker that schedules per-feed refreshes
// against the store.
//
// The IOC list (operator-curated) and the feed indicators (auto-fetched
// from external aggregators) compose into the matcher used by
// /api/findings. Slice 1 of Phase 7 wired the cached matcher; this
// slice 2 adds the first source-type adapter (MISP) and the worker
// that drives it on a per-feed cadence.
package feeds

import "context"

// SourceType identifies the upstream system a feed pulls from.
type SourceType string

const (
	SourceMISP    SourceType = "misp"
	SourceOpenCTI SourceType = "opencti"
)

// IndicatorType is the normalized shape of a feed indicator after the
// source-type adapter has translated whatever the upstream returned
// (MISP's `ip-src`/`ip-dst`/`domain`/`hostname`/`md5`/`sha1`/`sha256`,
// OpenCTI's STIX patterns, etc.) into one of these four buckets.
type IndicatorType string

const (
	IndicatorIP     IndicatorType = "ip"
	IndicatorDomain IndicatorType = "domain"
	IndicatorCIDR   IndicatorType = "cidr"
	IndicatorHash   IndicatorType = "hash"
)

// Feed is the operator-configured upstream-source row from the `feeds`
// SQLite table. Refresh runs synchronously before each watch full-pass
// (see server.refreshAllFeedsForWatch) plus on demand via the per-feed
// Refresh button.
type Feed struct {
	ID                 int64
	SourceType         SourceType
	Name               string
	URL                string
	APIKey             string
	IndicatorAgingDays int
	LastRefreshAt      int64 // unix seconds; 0 = never
	LastIndicatorCount int
	LastFetchTruncated bool // last fetch hit the adapter's page-walk cap
	LastError          string
	Status             string // "idle" | "fetching" | "ok" | "error"
	Enabled            bool
	// TLSSkipVerify disables certificate verification on the upstream
	// HTTPS request. Off by default. Internal MISP / OpenCTI deployments
	// commonly run with self-signed or internal-CA certs that the Archer
	// container does not trust; this flag is the operator's per-feed
	// opt-in to bypass that check. UI surfaces it with an explicit
	// warning — turn off only for trusted internal feeds.
	TLSSkipVerify bool
	CreatedAt     int64
	UpdatedAt     int64
}

// Indicator is the normalized form an adapter emits. The fetcher
// worker dedupes against the existing `feed_indicators` rows by
// (feed_id, indicator) and updates `last_seen` when the indicator is
// re-observed in a fresh fetch.
type Indicator struct {
	Indicator string // the value (IP, domain, CIDR, or hash hex)
	Type      IndicatorType
	SourceID  string   // upstream's stable ID (MISP attribute id, OpenCTI indicator id)
	Tags      []string // upstream-supplied labels — passed through verbatim
}

// Adapter is what each source-type implementation satisfies. The
// fetcher worker holds one Adapter per configured Feed; calling Fetch
// returns the current full indicator set for that feed (the worker
// dedupes against the previous snapshot).
//
// Implementations should: respect ctx cancellation, time-out network
// calls (the adapter owns the http.Client), and never panic on
// malformed upstream payloads — return an error that the worker can
// log and surface in the feed's last_error field.
type Adapter interface {
	// Source identifies which SourceType this adapter handles. The
	// worker uses it for logging and metrics; the SourceType in the
	// Feed row chooses which adapter constructor to invoke.
	Source() SourceType
	// Fetch returns the current indicator set. May be empty (legitimate
	// "no new entries" response) or partial on transient upstream error
	// (return what was collected plus the error).
	Fetch(ctx context.Context) (FetchResult, error)
}

// FetchResult is what an Adapter returns. Indicators is the
// normalized set; Truncated is true when the adapter hit its
// page-walk safety cap and the upstream may have more — operators
// need to know they're not getting the full feed.
type FetchResult struct {
	Indicators []Indicator
	Truncated  bool
}
