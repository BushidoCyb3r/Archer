package feeds

import "net"

// SourcedIndicators is a typed snapshot of one feed's current
// indicator set, bucketed by indicator type so consumers can do
// type-segregated lookups (a candidate IP isn't tested against domain
// indicators and vice versa).
//
// The IOC matcher in /api/findings continues to use the union-style
// SourcedMatcher (which mixes types into one map). This typed shape
// is for the analyzer's hot path, where preserving the distinction
// matters: a DNS query candidate matching a feed `domain` indicator
// emits a Threat Intel Hit; the same query string accidentally
// equalling an IP-typed indicator should not.
//
// Hashes carries md5 / sha1 / sha256 hex strings — algorithm-agnostic,
// since MISP and OpenCTI emit each algorithm as its own indicator
// type but we don't need to disambiguate at match time. Lowercased
// hex on the way in so case-mismatched upstream values don't miss.
type SourcedIndicators struct {
	Source  string          // "feed:<feed-name>"
	IPs     map[string]bool // exact IP-string match
	CIDRs   []*net.IPNet    // CIDR containment
	Domains map[string]bool // exact domain match (caller lowercases)
	Hashes  map[string]bool // exact hex match (caller lowercases)
	Tags    map[string][]string
}

// Provider exposes the per-feed indicator snapshot to consumers
// outside the store package. The store implements this against the
// feed_indicators table; tests use small in-memory stubs.
//
// Returned slice is read-only — consumers treat it as a snapshot
// for the duration of one read and do not mutate it.
type Provider interface {
	EnabledFeedIndicators() []SourcedIndicators
}
