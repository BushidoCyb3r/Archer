package analysis

import (
	"github.com/BushidoCyb3r/Archer/internal/feeds"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// SourcedFeedIndicators and FeedProvider are aliases for the canonical
// types in the feeds package. Aliasing keeps analyzer-facing call
// sites short (`a.feedSources []SourcedFeedIndicators`) without
// leaking a feeds-import requirement onto every caller of the
// analyzer's tests.
type SourcedFeedIndicators = feeds.SourcedIndicators
type FeedProvider = feeds.Provider

// FindingsProvider exposes the merged finding set as the analyzer
// sees it before the current run's results are folded in. Today the
// only consumer is aggregateRisk (v0.14.10 NEW-67): without it, a
// host whose detections were emitted in a prior run but who is silent
// this run keeps its previous Host Risk Score row indefinitely, even
// though aggregateRisk only ever saw a fresh per-run a.findings
// slice. Unioning the existing set with the current run lets the
// risk aggregator see the host's complete detection footprint.
//
// Implemented by *store.Store; the analyzer accepts the interface so
// tests can supply a stub without pulling the SQLite dependency.
type FindingsProvider interface {
	GetFindings() []model.Finding
}
