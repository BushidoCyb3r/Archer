package analysis

import "github.com/BushidoCyb3r/Archer/internal/feeds"

// SourcedFeedIndicators and FeedProvider are aliases for the canonical
// types in the feeds package. Aliasing keeps analyzer-facing call
// sites short (`a.feedSources []SourcedFeedIndicators`) without
// leaking a feeds-import requirement onto every caller of the
// analyzer's tests.
type SourcedFeedIndicators = feeds.SourcedIndicators
type FeedProvider = feeds.Provider
