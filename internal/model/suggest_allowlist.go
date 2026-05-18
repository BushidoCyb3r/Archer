package model

// SuggestedAllowEntry is one beacon-pair candidate returned by
// Store.SuggestedPairAllowlist. It surfaces beacons that have been
// acknowledged by an analyst and have re-fired across 14+ distinct UTC
// days — the two-signal conjunction that distinguishes known-good
// infrastructure from a patient C2.
type SuggestedAllowEntry struct {
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	DstPort     string `json:"dst_port"`
	FindingType string `json:"finding_type"`
	DayCount    int    `json:"day_count"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	PeakScore   int    `json:"peak_score"`
	AckedBy     string `json:"acked_by"`
}
