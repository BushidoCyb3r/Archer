package model

// PairAllowEntry is one tuple-scoped finding-filter rule. It hides
// findings whose (SrcIP, DstIP, DstPort) equals (Src, Dst, Port) — and,
// when FindingType is non-empty, only findings of that type. It is a
// pure view filter (see migrations/0017_pair_allowlist.sql): the rule
// is consulted at read/notify time, never at finding-emit time, so a
// rule add hides matching rows on the next fetch and a removal brings
// them back without re-analysis.
type PairAllowEntry struct {
	ID          int64  `json:"id"`
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	Port        string `json:"port"`
	FindingType string `json:"finding_type"` // "" = every type on the tuple
	Sensor      string `json:"sensor"`       // "" = every sensor on the tuple
	Detail      string `json:"detail"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
}
