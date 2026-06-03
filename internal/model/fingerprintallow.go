package model

// FingerprintAllowEntry marks one TLS client fingerprint as benign so it drops
// out of the TLS Fingerprints inventory wall (see
// migrations/0032_fingerprint_allowlist.sql). Kind is "ja3" or "ja4"; the
// (Kind, Fingerprint) pair is unique. It is a pure view filter consulted at
// read time, never at emit time, and never overrides a known-bad C2 match — a
// C2 fingerprint stays on the wall even if an entry exists for it.
type FingerprintAllowEntry struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"` // "ja3" | "ja4"
	Fingerprint string `json:"fingerprint"`
	Note        string `json:"note"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
}
