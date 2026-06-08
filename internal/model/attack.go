package model

import (
	"encoding/json"
	"strings"
)

// AttackTechnique is a single MITRE ATT&CK technique a finding type maps to.
// ID is the technique or sub-technique identifier ("T1071", "T1071.004"),
// Name the human label, Tactic the ATT&CK tactic it sits under. The mapping
// is metadata about a finding's Type, not a stored property — see attackByType.
type AttackTechnique struct {
	ID     string
	Name   string
	Tactic string
}

// URL is the canonical attack.mitre.org page for the technique. Sub-technique
// IDs ("T1071.004") render as a nested path ("/techniques/T1071/004/"); the
// dot is the only segment separator, so a single replace is correct.
func (t AttackTechnique) URL() string {
	return "https://attack.mitre.org/techniques/" + strings.Replace(t.ID, ".", "/", 1) + "/"
}

// MarshalJSON emits id/name/tactic plus the derived url so the client (the
// templated window.ATTACK_MAP and the coverage endpoint) gets the link without
// re-deriving it — keeping the URL convention owned in one place.
func (t AttackTechnique) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Tactic string `json:"tactic"`
		URL    string `json:"url"`
	}{t.ID, t.Name, t.Tactic, t.URL()})
}

// Curated technique set. Archer's detectors live almost entirely on the
// network / C2 edge, so the mapping is dominated by Command and Control with
// a few Exfiltration / Lateral Movement entries — an honest reflection of
// what network telemetry can attribute.
var (
	tAppLayer  = AttackTechnique{"T1071", "Application Layer Protocol", "Command and Control"}
	tWebProto  = AttackTechnique{"T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"}
	tDNSProto  = AttackTechnique{"T1071.004", "Application Layer Protocol: DNS", "Command and Control"}
	tEncrypted = AttackTechnique{"T1573", "Encrypted Channel", "Command and Control"}
	tOddPort   = AttackTechnique{"T1571", "Non-Standard Port", "Command and Control"}
	tTunneling = AttackTechnique{"T1572", "Protocol Tunneling", "Command and Control"}
	tFronting  = AttackTechnique{"T1090.004", "Proxy: Domain Fronting", "Command and Control"}
	tDGA       = AttackTechnique{"T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control"}
	tIngress   = AttackTechnique{"T1105", "Ingress Tool Transfer", "Command and Control"}
	tExfilAlt  = AttackTechnique{"T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"}
	tSchedXfer = AttackTechnique{"T1029", "Scheduled Transfer", "Exfiltration"}
	tRemoteSvc = AttackTechnique{"T1021", "Remote Services", "Lateral Movement"}
)

// attackByType maps each finding Type to the ATT&CK technique(s) it most
// precisely evidences. A type that maps to nothing (TI hits, roll-ups, raw
// Zeek notices) is deliberately absent rather than forced onto a loose
// technique — see attackExemptTypes and TestEveryFindingTypeMappedOrExempt,
// which together guarantee a new finding type is consciously classified.
var attackByType = map[string][]AttackTechnique{
	"Beacon":                      {tAppLayer},
	"HTTP Beacon":                 {tWebProto},
	"DNS Beacon":                  {tDNSProto},
	"Port-Hopping Beacon":         {tAppLayer, tOddPort},
	"Strobe":                      {tAppLayer},
	"Long Connection":             {tAppLayer},
	"Data Exfiltration":           {tExfilAlt},
	"Off-Hours Transfer":          {tSchedXfer},
	"Lateral Movement":            {tRemoteSvc},
	"DNS Tunneling":               {tDNSProto, tExfilAlt},
	"DNS NXDOMAIN Flood":          {tDGA},
	"DNS Subdomain DGA":           {tDGA},
	"Protocol Anomaly":            {tAppLayer},
	"C2 Port":                     {tOddPort},
	"C2 URI Pattern":              {tWebProto},
	"Protocol on Unexpected Port": {tOddPort},
	"Cobalt Strike URI":           {tWebProto},
	"Domain Fronting":             {tFronting},
	"DoH Bypass":                  {tDNSProto, tTunneling},
	"Malicious JA3":               {tEncrypted},
	"Malicious JA4":               {tEncrypted},
	"Weak TLS":                    {tEncrypted},
	"SSL No-SNI":                  {tEncrypted},
	"SSL No-SNI on C2 Port":       {tEncrypted, tOddPort},
	"Suspicious Certificate":      {tEncrypted},
	"Suspicious File Download":    {tIngress},
	"Suspicious TLD":              {tAppLayer},
	"Suspicious UA":               {tWebProto},
	TypeSuspiciousURL:             {tWebProto},
	// Cross-host C2 staging evidences both the C2 channel and the lateral
	// hop that spread it — a specific technique pair, unlike the generic
	// roll-ups (Correlated Activity / HRS) which carry no single technique.
	TypeMultiStageBeacon: {tAppLayer, tRemoteSvc},
}

// attackExemptTypes are finding types that intentionally carry no ATT&CK
// technique: TI-feed matches (evidence of known-bad infrastructure, not a
// specific technique), analyzer roll-ups, and pass-through Zeek notices.
var attackExemptTypes = map[string]bool{
	TypeTIHitIP:            true,
	TypeTIHitDomain:        true,
	TypeTIHitHash:          true,
	TypeTIHitLegacy:        true,
	TypeHostRiskScore:      true,
	TypeCorrelatedActivity: true,
	"Zeek Notice":          true,
}

// AttackTechniquesFor returns the ATT&CK techniques a finding type maps to, or
// nil for an unmapped (exempt) type. Type strings are canonical, so the lookup
// is exact.
func AttackTechniquesFor(findingType string) []AttackTechnique {
	return attackByType[findingType]
}

// AttackMap returns the full finding-type → technique mapping, used to
// bootstrap the client (window.ATTACK_MAP) so the UI renders technique tags
// from a finding's Type without per-finding API bloat.
func AttackMap() map[string][]AttackTechnique {
	return attackByType
}
