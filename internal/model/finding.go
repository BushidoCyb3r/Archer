package model

import (
	"regexp"
)

type Severity string
type Status string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"

	StatusOpen         Status = ""
	StatusAcknowledged Status = "acknowledged"
	StatusEscalated    Status = "escalated"
)

// Finding is a single detection result.
type Finding struct {
	ID          int      `json:"id"`
	Type        string   `json:"type"`
	Severity    Severity `json:"severity"`
	Score       int      `json:"score"`
	SrcIP       string   `json:"src_ip"`
	DstIP       string   `json:"dst_ip"`
	DstPort     string   `json:"dst_port"`
	Detail      string   `json:"detail"`
	Timestamp   string   `json:"timestamp"`
	SourceFile  string   `json:"source_file"`
	Status      Status   `json:"status"`
	Analyst     string   `json:"analyst"`
	AnalystNote string   `json:"analyst_note"`
	StatusTS    string   `json:"status_ts"`
	IOCMatch    bool     `json:"ioc_match"`
	// IOCSource names which list flagged the indicator: "Operator IOC list"
	// or "Feed: <feed name>". Computed at /api/findings read time from the
	// current Store snapshot — not persisted, since feed indicators age
	// out and can switch source on the next refresh. Empty when IOCMatch
	// is false. TI Hit / Suspicious URL findings (intrinsic IOCs per
	// the analyzer) get "Threat Intel" as the source label.
	IOCSource string       `json:"ioc_source,omitempty"`
	IsNew     bool         `json:"is_new"`
	Sensor    string       `json:"sensor,omitempty"`
	Intervals []float64    `json:"intervals,omitempty"`
	TSData    [][3]float64 `json:"ts_data,omitempty"`
	Notes     []Note       `json:"notes,omitempty"`
	// Correlations carries the IDs of sibling findings that share this
	// finding's (SrcIP, DstIP) pair and contributed to a Correlated
	// Activity roll-up. Populated by the analyzer's correlation phase
	// on each contributor and on the Correlated Activity row itself.
	// Empty for findings that don't participate in a correlation. The
	// table UI surfaces a `+N correlated` chip when the slice is
	// non-empty so analysts can pivot from one detector's hit to the
	// other detectors firing on the same host pair.
	Correlations []int `json:"correlations,omitempty"`
}

// Threat-intel finding types. Split into IP / Domain / Hash flavors in
// v0.7.0 so the Type filter dropdown surfaces them separately. The
// legacy "Threat Intel Hit" string is recognized too — it covers any
// findings persisted from pre-v0.7.0 builds.
const (
	TypeTIHitIP       = "TI Hit (IP)"
	TypeTIHitDomain   = "TI Hit (Domain)"
	TypeTIHitHash     = "TI Hit (Hash)"
	TypeSuspiciousURL = "Suspicious URL"
	TypeTIHitLegacy   = "Threat Intel Hit" // pre-v0.7.0 — kept recognized so old DBs still classify correctly
)

// Roll-up finding types — analyzer outputs derived from the rest of
// the finding set rather than from a single Zeek record. Two
// properties distinguish them:
//  1. They have an authoritative regeneration phase in the analyzer
//     (aggregateRisk for HRS, correlateFindings for Correlated
//     Activity), so SetFindings's preserve-historical loop must
//     purge stale instances whose contributing findings are gone —
//     otherwise an orphan row lingers indefinitely.
//  2. They must not feed themselves: aggregateRisk excludes Host
//     Risk Score from its contributor set, correlateFindings
//     excludes both itself and Host Risk Score from its eligible
//     types. The recursive-feedback hazard is the same shape NEW-67
//     documented for HRS.
const (
	TypeHostRiskScore      = "Host Risk Score"
	TypeCorrelatedActivity = "Correlated Activity"
)

// IsRollupType reports whether a finding type is an analyzer roll-up
// rather than a per-record detection. Used by Store.SetFindings to
// drop stale roll-up rows whose fingerprints aren't regenerated this
// run — preserving them would leave orphans behind once their
// underlying detections age out or get archived.
func IsRollupType(t string) bool {
	switch t {
	case TypeHostRiskScore, TypeCorrelatedActivity:
		return true
	}
	return false
}

// IsThreatIntelType reports whether a finding type is feed-driven —
// the IOC Hits tab, notification eligibility, IOC export filter, and
// the TI cross-annotator all hinge on this. Recognizing all flavors
// (and the legacy unified type) keeps both new and old findings
// classified consistently.
func IsThreatIntelType(t string) bool {
	switch t {
	case TypeTIHitIP, TypeTIHitDomain, TypeTIHitHash, TypeSuspiciousURL, TypeTIHitLegacy:
		return true
	}
	return false
}

// Fingerprint uniquely identifies a finding for delta/baseline comparison.
type Fingerprint struct {
	Type    string
	SrcIP   string
	DstIP   string
	DstPort string
}

func (f Finding) Fingerprint() Fingerprint {
	return Fingerprint{Type: f.Type, SrcIP: f.SrcIP, DstIP: f.DstIP, DstPort: f.DstPort}
}

// Notification is a UI alert for CRITICAL/TI findings.
type Notification struct {
	ID        int    `json:"id"`
	FindingID int    `json:"finding_id"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	DstPort   string `json:"dst_port"`
	Dismissed bool   `json:"dismissed"`
}

// KnownC2Ports maps port numbers to C2/malware labels.
var KnownC2Ports = map[int]string{
	1080:  "SOCKS proxy",
	3128:  "HTTP proxy (Squid)",
	4444:  "Metasploit default",
	4445:  "Metasploit alt",
	4899:  "Radmin RAT",
	6666:  "IRC / C2",
	6667:  "IRC",
	6668:  "IRC",
	6669:  "IRC",
	8008:  "C2 generic",
	8888:  "C2 / JupyterLab",
	9001:  "Tor relay",
	9030:  "Tor directory",
	31337: "Back Orifice / Elite",
}

// KnownBadJA3 maps JA3 hashes to C2 framework labels.
var KnownBadJA3 = map[string]string{
	"72a589da586844d7f0818ce684948eea": "Cobalt Strike beacon",
	"a0e9f5192cc6583673b72155f5a851c1": "Cobalt Strike SMB",
	"e7d705a3286e19ea42f587b344ee6865": "Metasploit/Meterpreter",
	"bc6c386f480f367c02e5d7c0f31d6b3b": "Meterpreter reverse",
	"6d4a5f8b3a7c9e1d2f0b4a8c3e5f7d9a": "C2 framework generic",
	"1aa7bf3b03eb4b20e561a3c9fe46e04a": "Cobalt Strike v4",
	"b386946a5a44d1ddcc843bc75336dfce": "Sliver C2",
	"6bea65232daa92d19e56f2a8c62b2ebf": "Cobalt Strike Malleable",
	"d0ec4b50a944b182f9159c61f5e00da4": "Brute Ratel",
	"f4febc55ea12b31ae17cfb7e8028f33c": "Brute Ratel alt",
}

// SuspiciousTLDs is the set of free/abused TLDs.
var SuspiciousTLDs = map[string]bool{
	".tk": true, ".ml": true, ".ga": true, ".cf": true, ".gq": true,
	".top": true, ".xyz": true, ".pw": true, ".cc": true, ".to": true,
	".biz": true, ".icu": true, ".club": true, ".live": true, ".work": true,
	".date": true, ".download": true, ".racing": true, ".review": true,
	".science": true, ".trade": true, ".win": true, ".stream": true,
	".faith": true, ".men": true, ".loan": true,
}

// WeakTLSVersions is the set of deprecated TLS protocol identifiers.
var WeakTLSVersions = map[string]bool{
	"SSLv2": true, "SSLv3": true, "TLSv10": true, "TLSv11": true,
}

// DoHIPs is the set of known DNS-over-HTTPS resolver IPs.
var DoHIPs = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true,
	"1.1.1.1": true, "1.0.0.1": true,
	"9.9.9.9": true, "149.112.112.112": true,
	"208.67.222.222": true, "208.67.220.220": true,
	"94.140.14.14": true, "94.140.15.15": true,
	"76.76.19.19": true, "76.223.122.150": true,
}

// DefaultCertSubjects are generic certificate subject strings indicating default tool output.
var DefaultCertSubjects = []string{
	"internet widgits", "example.com", "localhost",
	"default company", "my company", "test", "acme",
	"openssl", "self-signed", "ca-cert",
}

// C2URIPattern is a compiled C2 URI regex with a label.
type C2URIPattern struct {
	Re    *regexp.Regexp
	Label string
}

// C2URIPatterns are compiled at init time.
var C2URIPatterns []C2URIPattern

func init() {
	patterns := []struct{ pattern, label string }{
		{`^/submit\.php$`, "Cobalt Strike /submit.php"},
		{`^/ca$`, "Cobalt Strike /ca"},
		{`^/dpixel$`, "Cobalt Strike /dpixel"},
		{`^/pixel\.gif$`, "Cobalt Strike /pixel.gif"},
		{`^/ptj$`, "Cobalt Strike /ptj"},
		{`^/j\.ad$`, "Cobalt Strike /j.ad"},
		{`^/updates\.rss$`, "Cobalt Strike /updates.rss"},
		{`^/news\.php$`, "Empire /news.php"},
		{`^/admin/get\.php$`, "Empire /admin/get.php"},
		{`^/login/process\.php$`, "Empire /login/process.php"},
		{`^/[a-zA-Z0-9]{8}$`, "Metasploit stager (8-char alphanumeric)"},
	}
	for _, p := range patterns {
		C2URIPatterns = append(C2URIPatterns, C2URIPattern{
			Re:    regexp.MustCompile(p.pattern),
			Label: p.label,
		})
	}
}

// SuspiciousUAPatterns are substrings that identify scripting/automation user agents.
var SuspiciousUAPatterns = []string{
	"python-requests", "python-urllib", "curl/", "wget/",
	"go-http-client", "powershell", "libwww-perl",
}

// SuspiciousFileExts are file extensions that indicate executable/script downloads.
var SuspiciousFileExts = map[string]bool{
	".exe": true, ".dll": true, ".bat": true, ".ps1": true,
	".vbs": true, ".js": true, ".hta": true, ".scr": true,
	".sh": true, ".elf": true, ".com": true, ".msi": true,
}

// SuspiciousMIMETypes are MIME types indicating executable content.
var SuspiciousMIMETypes = map[string]bool{
	"application/x-dosexec":       true,
	"application/x-executable":    true,
	"application/x-elf":           true,
	"application/x-msdos-program": true,
	"application/octet-stream":    true,
}

// LateralMovementPorts are ports used for internal admin protocols.
var LateralMovementPorts = map[int]bool{
	445: true, 3389: true, 135: true, 5985: true, 5986: true, 22: true,
}

// ScoreExplanations provides analyst context for each detection type.
var ScoreExplanations = map[string]string{
	"Beaconing": "Score = ts×0.25 + ds×0.25 + hist×0.25 + dur×0.25 (0–100)\n" +
		"ts = max(Bowley+MAD on intervals, multimodal log2-bucket peaks, entropy of bucket occupancy, spectral rescue)\n" +
		"  Spectral rescue: Lomb-Scargle periodogram over reservoir timestamps, runs when ts < SpectralRescueThreshold (default 0.5)\n" +
		"  Catches jittered C2 (σ/period < 0.45) where the interval distribution defeats statistical scoring\n" +
		"ds = statistical score on orig byte counts\n" +
		"hist = histogram regularity (CV + bimodal) over 24 time buckets\n" +
		"dur = temporal persistence (coverage + consecutive-run consistency)\n" +
		"CRITICAL ≥ 80 | HIGH < 80\n" +
		"Detail tags 'Spectral rescue: period≈Xs' when the frequency-domain path won.\n" +
		"False positives: backup clients, update agents, NTP heartbeats.",

	"HTTP Beaconing": "Same multi-dimensional analysis as conn-level but on (src, host, URI path) triples.\n" +
		"ts+ds+hist+dur components — catches C2 over CDN where many IPs share one domain.\n" +
		"False positives: telemetry endpoints, analytics beacons, keepalive polls.",

	"Domain Fronting": "Score: 88 (fixed — SSL SNI ≠ HTTP Host header)\n" +
		"SSL SNI = visible domain at TLS layer (CDN edge)\n" +
		"HTTP Host = actual destination hidden inside encrypted stream.",

	"Cobalt Strike URI": "Score: 93 (checksum8 match on URI path)\n" +
		"Algorithm: sum(ord(c) for c in uri_path) % 256\n" +
		"92 = x86 payload | 93 = x64 payload",

	"C2 URI Pattern": "Score: 91 (regex match on known framework default paths)\n" +
		"Cobalt Strike: /submit.php /ca /dpixel /pixel.gif /ptj /j.ad /updates.rss\n" +
		"Empire: /news.php /admin/get.php /login/process.php\n" +
		"Metasploit: 8-char alphanumeric stager paths",

	"Malicious JA3": "Score: 95 (known C2 framework TLS ClientHello fingerprint)\n" +
		"Covers: Cobalt Strike (multiple profiles), Metasploit, Sliver, Brute Ratel.",

	"Strobe": "Score = 50 + log10(count)×15, capped at 88\n" +
		"Triggered when connection count to single dst IP exceeds threshold.",

	"Data Exfiltration": "Score = 55 + log10(MB_out+1)×12, capped at 92\n" +
		"Triggered when: outbound bytes > min_MB AND out/in ratio > threshold.",

	"Lateral Movement": "Score: 78 (internal→internal on administrative protocol)\n" +
		"Both src and dst are RFC-1918. Port in: 445/SMB 3389/RDP 135/WMI 5985-5986/WinRM 22/SSH",

	"Off-Hours Transfer": "Score = 45 + log10(MB+1)×12, capped at 78\n" +
		"Flags external transfers > min_MB outside business hours (UTC).",

	"DNS Tunneling": "Per-query: long label, high entropy, deep nesting, TXT/NULL type.\n" +
		"Diversity: >N unique subdomains per apex with high average entropy.\n" +
		"Tools: iodine, DNScat2, dns2tcp",

	"DNS NXDOMAIN Flood": "Score = 45 + log10(count)×15, capped at 85\n" +
		"High NXDOMAIN rate = DGA malware cycling through generated domains.",

	"Suspicious TLD": "Score: 52 (medium confidence supporting indicator)\n" +
		"Free/abused TLDs: .tk .ml .ga .cf .gq — Freenom free zones.",

	"DoH Bypass": "Score: 62 (TLS to known DoH resolver on 443)\n" +
		"Malware uses DoH to evade DNS sinkholes/RPZ, hide C2 lookups.",

	"Long Connection": "Score = 50 + hours/8, capped at 95 | HIGH >24h | MEDIUM 1-24h\n" +
		"Persistent TCP/UDP sessions: reverse shells, VPN tunnels, C2 sessions.",

	"C2 Port": "Score: 75 (connection to default C2/malware listener ports)\n" +
		"4444 Metasploit | 4899 Radmin | 6666-6669 IRC | 9001/9030 Tor | 31337 BO",

	"SSL No-SNI on C2 Port": "Score: 82 (established TLS with no SNI on known C2 port)\n" +
		"Legitimate HTTPS always includes SNI for virtual hosting.",

	"SSL No-SNI": "Score: 35 (LOW — supporting indicator only)\n" +
		"Established TLS with no SNI on non-standard non-C2 port.",

	"Weak TLS": "Score: 48 (deprecated protocol: SSLv2/SSLv3/TLS1.0/TLS1.1)",

	"Suspicious UA": "Score: 30 (LOW — scripting UAs: python-requests, curl, wget, Go-http-client, PowerShell)",

	"Suspicious Certificate": "Score: 58 (self-signed, default subject, short validity <48h, or >10 years)",

	"Suspicious File Download": "Score: 72 (executable or script MIME type / extension in files.log)",

	"Protocol Anomaly": "Score: 65 (HIGH-interest) | 22 (general) from Zeek weird.log",

	"TI Hit (IP)":     "Score: 97-99 (CRITICAL) for FeodoTracker / URLhaus | variable for OTX/AbuseIPDB | 90 (HIGH) for MISP/OpenCTI feed IP/CIDR matches.",
	"TI Hit (Domain)": "Score: 97 (CRITICAL) for URLhaus host matches | 90 (HIGH) for MISP/OpenCTI feed domain matches.",
	"TI Hit (Hash)":   "Score: 90 (HIGH). md5 / sha1 / sha256 from files.log matched against MISP/OpenCTI hash indicators.",

	"Host Risk Score": "Composite weighted sum, capped at 99\n" +
		"Beaconing +30 | HTTP Beaconing +28 | CS URI +40 | C2 URI Pattern +38\n" +
		"Domain Fronting +32 | Malicious JA3 +40 | TI Hit +35 | Exfiltration +25\n" +
		"CRITICAL ≥75 | HIGH ≥50 | MEDIUM ≥25",

	"Correlated Activity": "Cross-detector roll-up: same (src, dst) pair, ≥N distinct detector types\n" +
		"N defaults to 2 (correlation_min_types). Catches kill-chain progression:\n" +
		"Beaconing + DNS Tunneling, Suspicious File + TI Hit (Hash), etc.\n" +
		"Score = max(contributor scores) + 5 per extra distinct type above N, capped 99.\n" +
		"Contributing findings get a `+N corr` chip linking back to this roll-up.\n" +
		"Excluded from contribution: Host Risk Score, Correlated Activity (recursion), Zeek Notice, Long Connection.",

	"Zeek Notice": "Score: 92 (attack notices) | 68 (general)\n" +
		"Zeek policy script detections: Sensitive_Signature, Scan, Attack, Brute.",
}
