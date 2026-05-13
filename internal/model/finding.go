package model

import "strings"

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
	// StatusDismissed is the analyst's "I don't want to see this
	// again" close — stronger than Acknowledged (which keeps the
	// finding visible in the Ack tab). Dismissed findings are
	// hidden from every default view and only appear in the
	// dedicated Dismissed tab (which is itself hidden unless the
	// operator's "Show Dismissed" toggle is on). Reversible via
	// the row's status menu. v0.18.0 lightweight Dismissed; a
	// future stronger version may suppress the fingerprint from
	// future analysis runs but this slice intentionally does not.
	StatusDismissed Status = "dismissed"
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
	// Hostname is the destination hostname the analyzer associated
	// with this finding at emit time. Populated for Beaconing
	// (from SNI via sslUIDIndex) and HTTP Beaconing (from the Host
	// header in http.log records). Empty when no hostname signal
	// was available — pure-IP beacons that don't observe DNS, SNI,
	// or Host headers get no Hostname. Consumed by the DGA
	// augmentation pass to decide whether the destination looks
	// algorithmic-shaped; future detectors (asset enrichment,
	// hostname-based correlation) can read it without re-deriving.
	Hostname string `json:"hostname,omitempty"`
	// Correlations carries the IDs of sibling findings that share this
	// finding's (SrcIP, DstIP) pair and contributed to a Correlated
	// Activity roll-up. Populated by the analyzer's correlation phase
	// on each contributor and on the Correlated Activity row itself.
	// Empty for findings that don't participate in a correlation. The
	// table UI surfaces a `+N correlated` chip when the slice is
	// non-empty so analysts can pivot from one detector's hit to the
	// other detectors firing on the same host pair.
	Correlations []int `json:"correlations,omitempty"`
	// URI is the request path the analyzer associated with this
	// finding at emit time. Populated for HTTP Beaconing (from the
	// http.log uri field). Empty for non-HTTP findings.
	URI string `json:"uri,omitempty"`
	// TSScore / DSScore / HistScore / DurScore are the four
	// per-axis sub-scores that compose the Beaconing and HTTP
	// Beaconing total score (each is in [0, 1]; total = sum × 25).
	// Populated by the conn and http_analysis emit sites; consumed
	// by SetFindings to write the beacon_history row. Not serialized
	// to the findings JSON API — analysts see them via the per-finding
	// history endpoint instead.
	//
	// LIFECYCLE: these fields are populated only at emit time. They
	// are NOT persisted to the findings table (no columns), so:
	//   - At server boot, loadFindings rebuilds in-memory Finding
	//     objects with all four zeroed.
	//   - SetFindings's preserve-historical loop carries forward
	//     historical findings with whatever values they had on disk —
	//     which is zero, since the table has no column.
	//   - Only this-run finding emissions carry non-zero sub-scores;
	//     by the time saveBeaconHistory reads them (immediately after
	//     emission in the same SetFindings call), they're correct.
	//   - Any future consumer reading these fields outside the
	//     emit → SetFindings critical section must guard on IsNew or
	//     join to beacon_history; the in-memory Finding object can't
	//     be trusted to carry the sub-scores after a server restart.
	//
	// NEW-89 from the twentieth audit round documented this rather
	// than adding columns — no consumer outside saveBeaconHistory
	// currently needs the persistence. Add the columns (migration
	// 0013) the first time a feature requires them.
	TSScore   float64 `json:"-"`
	DSScore   float64 `json:"-"`
	HistScore float64 `json:"-"`
	DurScore  float64 `json:"-"`
}

// BeaconHistoryKey is the per-beacon identity used by the
// beacon_history table. Distinct from Fingerprint() because the
// existing fingerprint omits Hostname and URI — fine for analyst-state
// preservation (one note per src→dst beacon family is what an analyst
// wants), but catastrophic for history: two HTTP Beacons to different
// URIs on the same (src, dst, port) would otherwise overwrite each
// other's history rows every UTC day.
//
// Canonical string form (NOT hashed): human-readable in SQLite-CLI for
// forensic inspection, self-describing without a join back to findings
// (which matters because beacon_history rows can outlive the finding
// row by the retention window), and trivially extensible if Finding
// grows new identity-bearing fields later.
//
// ASCII Unit Separator (\x1f) is the delimiter — never appears in
// valid URLs, hostnames, IPs, ports, or finding types in normal
// operation. We defensively scrub any embedded \x1f from the input
// fields anyway, replacing it with \x1e (Record Separator), because
// a compromised sensor could craft an HTTP Host header containing the
// literal byte to produce a key that collides with another beacon's
// row. The threat model accepts that compromised-sensor data is
// untrusted, but the cost of the defense (one strings.ContainsRune
// + maybe one strings.ReplaceAll per field) is small enough to be
// worth the collision-resistance. NEW-85 from the nineteenth audit
// round.
func (f Finding) BeaconHistoryKey() string {
	const sep = "\x1f"
	return strings.Join([]string{
		scrubSeparator(f.Type),
		scrubSeparator(f.SrcIP),
		scrubSeparator(f.DstIP),
		scrubSeparator(f.DstPort),
		scrubSeparator(f.Hostname),
		scrubSeparator(f.URI),
	}, sep)
}

// scrubSeparator replaces any literal \x1f byte (the BeaconHistoryKey
// delimiter) in s with \x1e. Cheap on the common path — strings.Contains
// returns false immediately on the typical hostname/IP and ReplaceAll is
// never called. Only the contrived crafted-input case allocates.
func scrubSeparator(s string) string {
	if !strings.ContainsRune(s, '\x1f') {
		return s
	}
	return strings.ReplaceAll(s, "\x1f", "\x1e")
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

// Notification is a UI alert surfaced through the bell icon. Kind
// disambiguates what the operator is being told about:
//   - "finding" carries a FindingID; the Jump button navigates to
//     that finding in the table. Emitted when a new finding scores
//     >= 99 (previously: every CRITICAL/TI finding, which was
//     noisy enough that operators learned to ignore the bell).
//   - "sensor" carries a Target (sensor name); the Jump button
//     opens the Sensors modal. Emitted when a sensor's last_seen
//     crosses the staleness threshold.
//   - "feed" carries a Target (feed name); the Jump button opens
//     the Feeds modal. Emitted when a feed's consecutive_failures
//     or staleness crosses the unhealthy threshold.
//
// Empty Kind reads as "finding" for backward compat with notifications
// persisted before the field existed. Detail is a human-readable
// description rendered under the type/severity line — sensor/feed
// alarms populate it; finding alarms leave it empty.
type Notification struct {
	ID        int    `json:"id"`
	Kind      string `json:"kind,omitempty"`
	Target    string `json:"target,omitempty"`
	Detail    string `json:"detail,omitempty"`
	FindingID int    `json:"finding_id"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	DstPort   string `json:"dst_port"`
	Dismissed bool   `json:"dismissed"`
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
		"DGA augmentation: +15 score, one-step severity upgrade when the destination Hostname's SLD has Shannon entropy > dga_entropy_threshold (default 3.5) AND bigram log-likelihood < dga_bigram_threshold (default -4.5). Detail tags 'DGA-suspect destination: <host> (SLD=..., entropy=..., bigram=...)'.\n" +
		"False positives: backup clients, update agents, NTP heartbeats.",

	"HTTP Beaconing": "Same multi-dimensional analysis as conn-level but on (src, host, URI path) triples.\n" +
		"ts+ds+hist+dur components — catches C2 over CDN where many IPs share one domain.\n" +
		"DGA augmentation applies on the destination Host header: +15 score / severity bump when SLD entropy and bigram log-likelihood both cross their thresholds.\n" +
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
