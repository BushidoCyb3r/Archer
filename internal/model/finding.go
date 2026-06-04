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
	IOCSource string `json:"ioc_source,omitempty"`
	IsNew     bool   `json:"is_new"`
	// DetectedAt is the epoch-seconds wall-clock time this finding's
	// fingerprint first entered the store. Unlike IsNew — which the
	// SetFindings merge overwrites every run (fresh true, carried-forward
	// false) — DetectedAt is assigned once on first insert and carried
	// forward unchanged on every subsequent merge, like the stable ID.
	// It is the durable "new since when" anchor the per-user unseen count
	// (findings.detected_at > users.findings_seen_at) rests on. Persisted
	// as an INTEGER column (migration 0029).
	DetectedAt int64 `json:"detected_at,omitempty"`
	// IsNewToMe is the per-viewer "new since you last logged in" flag —
	// DetectedAt > the requesting session's new-findings boundary. Transient,
	// computed at read time by the list and single-finding handlers (never
	// persisted), like the sibling counts. It drives the table's blue "new"
	// dot and the detail pane's "new" flag, so those agree with the "New
	// only" filter and the new-findings modal — all four key off the same
	// boundary instead of the volatile per-run IsNew.
	IsNewToMe bool         `json:"is_new_to_me,omitempty"`
	Sensor    string       `json:"sensor,omitempty"`
	Intervals []float64    `json:"intervals,omitempty"`
	TSData    [][3]float64 `json:"ts_data,omitempty"`
	Notes     []Note       `json:"notes,omitempty"`
	// Hostname is the destination hostname the analyzer associated
	// with this finding at emit time. Populated for Beacon
	// (from SNI via sslUIDIndex) and HTTP Beacon (from the Host
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
	// finding at emit time. Populated for HTTP Beacon (from the
	// http.log uri field). Empty for non-HTTP findings.
	URI string `json:"uri,omitempty"`
	// TSScore / DSScore / HistScore / DurScore are the four per-axis
	// sub-scores that compose the Beacon and HTTP Beacon total
	// score (each is in [0, 1]; total = sum × 25). Populated by the
	// conn and http_analysis emit sites and serialized to the findings
	// JSON API so the detail-pane triage header can break the score
	// down by axis without a separate history fetch.
	//
	// Persisted as REAL columns on the findings table (migration 0018,
	// NEW-89 closure). They survive a server restart and the
	// preserve-historical carry-forward: loadFindings repopulates them
	// from the columns, so a beacon that didn't re-fire this run still
	// carries its real sub-scores instead of zeros. saveBeaconHistory
	// still reads them in the same SetFindings call that emitted them.
	TSScore   float64 `json:"ts_score,omitempty"`
	DSScore   float64 `json:"ds_score,omitempty"`
	HistScore float64 `json:"hist_score,omitempty"`
	DurScore  float64 `json:"dur_score,omitempty"`
	// MeanInterval / MedianInterval are the arithmetic mean and median
	// of the inter-arrival intervals (seconds) the timing scorer saw
	// for this beacon. Jitter is the coefficient of variation
	// (stddev / mean) of those intervals — the "± Ns" spread the
	// triage header renders as a percentage. SampleSize is the count
	// of observations the score is based on (connections for
	// Beacon, requests for HTTP Beacon) — the confidence signal.
	// Populated only for Beacon / HTTP Beacon; zero elsewhere.
	// Persisted alongside the sub-scores (migration 0018) for the same
	// restart-survival reason.
	MeanInterval   float64 `json:"mean_interval,omitempty"`
	MedianInterval float64 `json:"median_interval,omitempty"`
	Jitter         float64 `json:"jitter,omitempty"`
	SampleSize     int     `json:"sample_size,omitempty"`
	// JA3 / JA4 are the TLS client fingerprints of the connection that
	// seeded a conn-level Beacon finding, lifted from the sslUIDIndex
	// at emit time (the same index lookup that already resolves the SNI
	// into Hostname). Empty for non-TLS beacons, HTTP Beacon (http.log
	// is cleartext by construction — TLS lands in ssl.log, not http.log),
	// DNS Beacon, and every non-beacon type. JA4 stays empty unless
	// the sensor's Zeek emits a ja4 field (stock ssl.log is ja3/ja3s; JA4
	// needs the JA4+ plugin) — read opportunistically, never required.
	// Persisted as TEXT columns (migration 0019) for the same restart-
	// survival reason as the 0018 triage fields: a carried-forward beacon
	// that didn't re-fire this run still carries its fingerprint instead
	// of blanking out.
	JA3 string `json:"ja3,omitempty"`
	JA4 string `json:"ja4,omitempty"`
	// Channel discriminates a per-channel conn Beacon sub-finding from the
	// blended (sensor,src,dst) beacon it was split out of. Empty on the blend
	// and on every other finding type; set to "ja3:<hash>" (or "sni:<host>")
	// on a promoted channel — a coherent TLS channel to the same destination
	// that scores materially sharper than the noisy blend, i.e. a secondary
	// beacon the aggregation was hiding. It enters the Fingerprint so the
	// channel keeps independent analyst state and never collides with the
	// blend across re-analyses. Persisted as a TEXT column (migration 0035).
	Channel string `json:"channel,omitempty"`
	// JA3SiblingCount / JA4SiblingCount are transient, derived-at-read
	// fields — the count of OTHER beacon findings in the current dataset
	// sharing the same JA3 or JA4. Computed by the single-finding detail
	// handler, never persisted. The detail render gates each fingerprint
	// block on the field being non-empty, so an omitted-because-zero
	// count reads correctly as "matched 0 other beacons".
	JA3SiblingCount int `json:"ja3_sibling_count,omitempty"`
	JA4SiblingCount int `json:"ja4_sibling_count,omitempty"`
	// FPConcern / FPDetail are transient, derived-at-read fields describing how
	// rare a conn-level beacon's TLS client fingerprint is across ALL ssl.log
	// (not just emitted beacons) and whether it clusters across multiple internal
	// hosts. FPConcern is a severity-style level ("critical"/"high"/"medium"/
	// "low"/"none") that drives the detail-pane row colour; FPDetail is the
	// human-readable summary. Computed by the single-finding detail handler from
	// the store's per-fingerprint prevalence snapshot, never persisted — and
	// blank until the next full analysis repopulates that snapshot after a
	// restart (same transient contract as the sibling counts).
	FPConcern string `json:"fp_concern,omitempty"`
	FPDetail  string `json:"fp_detail,omitempty"`
	// TopURIs is the HTTP Beacon destination's request-path
	// footprint: the most-frequent paths the same (sensor,src,dst,host)
	// group beaconed on, count-descending, capped. Stamped identically
	// on every HTTP Beacon finding in the group at emit time, so the
	// one that survives the (Type,src,dst,port) fingerprint dedup still
	// carries the full footprint regardless of which single path scored
	// highest — deriving it from the surviving finding's own URI would
	// reintroduce the dedup blind spot. Persisted as a JSON TEXT column
	// (migration 0020) for the same restart / carry-forward survival
	// reason as the JA3 fields. Empty for every non-HTTP-Beacon type.
	TopURIs []URIStat `json:"top_uris,omitempty"`
	// SpectralRescued / SpectralPeriod are set at emit time when the
	// Lomb-Scargle periodogram rescued a beacon whose ts score fell below
	// SpectralRescueThreshold. Not persisted on the findings table — only
	// written to beacon_history (migration 0023) so the evolution chart
	// can mark spectral-rescued days. json:"-" keeps them out of the
	// /api/findings response; the history endpoint surfaces them instead.
	SpectralRescued bool    `json:"-"`
	SpectralPeriod  float64 `json:"-"`
	// TSRaw / TSMultimodal / TSEntropy are the individual timing-axis
	// layer scores captured before max() collapse. In-memory only —
	// written to beacon_history (migration 0024) for longitudinal layer
	// validation. json:"-" keeps them out of the /api/findings response.
	TSRaw        float64 `json:"-"`
	TSMultimodal float64 `json:"-"`
	TSEntropy    float64 `json:"-"`
}

// URIStat is one request path and the number of requests an HTTP
// beacon made to it. Slice element of Finding.TopURIs.
type URIStat struct {
	URI   string `json:"uri"`
	Count int    `json:"count"`
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
	parts := []string{
		scrubSeparator(f.Type),
		scrubSeparator(f.SrcIP),
		scrubSeparator(f.DstIP),
		scrubSeparator(f.DstPort),
		scrubSeparator(f.Hostname),
		scrubSeparator(f.URI),
		scrubSeparator(f.Sensor),
	}
	// Channel keeps a promoted per-channel beacon's evolution history on its
	// own track rather than colliding with the blend's (both share
	// src/dst/port/sensor). Appended only when set, so the blend's key — and
	// every existing on-disk beacon_history key — is byte-for-byte unchanged.
	if f.Channel != "" {
		parts = append(parts, scrubSeparator(f.Channel))
	}
	return strings.Join(parts, sep)
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

// IsBeaconType reports whether a finding type carries the migration-0018
// triage fields (the four ts/ds/hist/dur sub-scores + mean/median/jitter/
// sample_size). DNS Beacon leaves DSScore a structural zero — it has no
// data-size axis — but still populates the rest, so it counts. Bare string
// literals rather than constants: the analyzer emit sites use the literals
// directly and introducing a constant set is a wider refactor than this
// helper's callers (sub-score filter scope, JA3 cross-ref, beacon export)
// justify.
func IsBeaconType(t string) bool {
	switch t {
	case "Beacon", "HTTP Beacon", "DNS Beacon", "Port-Hopping Beacon":
		return true
	}
	return false
}

// knownFindingTypes is the closed vocabulary of Type strings the analyzer
// can emit, plus the legacy "Threat Intel Hit" string old DBs still carry.
// The query language validates an exact `type:` term against this set so a
// misspelling (type:"Correlatd Activity") is rejected at the query bar
// instead of silently matching nothing.
//
// This is a second home for type strings that otherwise live as literals at
// the detector emit sites — a new finding type MUST be registered here or
// exact `type:` queries for it get falsely rejected. TestIsKnownFindingType
// guards the constant-backed entries against drift.
var knownFindingTypes = map[string]bool{
	"Beacon": true, "HTTP Beacon": true, "DNS Beacon": true,
	"Port-Hopping Beacon": true,
	"Strobe":              true, "Long Connection": true, "Data Exfiltration": true,
	"Off-Hours Transfer": true, "Lateral Movement": true,
	"DNS Tunneling": true, "DNS NXDOMAIN Flood": true, "DNS Subdomain DGA": true,
	"Protocol Anomaly": true, "C2 Port": true, "C2 URI Pattern": true,
	"Cobalt Strike URI": true, "Domain Fronting": true, "DoH Bypass": true,
	"Malicious JA3": true, "Malicious JA4": true, "Weak TLS": true,
	"SSL No-SNI": true, "SSL No-SNI on C2 Port": true,
	"Suspicious Certificate": true, "Suspicious File Download": true,
	"Suspicious TLD": true, "Suspicious UA": true,
	"Zeek Notice":     true,
	TypeSuspiciousURL: true,
	TypeTIHitIP:       true, TypeTIHitDomain: true, TypeTIHitHash: true,
	TypeTIHitLegacy:   true,
	TypeHostRiskScore: true, TypeCorrelatedActivity: true,
}

// IsKnownFindingType reports whether t is a finding type the analyzer can
// emit, matched case-insensitively (type:beacon resolves to "Beacon"). The
// query language uses it to reject a misspelled exact `type:` term; the
// `type:beacons` family selector and the bare-term path don't reach here.
func IsKnownFindingType(t string) bool {
	if knownFindingTypes[t] {
		return true
	}
	for k := range knownFindingTypes {
		if strings.EqualFold(k, t) {
			return true
		}
	}
	return false
}

// FingerprintStat is the per-TLS-client-fingerprint prevalence over one
// analysis pass — every ssl.log connection, not just emitted beacons:
// total connections, distinct internal source hosts, distinct destinations.
// Built by the analyzer, handed to the store, and consulted at read time to
// derive Finding.FPConcern / FPDetail.
type FingerprintStat struct {
	Conns    int
	SrcHosts int
	Dsts     int
}

// FingerprintRow is one entry in the TLS-fingerprint inventory: a single JA3 or
// JA4 client fingerprint with its prevalence over the latest analysis pass, the
// derived concern Level, the known-bad C2 Label (when matched), and the count
// of resident findings carrying it. The inventory endpoint ranks these by
// severity; the TLS Fingerprints modal renders them as a fingerprint-first
// pivot surface into findings.
type FingerprintRow struct {
	Fingerprint  string `json:"fingerprint"`
	Kind         string `json:"kind"`  // "ja3" | "ja4"
	Level        string `json:"level"` // critical | high | medium
	KnownBad     bool   `json:"known_bad"`
	Label        string `json:"label,omitempty"`
	Conns        int    `json:"conns"`
	SrcHosts     int    `json:"src_hosts"`
	Dsts         int    `json:"dsts"`
	FindingCount int    `json:"finding_count"`
	// Detail is the count-free qualitative reason ("Rare client, clustered
	// across hosts") — the modal shows the prevalence counts in their own
	// columns, so the prose stays judgment-only.
	Detail string `json:"detail,omitempty"`
}

// Fingerprint uniquely identifies a finding for delta/baseline comparison.
// Hostname and URI are only populated for HTTP Beacon, where two beacons
// to different hosts or paths on the same (src, dst, port, sensor) are
// genuinely distinct findings with independent analyst state. All other types
// leave them empty, preserving the existing identity contract.
type Fingerprint struct {
	Type     string
	SrcIP    string
	DstIP    string
	DstPort  string
	Sensor   string
	Hostname string
	URI      string
	Channel  string
}

func (f Finding) Fingerprint() Fingerprint {
	fp := Fingerprint{Type: f.Type, SrcIP: f.SrcIP, DstIP: f.DstIP, DstPort: f.DstPort, Sensor: f.Sensor}
	if f.Type == "HTTP Beacon" {
		fp.Hostname = f.Hostname
		fp.URI = f.URI
	}
	// A per-channel conn Beacon carries a Channel discriminator so it keeps
	// identity (and analyst state) separate from the blended beacon at the
	// same (src,dst,port,sensor). The blend leaves Channel empty, preserving
	// its existing fingerprint.
	if f.Channel != "" {
		fp.Channel = f.Channel
	}
	return fp
}

// Notification is a UI alert. Kind controls where it surfaces:
//   - "finding" surfaces in the bell panel. Carries a FindingID; the
//     Jump button navigates to that finding in the table. Emitted when
//     a new finding scores >= 95 (previously every CRITICAL/TI finding,
//     which was noisy enough that operators learned to ignore the bell).
//   - "sensor" surfaces as a count badge on the Sensors nav button.
//     Carries a Target (sensor name); clicking the button opens the
//     Sensors modal and clears the badge. Emitted when a sensor's
//     last_seen crosses the staleness threshold.
//   - "feed" surfaces as a count badge on the Feeds nav button.
//     Carries a Target (feed name); clicking the button opens the
//     Feeds modal and clears the badge. Emitted when a feed's
//     consecutive_failures or staleness crosses the unhealthy threshold.
//
// Empty Kind reads as "finding" for backward compat with notifications
// persisted before the field existed. Detail is a human-readable
// description — sensor/feed alarms populate it; finding alarms leave
// it empty.
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
	Sensor    string `json:"sensor,omitempty"`
	Dismissed bool   `json:"dismissed"`
}

// ScoreExplanations provides analyst context for each detection type.
var ScoreExplanations = map[string]string{
	"Beacon": "Score = ts×0.25 + ds×0.25 + hist×0.25 + dur×0.25 (0–100)\n" +
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

	"Port-Hopping Beacon": "Same scoring as Beacon — this is a Beacon that spreads across many destination ports.\n" +
		"Relabel (not a re-score): a (sensor, src, dst) pair already qualified as a beacon, then was found to span ≥5 dst ports with no single port carrying ≥50% of connections.\n" +
		"The port deliberately isn't part of the beacon key, so a hopper is caught as one beacon today; this type just names the evasion shape.\n" +
		"Detail tags 'Port-hopping: N dst ports [...], no dominant port (max X%)'.\n" +
		"False positives: clients that legitimately fan out across an ephemeral-port service (some P2P, some RPC frameworks).",

	"HTTP Beacon": "Same multi-dimensional analysis as conn-level but on (src, host, URI path) triples.\n" +
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
		"Covers: Cobalt Strike (multiple profiles), Metasploit, Sliver, Brute Ratel.\n" +
		"Deprecated: ecosystem moving to JA4; sensor must run Zeek JA4+ plugin for JA4 coverage.",

	"Malicious JA4": "Score: 95 (known C2 malware TLS ClientHello fingerprint — JA4 format)\n" +
		"JA4 is the structured successor to JA3 (FoxIO, 2023): prefix encodes TLS version,\n" +
		"cipher count, extension count, and ALPN — more stable than MD5 JA3.\n" +
		"Covers: Cobalt Strike v4.9.1 (wininet/winhttp, SNI/no-SNI variants), IcedID loader.\n" +
		"Requires sensor running the Zeek JA4+ plugin; stock ssl.log only has ja3/ja3s.\n" +
		"Source: FoxIO public JA4+ database (github.com/FoxIO-LLC/ja4).",

	"Strobe": "Score = 50 + log10(count)×15, capped at 88\n" +
		"Triggered when connection count to single dst IP exceeds threshold.",

	"Data Exfiltration": "Score = 55 + log10(MB_out+1)×12, capped at 92\n" +
		"Triggered when: outbound bytes > min_MB AND out/in ratio > threshold.",

	"Lateral Movement": "Score: 78 (internal→internal on administrative protocol)\n" +
		"Both src and dst are RFC-1918. Port in: 445/SMB 3389/RDP 135/WMI 5985-5986/WinRM 22/SSH",

	"Off-Hours Transfer": "Score = 45 + log10(MB+1)×12, capped at 78\n" +
		"Flags external transfers > min_MB outside business hours (UTC).",

	"DNS Tunneling": "Per-query: long label, high entropy, or deep nesting per query.\n" +
		"Tools: iodine, DNScat2, dns2tcp",

	"DNS Subdomain DGA": ">N unique subdomains under a single apex with high average entropy.\n" +
		"Shape: DGA/fast-flux C2 rotating subdomains; distinct from per-query tunneling.",

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
		"Beacon +30 | HTTP Beacon +28 | CS URI +40 | C2 URI Pattern +38\n" +
		"Domain Fronting +32 | Malicious JA3 +40 | Malicious JA4 +40 | TI Hit +35 | Exfiltration +25\n" +
		"CRITICAL ≥75 | HIGH ≥50 | MEDIUM ≥25",

	"Correlated Activity": "Cross-detector roll-up: same (src, dst) pair, ≥N distinct detector types\n" +
		"N defaults to 2 (correlation_min_types). Catches kill-chain progression:\n" +
		"Beacon + DNS Tunneling, Suspicious File + TI Hit (Hash), etc.\n" +
		"Score = max(contributor scores) + 5 per extra distinct type above N, capped 99.\n" +
		"Contributing findings get a `+N corr` chip linking back to this roll-up.\n" +
		"Excluded from contribution: Host Risk Score, Correlated Activity (recursion), Zeek Notice, Long Connection.",

	"Zeek Notice": "Score: 92 (attack notices) | 68 (general)\n" +
		"Zeek policy script detections: Sensitive_Signature, Scan, Attack, Brute.",
}
