package config

// Config holds all tunable analysis thresholds.
type Config struct {
	BeaconMinConnections  int     `json:"beacon_min_connections"`
	HTTPBeaconMinRequests int     `json:"http_beacon_min_requests"`
	LongConnMinHours      float64 `json:"long_conn_min_hours"`
	// StrobeMinConnections is the minimum connection count before the rate gate
	// is evaluated. Acts as a count floor so a brief high-rate burst over a tiny
	// window doesn't mislabel a single rogue packet as a Strobe. Default 100.
	StrobeMinConnections int `json:"strobe_min_connections"`
	// StrobeMinRatePerSec is the average connection rate (connections/second)
	// at or above which a pair is classified as Strobe. Both conditions must
	// hold. This gate is the critical discriminator on long captures: a
	// 60-second C2 beacon over 30 days accumulates ~43,200 connections at
	// 0.017/s — well below this threshold — and must reach the beacon scorer.
	// A port scanner or high-rate automated tool hits ≥0.5/s. Default 0.5.
	StrobeMinRatePerSec   float64 `json:"strobe_min_rate_per_sec"`
	ExfilMinBytesMB       float64 `json:"exfil_min_bytes_mb"`
	ExfilRatioThreshold   float64 `json:"exfil_ratio_threshold"`
	OffHoursStart         int     `json:"off_hours_start"`
	OffHoursEnd           int     `json:"off_hours_end"`
	OffHoursMinMB         float64 `json:"off_hours_min_mb"`
	DNSTunnelLabelLen     int     `json:"dns_tunnel_label_len"`
	DNSTunnelEntropy      float64 `json:"dns_tunnel_entropy"`
	DNSTunnelMinDepth     int     `json:"dns_tunnel_min_depth"`
	DNSNXDomainThreshold  int     `json:"dns_nxdomain_threshold"`
	DNSUniqueSubdomainMin int     `json:"dns_unique_subdomain_min"`
	// DNSBeaconMinQueries is the minimum number of queries to a single
	// (src, apex) pair before the DNS-cadence beacon detector scores it.
	// A sample-size floor, not a calibration knob — the timing/spectral
	// math reuses the global beacon knobs — so it's a per-deployment
	// Settings field like BeaconMinConnections / HTTPBeaconMinRequests.
	// Default 20: high enough that an incidental browse burst to one
	// apex (chatty but irregular, rejected by the timing scorer anyway)
	// doesn't reach the scorer; low enough to catch a slow hourly DNS
	// heartbeat over a multi-day capture.
	DNSBeaconMinQueries int `json:"dns_beacon_min_queries"`
	// SIEM forwarding: when SIEMEnabled and SIEMHost is set, each finding an
	// analyst escalates is also forwarded to an external SIEM as CEF over UDP
	// syslog (Security Onion's CEF Fleet integration, port 9003 by default).
	// Non-secret — UDP syslog carries no credential; the SIEM host's firewall
	// allow-list is the trust boundary, so these are NOT in secretConfigKeys.
	SIEMEnabled bool   `json:"siem_enabled"`
	SIEMHost    string `json:"siem_host"`
	SIEMPort    int    `json:"siem_port"`
	// CorrelationMinTypes is the minimum number of distinct detector
	// types on the same (SrcIP, DstIP) pair required to emit a
	// Correlated Activity roll-up. Default 2 catches the high-value
	// kill-chain shape (e.g. DNS Tunneling + Beacon to the same
	// destination); raising to 3 trades coverage for false-positive
	// resistance on multi-protocol SaaS traffic. Pairs below the
	// threshold rely on their individual detector findings.
	CorrelationMinTypes int `json:"correlation_min_types"`

	// Spectral beacon detection — frequency-domain analysis (Lomb-Scargle
	// on the reservoir of connection timestamps) for beacons whose timing
	// jitter defeats the Bowley/MAD statistical math but which still have a
	// clear periodic structure.
	//
	// Annotation-only as of the 2026-06-21 timing-axis validation: the
	// result is recorded as an analyst hint (the SpectralRescued flag and a
	// Detail note) but does NOT feed the timing-axis score. The validation
	// against a live C2 corpus found the spectral path decided 0 true
	// positives and inflated 400+ benign clustered findings to CRITICAL, and
	// the period gate that would suppress those was deliberately removed for
	// burst-connect beacons (analysis/spectral_test.go) — so it cannot be
	// tuned out, and the boost was demoted to a hint.
	//
	// CPU cost: ~4 ms per pair on a 200-timestamp reservoir × 2000
	// frequency-grid points. Only runs when the statistical timing score is
	// already below SpectralRescueThreshold (the gate naming is legacy; it
	// now gates whether the annotation is computed, not a score rescue), so
	// well-scoring beacons skip this entirely.
	SpectralEnabled         bool    `json:"spectral_enabled"`
	SpectralMinObservations int     `json:"spectral_min_observations"`
	SpectralFAPThreshold    float64 `json:"spectral_fap_threshold"`
	SpectralRescueThreshold float64 `json:"spectral_rescue_threshold"`

	// DGA hostname augmentation for beacon scoring. When a Beacon
	// or HTTP Beacon finding's destination hostname (SNI for TLS,
	// Host header for HTTP) is algorithmic-shaped (high character
	// entropy AND low bigram log-likelihood against an embedded
	// English-corpus frequency table), bump the score and severity
	// to surface it as high-confidence C2. Both thresholds must
	// agree before the bump fires — either alone produces too many
	// false positives on legitimate algorithmic hostnames (CDN cache
	// keys, blob storage IDs, ad-network endpoints).
	DGAEnabled          bool    `json:"dga_enabled"`
	DGAEntropyThreshold float64 `json:"dga_entropy_threshold"`
	DGABigramThreshold  float64 `json:"dga_bigram_threshold"`

	TITimeoutSec     int    `json:"ti_timeout_sec"`
	OTXAPIKey        string `json:"otx_api_key"`
	AbuseIPDBAPIKey  string `json:"abuseipdb_api_key"`
	VirusTotalAPIKey string `json:"virustotal_api_key"`
	CrowdSecAPIKey   string `json:"crowdsec_api_key"`
	// GreyNoise Community API works unauthenticated (rate-limited to ~50/h).
	// A free Community-tier key bumps the limit; the field is optional and
	// the GreyNoise lookup runs regardless.
	GreyNoiseAPIKey string `json:"greynoise_api_key"`
	// Censys uses HTTP Basic with an ID + Secret pair. Both are required for
	// the lookup to fire; without them the service stays hidden in the UI.
	CensysAPIID     string `json:"censys_api_id"`
	CensysAPISecret string `json:"censys_api_secret"`

	// AI enrichment — optional, opt-in summarization of an escalated/triaged
	// finding's already-collected evidence (detector output + TI notes) into a
	// short analyst briefing written as a finding note. Annotation-only: the
	// model output never feeds a finding's score or severity.
	//
	// LLMProvider selects the backend: "anthropic" | "gemini" | "openai" |
	// "ollama" | "dod" | "custom". Cloud providers (anthropic/gemini/openai)
	// send the (redacted) evidence off-box; "ollama"/"dod"/"custom" point at a
	// self-hosted OpenAI-compatible endpoint — Ollama on the local/LAN network
	// (air-gapped posture) or the US DoD GenAI platform inside the accredited
	// boundary, so the evidence never leaves the enclave. Internal IPs are
	// tokenized out before send regardless of provider; external threat
	// indicators (the same ones already shared with TI services) are sent.
	//
	// LLMAPIKey is a credential — redacted by secretConfigKeys. LLMBaseURL is
	// required for ollama/custom; LLMModel is required for every provider
	// except anthropic (which defaults to claude-opus-4-8).
	LLMEnabled        bool   `json:"llm_enabled"`
	LLMProvider       string `json:"llm_provider,omitempty"`
	LLMBaseURL        string `json:"llm_base_url,omitempty"`
	LLMModel          string `json:"llm_model,omitempty"`
	LLMAPIKey         string `json:"llm_api_key,omitempty"`
	LLMTimeoutSec     int    `json:"llm_timeout_sec,omitempty"`
	LLMAutoOnEscalate bool   `json:"llm_auto_on_escalate,omitempty"`

	// Operator timezone — IANA name, e.g. "America/New_York". Empty = UTC.
	// Used by the watch scheduler (WatchTime is HH:MM in this TZ) and by
	// the off-hours detector (OffHoursStart/End read as hour-of-day in this
	// TZ). Setting one timezone for both keeps "off-hours at 02:00" mean
	// the same thing whether you're talking about scheduling or detection.
	Timezone string `json:"timezone,omitempty"`

	// Watch mode — scheduled analysis. WatchTime is the anchor (HH:MM in
	// Timezone) and WatchIntervalHours controls cadence: 0 or 24 = once
	// daily at HH:MM (the legacy default), 12/6/4/1 = sub-daily ticks at the
	// same minute past every Nth hour aligned to the anchor's hour-offset.
	WatchTime          string `json:"watch_time"` // HH:MM in Timezone, e.g. "02:00"
	WatchEnabled       bool   `json:"watch_enabled"`
	WatchIntervalHours int    `json:"watch_interval_hours,omitempty"` // 0 (default) or 24 = daily; 12/6/4/1 = sub-daily.

	// Archive mode — moves log files older than a cutoff out of the scan
	// directory. Findings remain in the database by default.
	ArchiveEnabled         bool `json:"archive_enabled"`
	ArchiveAfterDays       int  `json:"archive_after_days"`
	PruneFindingsOnArchive bool `json:"prune_findings_on_archive"`

	// Last archive run telemetry — populated after every successful archive
	// (manual button + watch-tick auto). Surfaced in Settings so admins on a
	// shared deployment can see when archive last fired and what it moved
	// without coordinating out-of-band. Empty on a fresh deployment.
	ArchiveLastRunAt          string `json:"archive_last_run_at,omitempty"`
	ArchiveLastFilesArchived  int    `json:"archive_last_files_archived,omitempty"`
	ArchiveLastBytesArchived  int64  `json:"archive_last_bytes_archived,omitempty"`
	ArchiveLastFindingsPruned int    `json:"archive_last_findings_pruned,omitempty"`
	ArchiveLastTriggeredBy    string `json:"archive_last_triggered_by,omitempty"`

	// Last successful analysis fingerprint — (relpath,size,mtime) SHA256 of
	// the /logs tree. When this matches, launchAnalysis can skip a redundant
	// run (watch fires but no files changed). Internal; not user-editable.
	LastAnalysisFingerprint string `json:"last_analysis_fingerprint"`

	// Two-tier watch cadence telemetry. The first watch tick of each UTC
	// calendar day is a full statistical run (Beacon, HTTP analysis, all
	// detectors); subsequent same-day ticks are incremental TI-only runs
	// over logs modified since the last run. These two timestamps drive
	// that decision and the incremental file-mtime filter respectively.
	// Both are also set after manual "Discard findings & re-analyze" so
	// the cycle resets cleanly. Internal; not user-editable.
	LastFullAnalysisUnix int64 `json:"last_full_analysis_unix,omitempty"` // when most recent full run completed; gates "did we already do a full today?"
	LastAnalysisUnix     int64 `json:"last_analysis_unix,omitempty"`      // when ANY run (full or incremental) completed; mtime filter cutoff for next incremental

	// WatchAlwaysFull disables the two-tier cadence: every watch tick runs
	// the full pipeline regardless of whether a full has already happened
	// today. Useful for active hunts where the operator wants statistical
	// detectors (beaconing, HTTP analysis, etc.) refreshing at every tick
	// instead of once daily. Costs more CPU per tick but eliminates the
	// "wait until tomorrow's first tick to see new beacons" gap.
	WatchAlwaysFull bool `json:"watch_always_full,omitempty"`

	// OrgInternalCIDRs are admin-supplied CIDRs (or single IPs) that the
	// Hosts tab should treat as belonging to the organisation, in addition
	// to the built-in private ranges (RFC 1918, IPv4 link-local, IPv6 ULA,
	// IPv6 link-local). Use this to surface cloud-hosted servers, owned
	// public blocks, or any non-RFC-1918 address you want to monitor as
	// "your host." Examples: "203.0.113.0/24", "198.51.100.42".
	OrgInternalCIDRs []string `json:"org_internal_cidrs,omitempty"`

	// SensorFacingHost is the hostname/IP (and optional :port) that Quiver
	// install one-liners should target. Empty = derive from the Host header
	// on the admin's enrollment request. Set this when Archer is reached at
	// different addresses internally vs. from the sensor network — e.g. the
	// admin uses an internal DNS name but sensors come in via a public IP.
	SensorFacingHost string `json:"sensor_facing_host,omitempty"`

	// Alerting thresholds — how long before the alarm loops fire.
	// 0 means "use the built-in default" so existing deployments that
	// don't have these fields in their persisted config keep the same
	// behaviour they had before the fields were introduced.
	//
	// SensorStaleThresholdHours: sensor offline alarm. Default 2 (covers
	// two missed hourly checkins plus jitter).
	//
	// FeedStaleThresholdHours: feed staleness alarm. Default 24 (a feed
	// that hasn't refreshed in a full day is almost certainly broken).
	//
	// RsyncStaleThresholdHours: gap between the sensor's most recent
	// HMAC checkin and the most recent rsync file mtime, above which the
	// "Sensor rsync stopped" alarm fires. Only considered when checkin
	// is still alive (within SensorStaleThreshold) and the sensor has
	// rsynced at least once. Default 4 (four missed hourly rsyncs).
	SensorStaleThresholdHours int `json:"sensor_stale_threshold_hours,omitempty"`
	FeedStaleThresholdHours   int `json:"feed_stale_threshold_hours,omitempty"`
	RsyncStaleThresholdHours  int `json:"rsync_stale_threshold_hours,omitempty"`

	// AuditLogRetentionDays bounds how long audit_log rows are kept. A daily
	// prune loop deletes entries older than this many days. 0 = unlimited (no
	// automatic prune) — the historical behaviour, and the safe default: a
	// team under a compliance regime may need the full trail, so Archer never
	// deletes audit history unless the operator opts in with a positive value.
	// Sized for the rare long-running instance whose append-only audit_log
	// would otherwise grow without bound; on the ≤4-month mission model the
	// table stays small and any reasonable value never triggers.
	AuditLogRetentionDays int `json:"audit_log_retention_days,omitempty"`
}

func Default() Config {
	return Config{
		BeaconMinConnections:  4,
		HTTPBeaconMinRequests: 8,
		LongConnMinHours:      1.0,
		StrobeMinConnections:  100,
		StrobeMinRatePerSec:   0.5,
		ExfilMinBytesMB:       5.0,
		ExfilRatioThreshold:   10.0,
		OffHoursStart:         22,
		OffHoursEnd:           6,
		OffHoursMinMB:         1.0,
		DNSTunnelLabelLen:     40,
		DNSTunnelEntropy:      3.5,
		DNSTunnelMinDepth:     5,
		DNSNXDomainThreshold:  200,
		DNSUniqueSubdomainMin: 50,
		DNSBeaconMinQueries:   20,
		CorrelationMinTypes:   2,
		SIEMPort:              9003,

		// Spectral defaults — conservative enough for first-run
		// safety, tunable per deployment if FP rate dictates.
		// Min observations: 16 gives Lomb-Scargle enough samples to
		// distinguish signal from noise without falling into the
		// few-sample-aliasing regime below 8.
		// FAP threshold 12.0: ~exp(-12) per-frequency false alarm
		// over 2000 grid points means ≈ 2e-2 false alarms per run
		// across all pairs — acceptable noise floor.
		// Rescue threshold 0.5: only run spectral when the
		// statistical timing axis (Bowley/MAD/multimodal/entropy)
		// already failed; pairs that scored above 0.5 don't need
		// rescue.
		SpectralEnabled:         true,
		SpectralMinObservations: 16,
		SpectralFAPThreshold:    12.0,
		SpectralRescueThreshold: 0.5,
		// DGA defaults — calibrated against the embedded
		// bigrams.txt table so legit English domains pass and
		// algorithmically-generated names trip. The bigram
		// threshold default -4.5 sits between the population
		// averages (English ~ -3.0 to -4.0, DGA ~ -5.5 to -6.5).
		// The entropy threshold default 3.5 catches the high-
		// uniform-character-distribution shape DGAs produce
		// without ruling out borderline English words.
		DGAEnabled:          true,
		DGAEntropyThreshold: 3.5,
		DGABigramThreshold:  -4.5,
		TITimeoutSec:        12,

		ArchiveAfterDays: 30,

		SensorStaleThresholdHours: 2,
		FeedStaleThresholdHours:   24,
		RsyncStaleThresholdHours:  4,
	}
}
