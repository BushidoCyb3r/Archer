package config

// Config holds all tunable analysis thresholds.
type Config struct {
	BeaconMinConnections  int     `json:"beacon_min_connections"`
	HTTPBeaconMinRequests int     `json:"http_beacon_min_requests"`
	LongConnMinHours      float64 `json:"long_conn_min_hours"`
	StrobeMinConnections  int     `json:"strobe_min_connections"`
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
	// CorrelationMinTypes is the minimum number of distinct detector
	// types on the same (SrcIP, DstIP) pair required to emit a
	// Correlated Activity roll-up. Default 2 catches the high-value
	// kill-chain shape (e.g. DNS Tunneling + Beaconing to the same
	// destination); raising to 3 trades coverage for false-positive
	// resistance on multi-protocol SaaS traffic. Pairs below the
	// threshold rely on their individual detector findings.
	CorrelationMinTypes int `json:"correlation_min_types"`

	// Spectral beacon detection — frequency-domain rescue for beacons
	// whose timing jitter defeats the Bowley/MAD statistical math but
	// who still have a clear periodic structure (the C2 use case where
	// adversaries deliberately jitter to evade timing-regularity
	// detection). The rescue runs Lomb-Scargle on the reservoir of
	// connection timestamps and combines its score into the timing
	// axis via max() — same shape as the multimodal and entropy
	// augmentations already in place.
	//
	// CPU cost: ~4 ms per pair on a 200-timestamp reservoir × 2000
	// frequency-grid points. Only fires when the statistical timing
	// score is already below SpectralRescueThreshold, so well-scoring
	// beacons skip this entirely.
	SpectralEnabled         bool    `json:"spectral_enabled"`
	SpectralMinObservations int     `json:"spectral_min_observations"`
	SpectralFAPThreshold    float64 `json:"spectral_fap_threshold"`
	SpectralRescueThreshold float64 `json:"spectral_rescue_threshold"`

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
	// calendar day is a full statistical run (Beaconing, HTTP analysis, all
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
}

func Default() Config {
	return Config{
		BeaconMinConnections:  10,
		HTTPBeaconMinRequests: 8,
		LongConnMinHours:      1.0,
		StrobeMinConnections:  1000,
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
		CorrelationMinTypes:   2,

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
		TITimeoutSec:            12,

		ArchiveAfterDays: 30,
	}
}
