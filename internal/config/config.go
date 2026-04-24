package config

// Config holds all tunable analysis thresholds.
type Config struct {
	BeaconMinConnections  int     `json:"beacon_min_connections"`
	BeaconMaxJitterCV     float64 `json:"beacon_max_jitter_cv"`
	BeaconMinIntervalSec  int     `json:"beacon_min_interval_sec"`
	BeaconGapMultiplier   float64 `json:"beacon_gap_multiplier"`
	HTTPBeaconMinRequests int     `json:"http_beacon_min_requests"`
	HTTPBeaconMaxCV       float64 `json:"http_beacon_max_cv"`
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
	TITimeoutSec          int     `json:"ti_timeout_sec"`
	OTXAPIKey             string  `json:"otx_api_key"`
	AbuseIPDBAPIKey       string  `json:"abuseipdb_api_key"`
	VirusTotalAPIKey      string  `json:"virustotal_api_key"`
	CrowdSecAPIKey        string  `json:"crowdsec_api_key"`

	// Watch mode — daily scheduled analysis
	WatchTime    string `json:"watch_time"`    // HH:MM in UTC, e.g. "02:00"
	WatchEnabled bool   `json:"watch_enabled"`

	// Archive mode — moves log files older than a cutoff out of the scan
	// directory. Findings remain in the database by default.
	ArchiveEnabled         bool `json:"archive_enabled"`
	ArchiveAfterDays       int  `json:"archive_after_days"`
	PruneFindingsOnArchive bool `json:"prune_findings_on_archive"`

	// Last successful analysis fingerprint — (relpath,size,mtime) SHA256 of
	// the /logs tree. When this matches, launchAnalysis can skip a redundant
	// run (watch fires but no files changed). Internal; not user-editable.
	LastAnalysisFingerprint string `json:"last_analysis_fingerprint"`
}

func Default() Config {
	return Config{
		BeaconMinConnections:  10,
		BeaconMaxJitterCV:     0.35,
		BeaconMinIntervalSec:  2,
		BeaconGapMultiplier:   5.0,
		HTTPBeaconMinRequests: 8,
		HTTPBeaconMaxCV:       0.40,
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
		TITimeoutSec:          12,

		ArchiveAfterDays: 30,
	}
}
