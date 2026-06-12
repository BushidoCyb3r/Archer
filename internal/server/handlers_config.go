package server

import (
	"encoding/json"
	"net/http"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// secretConfigKeys are the Config JSON fields that carry third-party
// credentials. Non-admin GET /api/config blanks these and the index
// page never embeds the config at all — a viewer/analyst must not be
// able to read admin-entered API keys from the config endpoint or page
// source. Same redaction shape as the feeds has_api_key pattern.
var secretConfigKeys = []string{
	"otx_api_key",
	"abuseipdb_api_key",
	"virustotal_api_key",
	"crowdsec_api_key",
	"greynoise_api_key",
	"censys_api_id",
	"censys_api_secret",
}

// redactConfigSecrets returns cfg as a JSON-shaped map with every
// credential field blanked and a companion "<field>_configured"
// boolean indicating whether a value was set. Non-secret fields pass
// through unchanged, so a future Config field is never silently leaked
// here and no parallel allowlist has to track the safe ones.
func redactConfigSecrets(cfg any) (map[string]any, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for _, k := range secretConfigKeys {
		v, _ := m[k].(string)
		m[k] = ""
		m[k+"_configured"] = v != ""
	}
	return m, nil
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		cfg := s.store.GetConfig()
		// Admins set these credentials, so the admin-only Settings
		// dialog gets them back verbatim to prefill. Every lower role
		// gets them blanked — reading the endpoint must not disclose
		// keys an analyst/viewer can't otherwise see.
		if userFromCtx(r).Role == model.RoleAdmin {
			json.NewEncoder(w).Encode(cfg)
			return
		}
		redacted, err := redactConfigSecrets(cfg)
		if err != nil {
			jsonError(w, "config encode error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(redacted)
	case http.MethodPut:
		if u := userFromCtx(r); u.Role != model.RoleAdmin {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		cfg := s.store.GetConfig()
		if err := decodeJSONBody(w, r, &cfg, configBodyMaxBytes); err != nil {
			return
		}
		// Off-hours window with start == end silently disabled
		// detection: the wraparound branch (start > end) was false
		// and the standard branch (hour >= X && hour < X) was always
		// false, so off-hours findings simply never fired and admins
		// got no signal that their config disabled a detector.
		// Reject loudly. Audited 2026-05-10.
		if cfg.OffHoursStart == cfg.OffHoursEnd {
			jsonError(w, "off_hours_start and off_hours_end must differ; equal values silently disable off-hours detection", http.StatusBadRequest)
			return
		}
		if cfg.OffHoursStart < 0 || cfg.OffHoursStart > 23 || cfg.OffHoursEnd < 0 || cfg.OffHoursEnd > 23 {
			jsonError(w, "off_hours_start and off_hours_end must be in [0, 23]", http.StatusBadRequest)
			return
		}
		// correlation_min_types < 2 is degenerate — a single-detector
		// pair would always trip, drowning the findings table in
		// useless roll-ups. Boundary rejection matches the NEW-66
		// pattern; correlate.go also short-circuits defensively.
		if cfg.CorrelationMinTypes < 2 {
			jsonError(w, "correlation_min_types must be at least 2", http.StatusBadRequest)
			return
		}
		// Spectral-detector bounds. Same NEW-66 shape: each detector
		// also defends itself at the analyzer call site, but the
		// boundary check rejects nonsense values loudly rather than
		// letting them silently disable the feature.
		if cfg.SpectralMinObservations < 8 {
			jsonError(w, "spectral_min_observations must be at least 8 (below this Lomb-Scargle on impulse trains produces unreliable peaks)", http.StatusBadRequest)
			return
		}
		if cfg.SpectralFAPThreshold <= 0 {
			jsonError(w, "spectral_fap_threshold must be > 0 (the false-alarm cutoff above noise)", http.StatusBadRequest)
			return
		}
		if cfg.SpectralRescueThreshold < 0 || cfg.SpectralRescueThreshold > 1 {
			jsonError(w, "spectral_rescue_threshold must be in [0, 1]", http.StatusBadRequest)
			return
		}
		// DGA augmentation bounds. Entropy is bit-per-char so log2(26)
		// ≈ 4.7 is the theoretical max for uniform letter distribution;
		// allow up to 8 (log2(256)) for non-letter content. Bigram
		// threshold sits in negative log-probability space; -10 is
		// well past the bigramFloor (-5.5) so values below that are
		// nonsensical, and any value > 0 inverts the sign of the
		// suspect check (would flag every host as DGA). NEW-66
		// boundary-validation pattern.
		if cfg.DGAEntropyThreshold < 0 || cfg.DGAEntropyThreshold > 8 {
			jsonError(w, "dga_entropy_threshold must be in [0, 8] (bits per character)", http.StatusBadRequest)
			return
		}
		if cfg.DGABigramThreshold < -10 || cfg.DGABigramThreshold >= 0 {
			jsonError(w, "dga_bigram_threshold must be in [-10, 0) (negative log-probability)", http.StatusBadRequest)
			return
		}
		if cfg.SensorStaleThresholdHours < 0 || cfg.FeedStaleThresholdHours < 0 || cfg.RsyncStaleThresholdHours < 0 {
			jsonError(w, "alerting threshold hours must be >= 0 (0 = use built-in default)", http.StatusBadRequest)
			return
		}
		if cfg.AuditLogRetentionDays < 0 {
			jsonError(w, "audit_log_retention_days must be >= 0 (0 = unlimited / no automatic prune)", http.StatusBadRequest)
			return
		}
		// Beacon detectors need at least 3 intervals to score, which requires
		// 4 events (state is created at event 3 with only 2 intervals; event 4
		// provides the third). Values below 4 can never produce a finding and
		// silently behave as if the detector is disabled.
		if cfg.BeaconMinConnections < 4 {
			jsonError(w, "beacon_min_connections must be at least 4 (fewer connections cannot produce 3 timing intervals)", http.StatusBadRequest)
			return
		}
		if cfg.HTTPBeaconMinRequests < 4 {
			jsonError(w, "http_beacon_min_requests must be at least 4 (fewer requests cannot produce 3 timing intervals)", http.StatusBadRequest)
			return
		}
		if cfg.DNSBeaconMinQueries < 4 {
			jsonError(w, "dns_beacon_min_queries must be at least 4 (fewer queries cannot produce 3 timing intervals)", http.StatusBadRequest)
			return
		}
		before := s.store.GetConfig()
		s.store.SetConfig(cfg)
		s.recordAudit(r, "config_change", auditEvent{
			TargetType:  "config",
			BeforeValue: configToAuditMap(before),
			AfterValue:  configToAuditMap(cfg),
		})
		jsonOK(w)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
