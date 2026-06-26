package server

// Audit-log action vocabulary. Centralised here so call sites can't
// fragment the namespace via typos in free-form strings, and so the
// authoritative list lives in one place that grep can find. v0.14.3
// NEW-41 — replaces the aspirational docstring comment that drifted
// behind the actual call sites across the audit-log additions
// (v0.14.0 → v0.14.3).
//
// Naming convention: snake_case, flat namespace (no dots), one
// action per state-changing event. New actions go below, grouped by
// the surface they live on. The action_consistency_test.go suite
// walks every recordAudit / recordAuditLogin / LogAuditEvent call
// site and asserts the action string matches one of these constants
// — adding a new emission without adding a constant is a compile-
// time-or-test-time failure, not a silently-fragmented vocabulary.
const (
	// Auth + session
	ActionLoginSuccess       = "login_success"
	ActionLoginFailure       = "login_failure"
	ActionLogout             = "logout"
	ActionUserRegister       = "user_register"
	ActionAdminBootstrap     = "admin_bootstrap"
	ActionRequestRateLimited = "request_rate_limited"

	// User management (admin API)
	ActionUserCreate         = "user_create"
	ActionUserRoleChange     = "user_role_change"
	ActionUserStatusChange   = "user_status_change"
	ActionUserDelete         = "user_delete"
	ActionUserPasswordChange = "user_password_change"
	ActionUserPasswordReset  = "user_password_reset"

	// Sensor lifecycle + auth surface
	ActionEnrollmentTokenCreate     = "enrollment_token_create"
	ActionEnrollmentTokenRevoke     = "enrollment_token_revoke"
	ActionSensorDisenroll           = "sensor_disenroll"
	ActionSensorPurge               = "sensor_purge"
	ActionSensorScheduleChange      = "sensor_schedule_change"
	ActionSensorUnauthorizedAttempt = "sensor_unauthorized_attempt"

	// Feeds
	ActionFeedCreate  = "feed_create"
	ActionFeedUpdate  = "feed_update"
	ActionFeedDelete  = "feed_delete"
	ActionFeedRefresh = "feed_refresh"

	// Analyst-side state on findings (v0.14.1+)
	ActionFindingStatusChange = "finding_status_change"
	ActionFindingEscalate     = "finding_escalate"
	ActionFindingNoteAdd      = "finding_note_add"
	// AI-triage egress — a finding's evidence was sent to an LLM provider.
	// The egress detail records cloud vs. local so an accredited deployment
	// can prove what left the enclave and what stayed on-network.
	ActionFindingAIEnrich = "finding_ai_enrich"

	// Config + global lists
	ActionConfigChange               = "config_change"
	ActionAllowlistEdit              = "allowlist_edit"
	ActionIOCEdit                    = "ioc_edit"
	ActionIOCFingerprintEdit         = "ioc_fingerprint_edit"
	ActionIOCFingerprintAdd          = "ioc_fingerprint_add"
	ActionSuppressionAdd             = "suppression_add"
	ActionSuppressionDelete          = "suppression_delete"
	ActionPairAllowlistAdd           = "pair_allowlist_add"
	ActionPairAllowlistRemove        = "pair_allowlist_remove"
	ActionFingerprintAllowlistAdd    = "fingerprint_allowlist_add"
	ActionFingerprintAllowlistRemove = "fingerprint_allowlist_remove"
	ActionWatchChange                = "watch_change"
	ActionFindingImport              = "finding_import"

	// Analyze pipeline lifecycle (v0.14.9 NEW-65). Watch-driven
	// runs are unattributed and don't pass through these handlers;
	// only user-initiated invocations on /api/analyze and its
	// pause/resume/cancel/reset siblings emit. The audit row
	// proves an operator chose to run/cancel/reset, which is the
	// missing piece next to config_change for "who ran what
	// pipeline when" forensics.
	ActionAnalyzeStart  = "analyze_start"
	ActionAnalyzeCancel = "analyze_cancel"
	ActionAnalyzePause  = "analyze_pause"
	ActionAnalyzeResume = "analyze_resume"
	ActionAnalyzeReset  = "analyze_reset"

	// Admin DB backup (v0.18.2+). The snapshot file contains every
	// finding, note, audit row, sensor secret, and user credential
	// hash — an exfil-via-backup attempt has to leave a row here.
	ActionDBBackup = "db_backup"

	// Service-account tokens — machine-to-machine credentials for
	// /api/sensors/health (Prometheus, Nagios). Stored as SHA-256
	// hashes; the raw credential is shown once on creation.
	ActionServiceTokenCreate = "service_token_create"
	ActionServiceTokenRevoke = "service_token_revoke"
)

// knownAuditActions is the authoritative set of action names the
// audit-log emission sites are allowed to use. The
// TestAuditActionVocabulary test walks the codebase and asserts
// every emission uses a constant from this set; adding a new
// emission without adding a constant fails the test.
var knownAuditActions = map[string]struct{}{
	ActionLoginSuccess:               {},
	ActionLoginFailure:               {},
	ActionLogout:                     {},
	ActionUserRegister:               {},
	ActionAdminBootstrap:             {},
	ActionRequestRateLimited:         {},
	ActionUserCreate:                 {},
	ActionUserRoleChange:             {},
	ActionUserStatusChange:           {},
	ActionUserDelete:                 {},
	ActionUserPasswordChange:         {},
	ActionUserPasswordReset:          {},
	ActionEnrollmentTokenCreate:      {},
	ActionEnrollmentTokenRevoke:      {},
	ActionSensorDisenroll:            {},
	ActionSensorPurge:                {},
	ActionSensorScheduleChange:       {},
	ActionSensorUnauthorizedAttempt:  {},
	ActionFeedCreate:                 {},
	ActionFeedUpdate:                 {},
	ActionFeedDelete:                 {},
	ActionFeedRefresh:                {},
	ActionFindingStatusChange:        {},
	ActionFindingEscalate:            {},
	ActionFindingNoteAdd:             {},
	ActionFindingAIEnrich:            {},
	ActionConfigChange:               {},
	ActionAllowlistEdit:              {},
	ActionIOCEdit:                    {},
	ActionIOCFingerprintEdit:         {},
	ActionIOCFingerprintAdd:          {},
	ActionSuppressionAdd:             {},
	ActionSuppressionDelete:          {},
	ActionPairAllowlistAdd:           {},
	ActionPairAllowlistRemove:        {},
	ActionFingerprintAllowlistAdd:    {},
	ActionFingerprintAllowlistRemove: {},
	ActionWatchChange:                {},
	ActionFindingImport:              {},
	ActionAnalyzeStart:               {},
	ActionAnalyzeCancel:              {},
	ActionAnalyzePause:               {},
	ActionAnalyzeResume:              {},
	ActionAnalyzeReset:               {},
	ActionDBBackup:                   {},
	ActionServiceTokenCreate:         {},
	ActionServiceTokenRevoke:         {},
}
