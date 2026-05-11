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
	ActionUserCreate       = "user_create"
	ActionUserRoleChange   = "user_role_change"
	ActionUserStatusChange = "user_status_change"
	ActionUserDelete       = "user_delete"

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

	// Config + global lists
	ActionConfigChange      = "config_change"
	ActionAllowlistEdit     = "allowlist_edit"
	ActionIOCEdit           = "ioc_edit"
	ActionSuppressionAdd    = "suppression_add"
	ActionSuppressionDelete = "suppression_delete"
	ActionWatchChange       = "watch_change"
	ActionFindingImport     = "finding_import"

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
)

// knownAuditActions is the authoritative set of action names the
// audit-log emission sites are allowed to use. The
// TestAuditActionVocabulary test walks the codebase and asserts
// every emission uses a constant from this set; adding a new
// emission without adding a constant fails the test.
var knownAuditActions = map[string]struct{}{
	ActionLoginSuccess:              {},
	ActionLoginFailure:              {},
	ActionLogout:                    {},
	ActionUserRegister:              {},
	ActionAdminBootstrap:            {},
	ActionRequestRateLimited:        {},
	ActionUserCreate:                {},
	ActionUserRoleChange:            {},
	ActionUserStatusChange:          {},
	ActionUserDelete:                {},
	ActionEnrollmentTokenCreate:     {},
	ActionEnrollmentTokenRevoke:     {},
	ActionSensorDisenroll:           {},
	ActionSensorPurge:               {},
	ActionSensorScheduleChange:      {},
	ActionSensorUnauthorizedAttempt: {},
	ActionFeedCreate:                {},
	ActionFeedUpdate:                {},
	ActionFeedDelete:                {},
	ActionFeedRefresh:               {},
	ActionFindingStatusChange:       {},
	ActionFindingEscalate:           {},
	ActionFindingNoteAdd:            {},
	ActionConfigChange:              {},
	ActionAllowlistEdit:             {},
	ActionIOCEdit:                   {},
	ActionSuppressionAdd:            {},
	ActionSuppressionDelete:         {},
	ActionWatchChange:               {},
	ActionFindingImport:             {},
	ActionAnalyzeStart:              {},
	ActionAnalyzeCancel:             {},
	ActionAnalyzePause:              {},
	ActionAnalyzeResume:             {},
	ActionAnalyzeReset:              {},
}
