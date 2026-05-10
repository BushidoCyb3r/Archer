package server

import (
	"encoding/json"
	"net/http"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// auditEvent is the per-call shape the wiring sites pass through.
// All fields are optional; only Action and the context-derived actor
// info are required for a meaningful entry.
type auditEvent struct {
	TargetType  string
	TargetID    string
	TargetName  string
	BeforeValue map[string]any
	AfterValue  map[string]any
	Details     map[string]any
}

// recordAudit writes an audit-log entry, pulling actor identity and
// source IP from the request context. Best-effort by design — see
// the docstring on Store.LogAuditEvent for why a write failure
// doesn't propagate. v0.14.0 audit-log addition.
//
// Action naming (snake_case, flat namespace, per v0.14.0 auditor
// response):
//
//	login_success / login_failure
//	user_create / user_role_change / user_status_change / user_delete
//	enrollment_token_create / enrollment_token_revoke
//	sensor_disenroll / sensor_purge / sensor_schedule_change
//	feed_create / feed_update / feed_delete / feed_refresh
//	suppression_add / suppression_delete
//	allowlist_edit / ioc_edit
//	config_change / watch_change
//	finding_import
//
// Add new actions to the same flat namespace rather than freeform
// strings so the UI's filter and any compliance-side report keep a
// bounded vocabulary.
func (s *Server) recordAudit(r *http.Request, action string, ev auditEvent) {
	if s.store == nil {
		return
	}
	user := userFromCtx(r)
	srcIP := ""
	if r != nil {
		srcIP = sourceIP(r)
	}
	s.store.LogAuditEvent(store.AuditEntry{
		ActorID:     int64(user.ID),
		ActorEmail:  user.Email,
		Action:      action,
		TargetType:  ev.TargetType,
		TargetID:    ev.TargetID,
		TargetName:  ev.TargetName,
		BeforeValue: store.MarshalAuditDetails(ev.BeforeValue),
		AfterValue:  store.MarshalAuditDetails(ev.AfterValue),
		Details:     store.MarshalAuditDetails(ev.Details),
		SourceIP:    srcIP,
	})
}

// recordAuditLogin is the special-case helper for the login handler,
// where the actor isn't in the request context yet (the session
// cookie that requireAuth consumes hasn't been set). Both success
// and failure paths use this — actorID will be 0 on failure
// (anonymous; we don't know who tried) and the authenticated user's
// id on success.
func (s *Server) recordAuditLogin(r *http.Request, action string, actorID int, actorEmail string, details map[string]any) {
	if s.store == nil {
		return
	}
	srcIP := ""
	if r != nil {
		srcIP = sourceIP(r)
	}
	s.store.LogAuditEvent(store.AuditEntry{
		ActorID:    int64(actorID),
		ActorEmail: actorEmail,
		Action:     action,
		Details:    store.MarshalAuditDetails(details),
		SourceIP:   srcIP,
	})
}

// configToAuditMap converts a Config to the map shape used by the
// audit log's before_value / after_value JSON. API-key fields are
// redacted: the audit log records "the operator changed the OTX key"
// without writing the key value itself, which would defeat the
// purpose of treating the keys as secrets elsewhere (the feeds API
// already refuses to echo APIKey back on GET). Redaction shape is
// "" for empty, "set" for non-empty — enough to see whether a key
// was added/removed/rotated but not what it is.
func configToAuditMap(c config.Config) map[string]any {
	b, err := json.Marshal(c)
	if err != nil {
		return map[string]any{"_marshal_error": err.Error()}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"_unmarshal_error": err.Error()}
	}
	for _, k := range []string{
		"otx_api_key", "abuseipdb_api_key", "virustotal_api_key",
		"crowdsec_api_key", "greynoise_api_key",
	} {
		if v, ok := m[k].(string); ok {
			if v == "" {
				m[k] = ""
			} else {
				m[k] = "set"
			}
		}
	}
	return m
}
