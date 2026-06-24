package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
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
//	user_password_change / user_password_reset
//	enrollment_token_create / enrollment_token_revoke
//	sensor_disenroll / sensor_purge / sensor_schedule_change
//	feed_create / feed_update / feed_delete / feed_refresh
//	suppression_add / suppression_delete
//	pair_allowlist_add / pair_allowlist_remove
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
		"censys_api_id", "censys_api_secret",
		"llm_api_key",
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

// auditListDiffCap caps the per-edit added/removed slice rendered
// into the audit row. Whole-list replacements (rare, e.g. importing
// a TI-feed-derived IOC dump) would otherwise produce multi-MB audit
// rows, breaking both the SQLite row footprint and the audit-log
// UI's table render. The hash + counts are the irrefutable forensic
// record; the diff is the human-readable explanation. A truncation
// marker tells readers the diff was sampled. v0.14.2 NEW-34.
const auditListDiffCap = 50

// diffStringSets returns the entries added or removed between two
// list snapshots. Order in the inputs doesn't matter; duplicates
// are de-duped (allowlist / IOC lists are conceptually sets, not
// multisets). Used by allowlist_edit / ioc_edit audit emission so
// the audit row records the *change*, not the full state.
func diffStringSets(before, after []string) (added, removed []string) {
	bSet := make(map[string]struct{}, len(before))
	for _, s := range before {
		bSet[s] = struct{}{}
	}
	aSet := make(map[string]struct{}, len(after))
	for _, s := range after {
		aSet[s] = struct{}{}
	}
	for s := range aSet {
		if _, in := bSet[s]; !in {
			added = append(added, s)
		}
	}
	for s := range bSet {
		if _, in := aSet[s]; !in {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// hashStringList returns a stable SHA-256 hex digest of a string
// list, sorted + newline-joined so reordering doesn't perturb the
// hash. Lets a forensic query prove the allowlist / IOC list at
// time T hashed to X — irrefutable, bounded-size, independent of
// the cap on the human-readable diff above.
func hashStringList(xs []string) string {
	if len(xs) == 0 {
		return "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	sorted := make([]string, len(xs))
	copy(sorted, xs)
	sort.Strings(sorted)
	h := sha256.New()
	for _, s := range sorted {
		h.Write([]byte(s))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// capStringSlice returns at most n entries from xs, used by audit
// emission to bound the per-row diff size while still surfacing
// the most-likely-useful subset for human review. Samples both
// ends of the (sorted) input so an alphabetically-late entry like
// `zzz_evil.example.com` buried in a bulk update doesn't get
// silently truncated from the diff view. The hash + counts catch
// the absolute fact of change; this just makes the human-readable
// diff sample less biased. v0.14.3 NEW-42.
func capStringSlice(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	half := n / 2
	out := make([]string, 0, n)
	out = append(out, xs[:half]...)
	out = append(out, xs[len(xs)-(n-half):]...)
	return out
}

// findingAuditName formats a finding's identity into the
// "Type src → dst:port" shape used as TargetName on
// finding_status_change / finding_escalate / finding_note_add
// audit rows. Pre-fix the TargetName was just f.Type, which made
// the audit-log UI render five "Beacon" rows in a row with no
// distinguishing detail — an analyst skimming the log had to
// click into each row to see which finding was acted on.
// Including src/dst/port answers the question the analyst was
// asking. v0.14.2 cosmetic, paired with NEW-36.
func findingAuditName(f model.Finding) string {
	if f.Type == "" {
		return ""
	}
	if f.SrcIP == "" && f.DstIP == "" {
		return f.Type
	}
	dst := f.DstIP
	if f.DstPort != "" {
		dst = dst + ":" + f.DstPort
	}
	return f.Type + " " + f.SrcIP + " → " + dst
}

// listEditAuditDetail packages the diff + hash pair into the audit
// event's Details map, including a truncation marker so readers know
// when the rendered added/removed slice was sampled.
func listEditAuditDetail(added, removed []string) map[string]any {
	return map[string]any{
		"added":          capStringSlice(added, auditListDiffCap),
		"removed":        capStringSlice(removed, auditListDiffCap),
		"added_count":    len(added),
		"removed_count":  len(removed),
		"diff_truncated": len(added) > auditListDiffCap || len(removed) > auditListDiffCap,
	}
}
