package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// AuditEntry is one row in the audit_log table. See
// migrations/0009_audit_log.sql for the schema rationale.
type AuditEntry struct {
	ID          int64  `json:"id"`
	TS          int64  `json:"ts"`
	ActorID     int64  `json:"actor_id,omitempty"`
	ActorEmail  string `json:"actor_email"`
	Action      string `json:"action"`
	TargetType  string `json:"target_type,omitempty"`
	TargetID    string `json:"target_id,omitempty"`
	TargetName  string `json:"target_name,omitempty"`
	BeforeValue string `json:"before_value,omitempty"`
	AfterValue  string `json:"after_value,omitempty"`
	Details     string `json:"details,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
}

// LogAuditEvent writes a single audit-log entry. Best-effort: a write
// failure is logged but does not propagate to the caller — refusing the
// underlying admin action because the audit table couldn't be written
// would be a denial-of-service on the most-privileged-user paths,
// which is worse than a gap in the audit log. The gap is visible
// (operator can see action counts vs. actual UI activity), the DoS
// would be invisible until production.
//
// Append-only by convention: this is the ONLY place audit_log gets
// written in this package, and there are no UPDATE or DELETE
// statements anywhere against audit_log. Preserve that discipline
// when adding new operations.
//
// Audit-log writes are observability, not enforcement — admin
// actions are authorized by the role check at the handler; the
// audit log records that they happened, it doesn't gate them.
// v0.14.0 audit-log addition.
func (s *Store) LogAuditEvent(e AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	if e.TS == 0 {
		e.TS = time.Now().Unix()
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_log (
			ts, actor_id, actor_email, action, target_type, target_id, target_name,
			before_value, after_value, details, source_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, nullableActorID(e.ActorID), e.ActorEmail, e.Action,
		e.TargetType, e.TargetID, e.TargetName,
		e.BeforeValue, e.AfterValue, e.Details, e.SourceIP,
	)
	if err != nil {
		slog.Error("audit_log: write failed", "action", e.Action, "actor", e.ActorEmail, "err", err)
	}
}

// nullableActorID returns sql.NullInt64 so a 0 actor_id (system-
// issued action, anonymous login failure) lands as SQL NULL rather
// than literal 0, matching the schema's "FK-shaped but not declared"
// intent.
func nullableActorID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// ListAuditLog returns the most recent count rows starting from
// before the (exclusive) cursor id. Cursor=0 means "most recent
// page." Pagination is cursor-based on id rather than LIMIT/OFFSET
// so concurrent writes during paging don't shift the window.
func (s *Store) ListAuditLog(cursor int64, count int) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil || count <= 0 {
		return nil
	}
	if count > 500 {
		count = 500
	}

	var rows *sql.Rows
	var err error
	const cols = `id, ts, COALESCE(actor_id, 0), actor_email, action,
		target_type, target_id, target_name, before_value, after_value,
		details, source_ip`
	if cursor > 0 {
		rows, err = s.db.Query(
			`SELECT `+cols+` FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?`,
			cursor, count,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT `+cols+` FROM audit_log ORDER BY id DESC LIMIT ?`,
			count,
		)
	}
	if err != nil {
		slog.Error("audit_log: list failed", "err", err)
		return nil
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(
			&e.ID, &e.TS, &e.ActorID, &e.ActorEmail, &e.Action,
			&e.TargetType, &e.TargetID, &e.TargetName,
			&e.BeforeValue, &e.AfterValue, &e.Details, &e.SourceIP,
		); err == nil {
			out = append(out, e)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("audit_log: incomplete list read", "err", err)
	}
	return out
}

// auditCountCacheTTL bounds how stale the audit-log total count
// can be when surfaced in the UI. For hunt-team scale (thousands
// of rows) the underlying SELECT COUNT(*) is fast; for a long-
// running deployment where the operator missed the documented
// retention prune and the table is millions of rows, the full
// table scan on every audit-dialog page-load was seconds-per-
// load. 60 seconds is short enough that the "n total entries"
// readout never feels stale in practice and bounds the worst-case
// cost to one scan per minute regardless of UI poll rate.
// v0.14.3 NEW-43.
const auditCountCacheTTL = 60 * time.Second

// CountAuditLog returns the total row count. Used by the UI to
// decide whether to show a "load more" affordance. Cached for
// auditCountCacheTTL — see the constant's comment for the
// rationale. Cache is invalidated implicitly by the TTL; writes
// don't trigger an invalidation because the count's bound on
// staleness is the TTL, not transactional correctness.
func (s *Store) CountAuditLog() int64 {
	s.mu.RLock()
	if s.db == nil {
		s.mu.RUnlock()
		return 0
	}
	if !s.auditCountAt.IsZero() && time.Since(s.auditCountAt) < auditCountCacheTTL {
		n := s.auditCountValue
		s.mu.RUnlock()
		return n
	}
	s.mu.RUnlock()

	// Refresh — drop the read lock first so the COUNT(*) doesn't
	// hold readers blocked. We take the write lock briefly only to
	// publish the new value.
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		return 0
	}
	s.mu.Lock()
	s.auditCountValue = n
	s.auditCountAt = time.Now()
	s.mu.Unlock()
	return n
}

// MarshalAuditDetails is a small convenience for the common caller
// shape: build a map, json-encode it. Errors get swallowed because
// audit-log writes are best-effort and an unserialisable value
// should still produce a log entry with the action/target columns
// intact.
func MarshalAuditDetails(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf(`{"_marshal_error":"%s"}`, err.Error())
	}
	return string(b)
}
