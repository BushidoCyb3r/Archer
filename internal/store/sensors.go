package store

// Persistent state for Quiver: enrolled sensors, outstanding enrollment
// tokens, and unauthorized checkin attempts. Schema lives in
// migrations/0001_init.sql alongside the other Archer tables; the
// migration runner ensures it's present before any handler reads or
// writes here.
//
// The tables don't carry any cross-references with the existing findings
// table; the link is purely by sensor name (Finding.Sensor matches
// sensors.name). Decoupling means a sensor row can be deleted without
// dragging finding rows with it — that decision is the admin's, made
// through the explicit Purge action.

import (
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Sensor is a Quiver-enrolled (or formerly enrolled) endpoint.
//
// CheckinSecret is the per-sensor HMAC key established at enrollment
// (v0.12.0+). The sensor signs each checkin payload with HMAC-SHA256
// keyed on this secret; the server's checkin handler verifies. Empty
// for sensors that enrolled under protocol v1 (pre-v0.12.0) — those
// must re-enroll to upgrade. Tagged "-" so it never leaks into JSON
// responses; the secret is only echoed once, in the enroll response,
// to the sensor that's about to persist it. Audit 2026-05-10 NEW-16.
type Sensor struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Host           string `json:"host"`
	SourceIP       string `json:"source_ip"`
	EnrolledAt     int64  `json:"enrolled_at"`
	EnrolledBy     string `json:"enrolled_by"`
	Status         string `json:"status"` // enrolled | disenrolling | disenrolled
	PubkeyFP       string `json:"pubkey_fp"`
	AuthKeyLine    string `json:"-"` // exact authorized_keys line we wrote; used to remove on disenroll
	CheckinSecret  string `json:"-"` // HMAC key for checkin authentication; never serialized
	ScheduleHour   int    `json:"schedule_hour"`
	ScheduleMinute int    `json:"schedule_minute"`
	LastSeenAt     int64  `json:"last_seen_at"`
	LastFiles      int64  `json:"last_files"`
	LastBytes      int64  `json:"last_bytes"`
	// ProtocolVersion is the Quiver wire-protocol version this sensor last
	// reported (enroll or most recent checkin). 0 = unknown — only on a row
	// no post-upgrade checkin has refreshed. The enroll/checkin handlers
	// reject unsupported versions before writing, so any non-zero value here
	// is a version this server supports.
	ProtocolVersion int `json:"protocol_version"`
}

// EnrollmentToken is a single-use, time-bounded token that authorizes a
// sensor to enroll. OverrideName, when set, locks the sensor's name to
// the admin's chosen value; otherwise the sensor's hostname is used.
type EnrollmentToken struct {
	ID           int64  `json:"id"`
	Token        string `json:"token"`
	OverrideName string `json:"override_name,omitempty"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	UsedAt       int64  `json:"used_at,omitempty"`
	CreatedBy    string `json:"created_by"`
	ConsumedBy   string `json:"consumed_by,omitempty"`
}

// UnauthorizedAttempt records a checkin from a name we don't recognise.
// Surfaced in the Sensors modal so admins can investigate before either
// dismissing the row or minting an enrollment token for it.
type UnauthorizedAttempt struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	SourceIP     string `json:"source_ip"`
	FirstSeen    int64  `json:"first_seen"`
	LastSeen     int64  `json:"last_seen"`
	AttemptCount int64  `json:"attempt_count"`
	Pinned       bool   `json:"pinned"`
}

// ── Sensors CRUD ──────────────────────────────────────────────────────────

// CreateSensor inserts a new active sensor row. Caller must have already
// verified the name is free; SQLite will enforce that with the partial
// unique index.
func (s *Store) CreateSensor(sn Sensor) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, nil
	}
	res, err := s.db.Exec(
		`INSERT INTO sensors(name, host, source_ip, enrolled_at, enrolled_by, status, pubkey_fp, authkey_line, schedule_hour, schedule_minute, checkin_secret, protocol_version)
		 VALUES (?,?,?,?,?,'enrolled',?,?,?,?,?,?)`,
		sn.Name, sn.Host, sn.SourceIP, sn.EnrolledAt, sn.EnrolledBy,
		sn.PubkeyFP, sn.AuthKeyLine, sn.ScheduleHour, sn.ScheduleMinute, sn.CheckinSecret, sn.ProtocolVersion,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetSensors returns every sensor row (any status), most recent first.
func (s *Store) GetSensors() []Sensor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil
	}
	// COALESCE the nullable text columns — see ListEnrollmentTokens for
	// the same trap (NULL → Scan into *string fails silently → row dropped).
	rows, err := s.db.Query(`SELECT id, name,
	                                COALESCE(host,'')          AS host,
	                                COALESCE(source_ip,'')     AS source_ip,
	                                enrolled_at,
	                                COALESCE(enrolled_by,'')   AS enrolled_by,
	                                status,
	                                COALESCE(pubkey_fp,'')     AS pubkey_fp,
	                                COALESCE(authkey_line,'')  AS authkey_line,
	                                COALESCE(checkin_secret,'') AS checkin_secret,
	                                schedule_hour, schedule_minute, last_seen_at, last_files, last_bytes, protocol_version
	                         FROM sensors ORDER BY enrolled_at DESC, id DESC`)
	if err != nil {
		slog.Error("store: GetSensors", "err", err)
		return nil
	}
	defer rows.Close()
	var out []Sensor
	for rows.Next() {
		var sn Sensor
		if err := rows.Scan(&sn.ID, &sn.Name, &sn.Host, &sn.SourceIP, &sn.EnrolledAt, &sn.EnrolledBy, &sn.Status, &sn.PubkeyFP, &sn.AuthKeyLine, &sn.CheckinSecret, &sn.ScheduleHour, &sn.ScheduleMinute, &sn.LastSeenAt, &sn.LastFiles, &sn.LastBytes, &sn.ProtocolVersion); err == nil {
			out = append(out, sn)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("store: incomplete sensors read", "err", err)
	}
	return out
}

// GetSensorByID returns the sensor row with the given primary-key ID,
// regardless of status. Used after slot claim to get a fresh snapshot.
func (s *Store) GetSensorByID(id int64) (Sensor, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return Sensor{}, false
	}
	row := s.db.QueryRow(`SELECT id, name,
	                             COALESCE(host,'')           AS host,
	                             COALESCE(source_ip,'')      AS source_ip,
	                             enrolled_at,
	                             COALESCE(enrolled_by,'')    AS enrolled_by,
	                             status,
	                             COALESCE(pubkey_fp,'')      AS pubkey_fp,
	                             COALESCE(authkey_line,'')   AS authkey_line,
	                             COALESCE(checkin_secret,'') AS checkin_secret,
	                             schedule_hour, schedule_minute, last_seen_at, last_files, last_bytes, protocol_version
	                      FROM sensors WHERE id=?`, id)
	var sn Sensor
	if err := row.Scan(&sn.ID, &sn.Name, &sn.Host, &sn.SourceIP, &sn.EnrolledAt, &sn.EnrolledBy,
		&sn.Status, &sn.PubkeyFP, &sn.AuthKeyLine, &sn.CheckinSecret,
		&sn.ScheduleHour, &sn.ScheduleMinute, &sn.LastSeenAt, &sn.LastFiles, &sn.LastBytes, &sn.ProtocolVersion); err != nil {
		return Sensor{}, false
	}
	return sn, true
}

// GetActiveSensorByName returns the currently-enrolled sensor with this
// name, or (Sensor{}, false). Used by the checkin endpoint to decide
// enrolled / disenrolled / unknown.
func (s *Store) GetActiveSensorByName(name string) (Sensor, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return Sensor{}, false
	}
	row := s.db.QueryRow(`SELECT id, name,
	                             COALESCE(host,'')          AS host,
	                             COALESCE(source_ip,'')     AS source_ip,
	                             enrolled_at,
	                             COALESCE(enrolled_by,'')   AS enrolled_by,
	                             status,
	                             COALESCE(pubkey_fp,'')     AS pubkey_fp,
	                             COALESCE(authkey_line,'')  AS authkey_line,
	                             COALESCE(checkin_secret,'') AS checkin_secret,
	                             schedule_hour, schedule_minute, last_seen_at, last_files, last_bytes, protocol_version
	                      FROM sensors WHERE name=? AND status IN ('enrolled','disenrolling') ORDER BY id DESC LIMIT 1`, name)
	var sn Sensor
	if err := row.Scan(&sn.ID, &sn.Name, &sn.Host, &sn.SourceIP, &sn.EnrolledAt, &sn.EnrolledBy, &sn.Status, &sn.PubkeyFP, &sn.AuthKeyLine, &sn.CheckinSecret, &sn.ScheduleHour, &sn.ScheduleMinute, &sn.LastSeenAt, &sn.LastFiles, &sn.LastBytes, &sn.ProtocolVersion); err != nil {
		return Sensor{}, false
	}
	return sn, true
}

// HasMostRecentDisenrolled reports whether the most recent row for `name`
// is in disenrolled state. Used so the checkin endpoint can return a
// "disenrolled" verdict to a sensor whose authorized_keys line was already
// pulled but whose cron is still firing.
func (s *Store) HasMostRecentDisenrolled(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return false
	}
	var status string
	err := s.db.QueryRow(`SELECT status FROM sensors WHERE name=? ORDER BY id DESC LIMIT 1`, name).Scan(&status)
	if err != nil {
		return false
	}
	return status == "disenrolled" || status == "disenrolling"
}

// SetSensorStatus moves a sensor row through the lifecycle.
func (s *Store) SetSensorStatus(id int64, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`UPDATE sensors SET status=? WHERE id=?`, status, id)
	return err
}

// UpdateSensorSchedule rewrites the daily slot a sensor uses. The change
// propagates to the sensor on its next checkin.
func (s *Store) UpdateSensorSchedule(id int64, hour, minute int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`UPDATE sensors SET schedule_hour=?, schedule_minute=? WHERE id=?`, hour, minute, id)
	return err
}

// TouchSensor records the most recent successful interaction with a sensor.
// Files/bytes are optional — pass 0 when only the timestamp is known.
// proto is the resolved (already-validated) Quiver protocol version the
// sensor reported on this interaction, so the row tracks the version of the
// binary that last checked in rather than just the enroll-time value.
func (s *Store) TouchSensor(id int64, ts int64, files, bytes int64, srcIP string, proto int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`UPDATE sensors SET last_seen_at=?, last_files=?, last_bytes=?, source_ip=?, protocol_version=? WHERE id=?`,
		ts, files, bytes, srcIP, proto, id)
	return err
}

// DeleteSensor removes the sensor row entirely. Used by the Purge action;
// callers are responsible for already having archived/deleted the on-disk
// logs and re-tagged or removed the related findings.
func (s *Store) DeleteSensor(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM sensors WHERE id=?`, id)
	return err
}

// ── Enrollment tokens ─────────────────────────────────────────────────────

// CreateEnrollmentToken inserts a new token row. The caller supplies the
// random material; we don't generate it here so the same call site can
// also return it to the UI without an extra round-trip.
func (s *Store) CreateEnrollmentToken(t EnrollmentToken) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, nil
	}
	res, err := s.db.Exec(
		`INSERT INTO enrollment_tokens(token, override_name, created_at, expires_at, created_by) VALUES (?,?,?,?,?)`,
		t.Token, t.OverrideName, t.CreatedAt, t.ExpiresAt, t.CreatedBy,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListEnrollmentTokens returns all tokens — used and unused, expired and
// fresh — most recent first. The UI is responsible for hiding consumed
// tokens by default.
func (s *Store) ListEnrollmentTokens() []EnrollmentToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil
	}
	// COALESCE the nullable text columns: override_name / created_by /
	// consumed_by are stored as NULL when blank, and database/sql refuses
	// to scan NULL into a plain Go string. Without the coalesce every Scan
	// here errors silently and the JSON response collapses to `null`.
	rows, err := s.db.Query(`SELECT id, token,
	                                COALESCE(override_name,'') AS override_name,
	                                created_at, expires_at, used_at,
	                                COALESCE(created_by,'')   AS created_by,
	                                COALESCE(consumed_by,'')  AS consumed_by
	                         FROM enrollment_tokens ORDER BY created_at DESC, id DESC`)
	if err != nil {
		slog.Error("store: ListEnrollmentTokens", "err", err)
		return nil
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.Token, &t.OverrideName, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &t.CreatedBy, &t.ConsumedBy); err == nil {
			out = append(out, t)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("store: incomplete enrollment-tokens read", "err", err)
	}
	return out
}

// ConsumeEnrollmentToken validates the token (exists, not used, not expired)
// and atomically marks it consumed. Returns the token row on success.
//
// Pre-fix the validation was a SELECT-then-UPDATE pair that relied on s.mu
// to serialize concurrent /api/quiver/enroll calls. Mutex held across both
// statements is correct today, but TOCTOU was latent: anything that ever
// bypassed the lock (or removing the lock for perf) would let two sensors
// successfully enroll against the same single-use token. The fix collapses
// the check into the WHERE clause so the predicate is enforced by SQLite
// itself; rowsAffected==0 means the token already had used_at!=0 or had
// expired, regardless of when it transitioned. Audit 2026-05-10 LOW.
func (s *Store) ConsumeEnrollmentToken(token string, sensorName string, now int64) (EnrollmentToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return EnrollmentToken{}, false
	}
	res, err := s.db.Exec(
		`UPDATE enrollment_tokens SET used_at=?, consumed_by=?
		 WHERE token=? AND used_at=0 AND expires_at>?`,
		now, sensorName, token, now,
	)
	if err != nil {
		return EnrollmentToken{}, false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return EnrollmentToken{}, false
	}
	var t EnrollmentToken
	row := s.db.QueryRow(`SELECT id, token,
	                              COALESCE(override_name,'') AS override_name,
	                              created_at, expires_at, used_at,
	                              COALESCE(created_by,'')   AS created_by,
	                              COALESCE(consumed_by,'')  AS consumed_by
	                       FROM enrollment_tokens WHERE token=?`, token)
	if err := row.Scan(&t.ID, &t.Token, &t.OverrideName, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &t.CreatedBy, &t.ConsumedBy); err != nil {
		return EnrollmentToken{}, false
	}
	return t, true
}

// ResetEnrollmentToken rolls back a successful ConsumeEnrollmentToken
// by clearing used_at and consumed_by. Used by the enrollment handler
// when a step *after* token consumption fails (authorized_keys write,
// log dir creation, sensor row insert) — without rollback the operator
// is stuck: their token is permanently used_at!=0 but no sensor was
// recorded, and they can't re-enroll without minting a new token. The
// existing rollback of AppendAuthKey shows the author intended this to
// be transactional; this completes the transaction. Audit 2026-05-10
// NEW-19.
func (s *Store) ResetEnrollmentToken(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`UPDATE enrollment_tokens SET used_at=0, consumed_by=NULL WHERE id=?`, id)
	return err
}

// DeleteEnrollmentToken removes a token row by id. Used to revoke an
// outstanding (unused) token from the admin UI.
func (s *Store) DeleteEnrollmentToken(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM enrollment_tokens WHERE id=?`, id)
	return err
}

// ── Unauthorized attempts ─────────────────────────────────────────────────

// RecordUnauthorizedAttempt upserts an attempt row keyed by (name, ip).
// Returns the resulting row so the caller can publish it as an SSE event
// without an extra read.
func (s *Store) RecordUnauthorizedAttempt(name, ip string, now int64) UnauthorizedAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := UnauthorizedAttempt{Name: name, SourceIP: ip, FirstSeen: now, LastSeen: now, AttemptCount: 1}
	if s.db == nil {
		return out
	}
	// Try update first; if no row was touched, insert.
	res, err := s.db.Exec(
		`UPDATE unauthorized_attempts SET last_seen=?, attempt_count=attempt_count+1 WHERE name=? AND source_ip=?`,
		now, name, ip,
	)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			row := s.db.QueryRow(`SELECT id, name, source_ip, first_seen, last_seen, attempt_count, pinned FROM unauthorized_attempts WHERE name=? AND source_ip=?`, name, ip)
			var pinned int
			if err := row.Scan(&out.ID, &out.Name, &out.SourceIP, &out.FirstSeen, &out.LastSeen, &out.AttemptCount, &pinned); err == nil {
				out.Pinned = pinned == 1
			}
			return out
		}
	}
	res, err = s.db.Exec(
		`INSERT INTO unauthorized_attempts(name, source_ip, first_seen, last_seen) VALUES (?,?,?,?)`,
		name, ip, now, now,
	)
	if err == nil {
		out.ID, _ = res.LastInsertId()
	}
	return out
}

// ListUnauthorizedAttempts returns all attempts, most recent first. Pruning
// of stale (unpinned, >30 days) rows happens in PruneUnauthorizedAttempts.
func (s *Store) ListUnauthorizedAttempts() []UnauthorizedAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, name, source_ip, first_seen, last_seen, attempt_count, pinned FROM unauthorized_attempts ORDER BY last_seen DESC`)
	if err != nil {
		slog.Warn("store: ListUnauthorizedAttempts", "err", err)
		return nil
	}
	defer rows.Close()
	var out []UnauthorizedAttempt
	for rows.Next() {
		var a UnauthorizedAttempt
		var pinned int
		if err := rows.Scan(&a.ID, &a.Name, &a.SourceIP, &a.FirstSeen, &a.LastSeen, &a.AttemptCount, &pinned); err == nil {
			a.Pinned = pinned == 1
			out = append(out, a)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("store: incomplete unauthorized-attempts read", "err", err)
	}
	return out
}

// DeleteUnauthorizedAttempt removes a row by id. Pinned rows protect
// against the auto-prune; deleting them is explicit.
func (s *Store) DeleteUnauthorizedAttempt(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM unauthorized_attempts WHERE id=?`, id)
	return err
}

// PruneUnauthorizedAttempts deletes unpinned rows whose last_seen is more
// than retention old. Called from a background ticker; idempotent.
func (s *Store) PruneUnauthorizedAttempts(retention time.Duration) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0
	}
	cutoff := time.Now().Add(-retention).Unix()
	res, err := s.db.Exec(`DELETE FROM unauthorized_attempts WHERE pinned=0 AND last_seen < ?`, cutoff)
	if err != nil {
		slog.Warn("store: PruneUnauthorizedAttempts", "err", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ── Helpers ───────────────────────────────────────────────────────────────

// RetagFindings rewrites the sensor field on every finding currently
// matching oldName. Called from disenroll so a future re-enrollment with
// the same name doesn't conflate two distinct sensor lifecycles.
func (s *Store) RetagFindings(oldName, newName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	if _, err := s.db.Exec(`UPDATE findings SET sensor=? WHERE sensor=?`, newName, oldName); err != nil {
		slog.Error("store: RetagFindings", "err", err)
		return
	}
	// Mirror the change in the in-memory slice so the UI reflects it
	// without a reload-from-DB round-trip.
	for i := range s.findings {
		if s.findings[i].Sensor == oldName {
			s.findings[i].Sensor = newName
		}
	}
}

// DeleteFindingsBySensorPrefix removes every finding whose sensor field
// starts with the given prefix. Used by Purge to drop the disenrolled
// findings that share a "<name>:disenrolled-..." marker.
func (s *Store) DeleteFindingsBySensorPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	// Use substr() rather than LIKE to avoid SQL wildcard interpretation of
	// '_' characters that are valid in sensor names (validSensorName regex).
	if _, err := s.db.Exec(`DELETE FROM findings WHERE substr(sensor, 1, ?) = ?`, len(prefix), prefix); err != nil {
		slog.Error("store: DeleteFindingsBySensorPrefix", "err", err)
		return
	}
	out := s.findings[:0]
	for _, f := range s.findings {
		if !strings.HasPrefix(f.Sensor, prefix) {
			out = append(out, f)
		}
	}
	s.findings = out
	s.rebuildFindingsIdx()
	s.dismissOrphanedFindingNotificationsLocked()
}

// DeleteOrphanedHostRiskScores removes Host Risk Score findings whose
// src_ip no longer appears in any non-rollup finding. Called after
// DeleteFindingsBySensorPrefix so HRS rows backed solely by the purged
// sensor's findings don't persist without backing detections.
func (s *Store) DeleteOrphanedHostRiskScores() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	if _, err := s.db.Exec(`
		DELETE FROM findings
		WHERE type = 'Host Risk Score'
		AND src_ip NOT IN (
			SELECT DISTINCT src_ip FROM findings
			WHERE type NOT IN ('Host Risk Score', 'Correlated Activity')
			AND src_ip != ''
		)`); err != nil {
		slog.Error("store: DeleteOrphanedHostRiskScores", "err", err)
		return
	}
	backed := make(map[string]bool)
	for _, f := range s.findings {
		if !model.IsRollupType(f.Type) && f.SrcIP != "" {
			backed[f.SrcIP] = true
		}
	}
	out := s.findings[:0]
	for _, f := range s.findings {
		if f.Type == model.TypeHostRiskScore && !backed[f.SrcIP] {
			continue
		}
		out = append(out, f)
	}
	s.findings = out
	s.rebuildFindingsIdx()
	s.dismissOrphanedFindingNotificationsLocked()
}

// FingerprintSSHPubkey returns the standard-base64-encoded SHA256 of the key
// blob portion of an SSH public key line. Note: this does NOT match
// ssh-keygen -lf output, which uses unpadded base64 with a "SHA256:" prefix.
// The stored value is display-only; it is not used for any security check.
func FingerprintSSHPubkey(line string) string {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return base64.StdEncoding.EncodeToString(sum[:])
}
