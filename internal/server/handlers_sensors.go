package server

// Admin-facing endpoints for the Sensors modal. All write actions are
// admin-only; reads are admin-or-analyst so a SOC analyst can see
// sensor health without being able to enroll, disenroll, or change
// schedules. Roles are enforced inside each handler so the route table
// can stay flat.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// handleSensorsList returns the sensor table with last_seen_at refreshed
// from disk so a sensor that hasn't checked in but is still pushing logs
// looks "fresh." Available to admins and analysts; the UI hides the
// admin-only action buttons for analyst sessions.
func (s *Server) handleSensorsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := s.store.GetSensors()
	for i := range out {
		if t := s.lastLogMTime(out[i].Name, out[i].Status); t > out[i].LastSeenAt {
			out[i].LastSeenAt = t
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// handleSensorsInfo returns the deployment-level state the Sensors modal
// needs to render the install one-liner: TLS fingerprint, sensor-facing
// host (or empty so the UI can fall back to its own location.host), and
// the SSH port the docker-compose layout exposes.
func (s *Server) handleSensorsInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"tls_fingerprint":             s.TLSFingerprint(),
		"sensor_facing_host":          s.store.GetSensorFacingHost(),
		"effective_host":              s.SensorFacingHost(r),
		"server_protocol_version":     QuiverProtocolVersion,
		"supported_protocol_versions": supportedQuiverProtocolList(),
	})
}

// handleSensorsHost is PUT-only; admins call it to set the sensor-facing
// hostname/IP (and optional :port) that install one-liners should target
// when Archer's admin URL differs from what sensors should hit.
func (s *Server) handleSensorsHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.store.SetSensorFacingHost(strings.TrimSpace(req.Host))
	jsonOK(w)
}

// handleSensorsTokens GET lists outstanding tokens; POST creates a new
// one. Both admin-only.
func (s *Server) handleSensorsTokens(w http.ResponseWriter, r *http.Request) {
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.ListEnrollmentTokens())
	case http.MethodPost:
		var req struct {
			OverrideName string `json:"override_name"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req)
		req.OverrideName = strings.TrimSpace(req.OverrideName)
		if req.OverrideName != "" && !validSensorName.MatchString(req.OverrideName) {
			jsonError(w, "override_name failed validation (a-z, 0-9, '-', '_'; max 52 chars)", http.StatusBadRequest)
			return
		}
		token, err := b64Random(24)
		if err != nil {
			jsonError(w, "could not generate token", http.StatusInternalServerError)
			return
		}
		now := time.Now()
		t := store.EnrollmentToken{
			Token:        token,
			OverrideName: req.OverrideName,
			CreatedAt:    now.Unix(),
			ExpiresAt:    now.Add(24 * time.Hour).Unix(),
			CreatedBy:    userFromCtx(r).DisplayName(),
		}
		id, err := s.store.CreateEnrollmentToken(t)
		if err != nil {
			jsonError(w, "could not save token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		t.ID = id
		s.recordAudit(r, "enrollment_token_create", auditEvent{
			TargetType: "enrollment_token",
			TargetID:   fmt.Sprintf("%d", id),
			TargetName: req.OverrideName,
			Details:    map[string]any{"override_name": req.OverrideName, "expires_at": t.ExpiresAt},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSensorsTokenRevoke deletes an outstanding (used or unused) token
// row. We don't refuse to revoke an already-used token because cleanup
// of the row from the table is harmless.
func (s *Server) handleSensorsTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.ID == 0 {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteEnrollmentToken(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "enrollment_token_revoke", auditEvent{
		TargetType: "enrollment_token",
		TargetID:   fmt.Sprintf("%d", req.ID),
	})
	jsonOK(w)
}

// handleSensorDisenroll executes the full disenroll sequence:
//
//  1. mark the sensor row 'disenrolling',
//  2. drop its line from authorized_keys (further rsync attempts fail at sshd),
//  3. rotate /logs/<name>/ aside to /logs/_archived/<name>-<date>/,
//  4. retag findings with sensor='<name>:disenrolled-<date>' so a future
//     re-enrollment with the same name doesn't conflate analyst notes,
//  5. mark the row 'disenrolled'.
//
// The sensor's next checkin returns "disenrolled" and the sensor self-cleans.
func (s *Server) handleSensorDisenroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.ID == 0 {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	all := s.store.GetSensors()
	var sn store.Sensor
	for _, x := range all {
		if x.ID == req.ID {
			sn = x
			break
		}
	}
	if sn.ID == 0 {
		jsonError(w, "sensor not found", http.StatusNotFound)
		return
	}
	// Pre-fix this rejected anything other than "enrolled", which
	// included sensors stuck in "disenrolling" from a server crash or
	// a SetSensorStatus failure mid-sequence. The admin then had no
	// path through the UI to complete the disenroll; they had to edit
	// the SQLite database manually. Every step in the disenroll
	// sequence is already idempotent (RemoveAuthKey is no-op if line
	// absent, rotateSensorLogs returns immediately if /logs/<name>/
	// is missing, RetagFindings has nothing to retag if it ran
	// already, SetSensorStatus is unconditionally settable). Resuming
	// from "disenrolling" reuses that resilience. Audit 2026-05-10
	// NEW-23.
	if sn.Status != "enrolled" && sn.Status != "disenrolling" {
		jsonError(w, "sensor is not currently enrolled", http.StatusConflict)
		return
	}
	// Claim the analysis slot before marking disenrolling. If the claim
	// fails, the sensor stays enrolled with the Disenroll button visible.
	// The handler still accepts disenrolling on retry to recover from a
	// crash mid-disenroll (slot is not held across restarts).
	if !s.store.TryStartAnalysis() {
		jsonError(w, "analysis in progress", http.StatusConflict)
		return
	}
	defer s.store.SetAnalyzing(false)
	// Re-read the sensor under the slot so all subsequent operations use
	// current DB state, not the snapshot taken before the claim.
	fresh, ok := s.store.GetSensorByID(sn.ID)
	if !ok {
		jsonError(w, "sensor not found", http.StatusNotFound)
		return
	}
	if fresh.Status != "enrolled" && fresh.Status != "disenrolling" {
		jsonError(w, "sensor is not currently enrolled", http.StatusConflict)
		return
	}
	sn = fresh
	if err := s.store.SetSensorStatus(sn.ID, "disenrolling"); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := RemoveAuthKey(s.authKeysPath, sn.AuthKeyLine); err != nil {
		// Don't bail — the disenroll is mostly a server-side state change;
		// log and continue so we don't get stuck in 'disenrolling'.
		fmt.Fprintf(os.Stderr, "disenroll: %v\n", err)
	}
	stamp := time.Now().UTC().Format("2006-01-02")
	s.rotateSensorLogs(sn.Name, stamp)
	s.store.RetagFindings(sn.Name, sn.Name+":disenrolled-"+stamp)
	if err := s.store.SetSensorStatus(sn.ID, "disenrolled"); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "sensor_disenroll", auditEvent{
		TargetType: "sensor",
		TargetID:   fmt.Sprintf("%d", sn.ID),
		TargetName: sn.Name,
		Details:    map[string]any{"stamp": stamp},
	})
	jsonOK(w)
}

// handleSensorPurge removes a disenrolled sensor row, its archived logs,
// and its retagged findings. Active sensors must be disenrolled first;
// we refuse to purge from any other status to keep the UI honest.
func (s *Server) handleSensorPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.ID == 0 {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	all := s.store.GetSensors()
	var sn store.Sensor
	for _, x := range all {
		if x.ID == req.ID {
			sn = x
			break
		}
	}
	if sn.ID == 0 {
		jsonError(w, "sensor not found", http.StatusNotFound)
		return
	}
	if sn.Status != "disenrolled" {
		jsonError(w, "sensor must be disenrolled before purge", http.StatusConflict)
		return
	}
	if !s.store.TryStartAnalysis() {
		jsonError(w, "analysis in progress", http.StatusConflict)
		return
	}
	defer s.store.SetAnalyzing(false)
	fresh, ok := s.store.GetSensorByID(sn.ID)
	if !ok {
		jsonError(w, "sensor not found", http.StatusNotFound)
		return
	}
	if fresh.Status != "disenrolled" {
		jsonError(w, "sensor must be disenrolled before purge", http.StatusConflict)
		return
	}
	sn = fresh
	s.purgeSensorLogs(sn.Name)
	s.store.DeleteFindingsBySensorPrefix(sn.Name + ":disenrolled-")
	s.store.DeleteOrphanedHostRiskScores()
	if err := s.store.DeleteSensor(sn.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "sensor_purge", auditEvent{
		TargetType: "sensor",
		TargetID:   fmt.Sprintf("%d", sn.ID),
		TargetName: sn.Name,
	})
	jsonOK(w)
}

// handleSensorSchedule reassigns the daily slot a sensor uses. The new
// slot propagates on the sensor's next checkin.
func (s *Server) handleSensorSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		ID     int64 `json:"id"`
		Hour   int   `json:"hour"`
		Minute int   `json:"minute"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.ID == 0 {
		jsonError(w, "id, hour, minute required", http.StatusBadRequest)
		return
	}
	if req.Hour < 0 || req.Hour > 23 || req.Minute < 0 || req.Minute > 59 {
		jsonError(w, "hour must be 0-23 and minute 0-59", http.StatusBadRequest)
		return
	}
	// Snapshot the previous schedule + sensor name for the audit entry.
	var beforeName string
	var beforeHour, beforeMinute int
	for _, x := range s.store.GetSensors() {
		if x.ID == req.ID {
			beforeName = x.Name
			beforeHour = x.ScheduleHour
			beforeMinute = x.ScheduleMinute
			break
		}
	}
	if err := s.store.UpdateSensorSchedule(req.ID, req.Hour, req.Minute); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.recordAudit(r, "sensor_schedule_change", auditEvent{
		TargetType:  "sensor",
		TargetID:    fmt.Sprintf("%d", req.ID),
		TargetName:  beforeName,
		BeforeValue: map[string]any{"hour": beforeHour, "minute": beforeMinute},
		AfterValue:  map[string]any{"hour": req.Hour, "minute": req.Minute},
	})
	jsonOK(w)
}

// handleUnauthorizedList returns recent unrecognised checkin attempts.
// Admin + analyst can read; only admin can dismiss.
func (s *Server) handleUnauthorizedList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.ListUnauthorizedAttempts())
}

// handleUnauthorizedDismiss deletes an unauthorized_attempts row.
func (s *Server) handleUnauthorizedDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role != model.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.ID == 0 {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteUnauthorizedAttempt(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w)
}

// ── Filesystem helpers ────────────────────────────────────────────────────

// rotateSensorLogs moves /logs/<name>/ aside to
// /logs/_archived/<name>/<stamp>/. Best-effort: a missing source
// directory or a busy filesystem won't fail the disenroll. The archive
// directory is created on first need.
//
// Pre-v0.12.0 the layout was /logs/_archived/<name>-<stamp>/ — flat,
// hyphen-delimited. validSensorName allows hyphens, so sensors named
// "abc" and "abc-east" produced archive directories with overlapping
// prefixes (`abc-2026-01-15` and `abc-east-2026-01-20`). The matching
// purgeSensorLogs implementation used HasPrefix(name + "-"), so
// purging "abc" would also wipe "abc-east"'s archive — silently
// destroying the second sensor's logs. Naming conventions like
// region-hostname ("east-fw01", "east-fw02", "west-fw01") are common
// for sensor fleets, so the collision wasn't theoretical.
//
// Nesting <name>/<stamp> moves the per-sensor namespace into a
// directory rather than a path prefix; purge becomes a single
// `os.RemoveAll(/_archived/<name>)` with no prefix matching, no
// collision possible. Audit 2026-05-10 NEW-21.
func (s *Server) rotateSensorLogs(name, stamp string) {
	if s.logsDir == "" || name == "" {
		return
	}
	src := filepath.Join(s.logsDir, name)
	if _, err := os.Stat(src); err != nil {
		return
	}
	archiveRoot := filepath.Join(s.logsDir, "_archived", name)
	_ = os.MkdirAll(archiveRoot, 0o755)
	dst := filepath.Join(archiveRoot, stamp)
	// If a previous disenroll on the same calendar day already used this
	// path, suffix a counter so we don't merge the trees.
	for i := 2; ; i++ {
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			break
		}
		dst = filepath.Join(archiveRoot, fmt.Sprintf("%s-%d", stamp, i))
	}
	if err := os.Rename(src, dst); err != nil {
		fmt.Fprintf(os.Stderr, "rotateSensorLogs: %v\n", err)
	}
}

// purgeSensorLogs removes the archived directory for the sensor name.
// The active directory is gone by this point — purge only runs after a
// successful disenroll. Single-level removal is safe because the
// nested-by-name layout (rotateSensorLogs) puts every archived
// snapshot for a sensor under its own /_archived/<name>/ directory,
// so there's no chance of catching another sensor's logs the way the
// pre-v0.12.0 prefix-match implementation did. Audit 2026-05-10
// NEW-21.
func (s *Server) purgeSensorLogs(name string) {
	if s.logsDir == "" || name == "" {
		return
	}
	dir := filepath.Join(s.logsDir, "_archived", name)
	_ = os.RemoveAll(dir)
}

// lastLogMTime returns the most recent file mtime under /logs/<name>/ as
// a unix timestamp, or 0 if the directory is empty / missing. Disenrolled
// sensors don't have an active log directory, so we skip them.
//
// Cached for sensorMtimeCacheTTL because handleSensorsList — the only
// caller — fires on every Sensors-modal poll. Pre-cache a 50-sensor
// fleet with a busy log tree could spend 100+ ms just stat'ing files
// per UI tick. The TTL is short enough that a sensor that just went
// idle still shows fresh data within ~5 seconds; a sensor that just
// pushed shows up at most that delayed. Audit 2026-05-10 LOW.
const sensorMtimeCacheTTL = 5 * time.Second

func (s *Server) lastLogMTime(name, status string) int64 {
	if s.logsDir == "" || name == "" || status == "disenrolled" {
		return 0
	}
	now := time.Now()

	s.sensorMtimeMu.Lock()
	if s.sensorMtimeCache == nil {
		s.sensorMtimeCache = make(map[string]sensorMtimeEntry)
	}
	if e, ok := s.sensorMtimeCache[name]; ok && now.Sub(e.cachedAt) < sensorMtimeCacheTTL {
		s.sensorMtimeMu.Unlock()
		return e.mtime
	}
	s.sensorMtimeMu.Unlock()

	dir := filepath.Join(s.logsDir, name)
	var newest int64
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if t := info.ModTime().Unix(); t > newest {
			newest = t
		}
		return nil
	})

	s.sensorMtimeMu.Lock()
	s.sensorMtimeCache[name] = sensorMtimeEntry{mtime: newest, cachedAt: now}
	s.sensorMtimeMu.Unlock()
	return newest
}
