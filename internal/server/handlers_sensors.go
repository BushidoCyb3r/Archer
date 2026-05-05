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
		"tls_fingerprint":    s.TLSFingerprint(),
		"sensor_facing_host": s.store.GetSensorFacingHost(),
		"effective_host":     s.SensorFacingHost(r),
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
	if sn.Status != "enrolled" {
		jsonError(w, "sensor is not currently enrolled", http.StatusConflict)
		return
	}
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
	s.purgeSensorLogs(sn.Name)
	s.store.DeleteFindingsBySensorPrefix(sn.Name + ":disenrolled-")
	if err := s.store.DeleteSensor(sn.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
	if err := s.store.UpdateSensorSchedule(req.ID, req.Hour, req.Minute); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

// rotateSensorLogs moves /logs/<name>/ aside to /logs/_archived/<name>-<stamp>/.
// Best-effort: a missing source directory or a busy filesystem won't fail
// the disenroll. The archive directory is created on first need.
func (s *Server) rotateSensorLogs(name, stamp string) {
	if s.logsDir == "" || name == "" {
		return
	}
	src := filepath.Join(s.logsDir, name)
	if _, err := os.Stat(src); err != nil {
		return
	}
	archiveRoot := filepath.Join(s.logsDir, "_archived")
	_ = os.MkdirAll(archiveRoot, 0o755)
	dst := filepath.Join(archiveRoot, name+"-"+stamp)
	// If a previous disenroll on the same calendar day already used this
	// path, suffix a counter so we don't merge the trees.
	for i := 2; ; i++ {
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			break
		}
		dst = filepath.Join(archiveRoot, fmt.Sprintf("%s-%s-%d", name, stamp, i))
	}
	if err := os.Rename(src, dst); err != nil {
		fmt.Fprintf(os.Stderr, "rotateSensorLogs: %v\n", err)
	}
}

// purgeSensorLogs removes every archived directory for the sensor name.
// The active directory is gone by this point — purge only runs after a
// successful disenroll.
func (s *Server) purgeSensorLogs(name string) {
	if s.logsDir == "" || name == "" {
		return
	}
	archiveRoot := filepath.Join(s.logsDir, "_archived")
	entries, err := os.ReadDir(archiveRoot)
	if err != nil {
		return
	}
	prefix := name + "-"
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(archiveRoot, e.Name()))
	}
}

// lastLogMTime returns the most recent file mtime under /logs/<name>/ as
// a unix timestamp, or 0 if the directory is empty / missing. Disenrolled
// sensors don't have an active log directory, so we skip them.
func (s *Server) lastLogMTime(name, status string) int64 {
	if s.logsDir == "" || name == "" || status == "disenrolled" {
		return 0
	}
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
	return newest
}
