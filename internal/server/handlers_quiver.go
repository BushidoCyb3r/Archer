package server

// Sensor-facing endpoints: the install script, enrollment, and the daily
// checkin. These have no session auth — sensors aren't users — but they
// run over the TLS listener and the install script's curl invocation pins
// the cert fingerprint so a man-in-the-middle can't substitute a malicious
// response (or steal the enrollment token from the request).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/store"
)

// validSensorName mirrors the regex the install script enforces on the
// sensor side. Filesystem-safe so the name can serve as a /logs/<name>/
// directory; capped at 52 chars to leave headroom.
var validSensorName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,51}$`)

// handleQuiverInstallScript serves the bash bootstrap that an admin's
// enrollment one-liner downloads on the sensor. The full installer body
// lives in step 6; for now we serve a stub so the route exists and the
// build/deploy story doesn't drift between commits.
func (s *Server) handleQuiverInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintln(w, "#!/bin/sh")
	fmt.Fprintln(w, "# Quiver installer — body filled in by a later commit.")
	fmt.Fprintln(w, "echo 'quiver: installer not yet shipped on this Archer release' >&2")
	fmt.Fprintln(w, "exit 1")
}

// handleQuiverEnroll is what the sensor POSTs to during the install
// one-liner. Validates the token, the requested name, and the supplied
// public key, then writes the authorized_keys line and the sensor row in
// one transaction-ish sequence. Failure halfway through can leave a
// sensor row without an authorized_keys line; we treat that as a UI-side
// concern (the sensor will checkin and look healthy from the server's
// view but its rsync will fail at sshd, prompting the operator to
// disenroll/re-enroll).
func (s *Server) handleQuiverEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token  string `json:"token"`
		Name   string `json:"name"`
		Host   string `json:"host"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Token = strings.TrimSpace(req.Token)
	req.Pubkey = strings.TrimSpace(req.Pubkey)
	if req.Token == "" || req.Pubkey == "" || req.Name == "" {
		jsonError(w, "token, name, and pubkey are all required", http.StatusBadRequest)
		return
	}
	if !validSensorName.MatchString(req.Name) {
		jsonError(w, "invalid sensor name (allowed: a-z, 0-9, '-', '_'; max 52 chars; must start with alphanumeric)", http.StatusBadRequest)
		return
	}

	now := time.Now().Unix()
	tok, ok := s.store.ConsumeEnrollmentToken(req.Token, req.Name, now)
	if !ok {
		jsonError(w, "token invalid, expired, or already used", http.StatusForbidden)
		return
	}
	// Honor the admin's pre-set name override over whatever the sensor
	// reported. Skipping the override-name match check is intentional:
	// the admin's name wins, period.
	finalName := req.Name
	if tok.OverrideName != "" {
		if !validSensorName.MatchString(tok.OverrideName) {
			jsonError(w, "admin override name failed validation", http.StatusInternalServerError)
			return
		}
		finalName = tok.OverrideName
	}

	if _, exists := s.store.GetActiveSensorByName(finalName); exists {
		jsonError(w, "a sensor with this name is already enrolled", http.StatusConflict)
		return
	}

	hour, minute := randomDailySlot()
	authLine := BuildAuthKeyLine(finalName, req.Pubkey)
	if err := AppendAuthKey(s.authKeysPath, authLine); err != nil {
		jsonError(w, "could not write authorized_keys: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sensor := store.Sensor{
		Name:           finalName,
		Host:           strings.TrimSpace(req.Host),
		SourceIP:       sourceIP(r),
		EnrolledAt:     now,
		EnrolledBy:     tok.CreatedBy,
		PubkeyFP:       store.FingerprintSSHPubkey(req.Pubkey),
		AuthKeyLine:    authLine,
		ScheduleHour:   hour,
		ScheduleMinute: minute,
	}
	id, err := s.store.CreateSensor(sensor)
	if err != nil {
		// Roll back the authorized_keys append so the sensor isn't left
		// with implicit access without a server-side row to disenroll.
		_ = RemoveAuthKey(s.authKeysPath, authLine)
		jsonError(w, "could not record sensor: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sensor.ID = id

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"name":            sensor.Name,
		"schedule_hour":   sensor.ScheduleHour,
		"schedule_minute": sensor.ScheduleMinute,
	})
}

// handleQuiverCheckin is called by every enrolled sensor's cron tick
// before it attempts the rsync push. Returns one of three verdicts:
//   - {status: "enrolled", schedule: {hour, minute}}      → push logs
//   - {status: "disenrolled"}                              → self-clean
//   - {status: "unknown"}                                  → record + exit
//
// Unknown attempts also produce an unauthorized_attempts row so the admin
// can investigate why an unrecognised name showed up.
func (s *Server) handleQuiverCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if sn, ok := s.store.GetActiveSensorByName(req.Name); ok {
		_ = s.store.TouchSensor(sn.ID, time.Now().Unix(), 0, 0, sourceIP(r))
		json.NewEncoder(w).Encode(map[string]any{
			"status": "enrolled",
			"schedule": map[string]int{
				"hour":   sn.ScheduleHour,
				"minute": sn.ScheduleMinute,
			},
		})
		return
	}
	if s.store.HasMostRecentDisenrolled(req.Name) {
		json.NewEncoder(w).Encode(map[string]any{"status": "disenrolled"})
		return
	}
	s.store.RecordUnauthorizedAttempt(req.Name, sourceIP(r), time.Now().Unix())
	json.NewEncoder(w).Encode(map[string]any{"status": "unknown"})
}

// randomDailySlot picks a uniformly random (hour, minute) within a day,
// using crypto/rand because the schedule is the moment a sensor leaks
// its presence to the network — predictable seeding wouldn't be a
// security flaw here, but using the same RNG everywhere is one less
// thing to remember.
func randomDailySlot() (hour, minute int) {
	var b [2]byte
	_, _ = rand.Read(b[:])
	hour = int(b[0]) % 24
	minute = int(b[1]) % 60
	return
}

// sourceIP returns the client IP for an incoming request, stripping the
// :port suffix that net/http puts on RemoteAddr. We don't honor X-
// Forwarded-For — Archer's deployment story has no reverse proxy, so
// trusting that header would let any sensor lie about its IP.
func sourceIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip := r.RemoteAddr
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	return ip
}

// b64Random returns n random bytes encoded as a URL-safe base64 string.
// Used for enrollment token material.
func b64Random(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
