package server

// Sensor-facing endpoints: the install script, enrollment, and the daily
// checkin. These have no session auth — sensors aren't users — but they
// run over the TLS listener and the install script's curl invocation pins
// the cert fingerprint so a man-in-the-middle can't substitute a malicious
// response (or steal the enrollment token from the request).

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/store"
)

//go:embed quiver_assets/install.sh
var quiverInstallTemplate string

//go:embed quiver_assets/quiver.sh
var quiverDailyScript string

//go:embed quiver_assets/quiver-uninstall.sh
var quiverUninstallScript string

// validSensorName mirrors the regex the install script enforces on the
// sensor side. Filesystem-safe so the name can serve as a /logs/<name>/
// directory; capped at 52 chars to leave headroom.
var validSensorName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,51}$`)

// handleQuiverInstallScript serves the bash bootstrap an admin's
// enrollment one-liner downloads on the sensor. The template lives in
// quiver_assets/ and is embedded at build time; we substitute the
// deployment-specific values (host, ports, cert fingerprint) and inline
// the daily script + uninstall helper as base64-encoded blobs so the
// sensor's install runs without a second network hop.
func (s *Server) handleQuiverInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	// Strip the port off the sensor-facing host — we provide HTTPS_PORT
	// and SSH_PORT separately so the script can construct each URL with
	// the right port. Bracketed IPv6 hosts are left intact.
	host := s.SensorFacingHost(r)
	if !strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
	}

	body := strings.NewReplacer(
		"{{ARCHER_HOST}}", host,
		"{{HTTPS_PORT}}", "8443",
		"{{SSH_PORT}}", "2222",
		"{{TLS_FP}}", s.TLSFingerprint(),
		"{{QUIVER_SH_B64}}", base64.StdEncoding.EncodeToString([]byte(quiverDailyScript)),
		"{{UNINSTALL_SH_B64}}", base64.StdEncoding.EncodeToString([]byte(quiverUninstallScript)),
	).Replace(quiverInstallTemplate)

	_, _ = w.Write([]byte(body))
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
		Token           string `json:"token"`
		Name            string `json:"name"`
		Host            string `json:"host"`
		Pubkey          string `json:"pubkey"`
		ProtocolVersion *int   `json:"protocol_version,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Validate the sensor's protocol version before any state-changing work
	// (token consume, authorized_keys write, sensor-row insert). A pre-Phase-2
	// sensor that omits the field is treated as v1 for one compatibility
	// cycle so existing fleets keep enrolling during the upgrade window.
	sentProto := 1
	if req.ProtocolVersion != nil {
		sentProto = *req.ProtocolVersion
	}
	if _, ok := resolveQuiverProtocol(req.ProtocolVersion); !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(quiverProtocolErrorJSON(sentProto))
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

	// Hourly cadence: pick a random minute-of-hour per sensor so 20
	// sensors don't all hit Archer at HH:00. ScheduleHour is preserved
	// in the row schema for backward-compat with daily-mode sensors but
	// is no longer consulted by the cron line install.sh writes.
	hour := 0
	minute := randomMinute()
	authLine := BuildAuthKeyLine(finalName, req.Pubkey)
	if err := AppendAuthKey(s.authKeysPath, authLine); err != nil {
		jsonError(w, "could not write authorized_keys: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// rrsync chroots into /logs/<name>/ on the first push; if the dir
	// doesn't exist its lock_or_die opens a missing path and the rsync
	// connection drops with FileNotFoundError. Create it here, owned by
	// the same uid that runs rrsync (the user sshd drops to, derived
	// from the authorized_keys parent dir's owner).
	if err := s.ensureSensorLogDir(finalName); err != nil {
		_ = RemoveAuthKey(s.authKeysPath, authLine)
		jsonError(w, "could not create sensor logs dir: "+err.Error(), http.StatusInternalServerError)
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

	// Live event for the Sensors modal: the parent table can refresh
	// in place, and the still-open enrollment dialog can swap its
	// "waiting" status for a confirmation tick without polling.
	if data, err := json.Marshal(sensor); err == nil {
		s.broker.Publish(SSEEvent{Type: "sensor_enrolled", Data: string(data)})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"name":             sensor.Name,
		"schedule_hour":    sensor.ScheduleHour,
		"schedule_minute":  sensor.ScheduleMinute,
		"protocol_version": QuiverProtocolVersion,
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
		Name            string `json:"name"`
		ProtocolVersion *int   `json:"protocol_version,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Validate protocol before doing any store work. Checkin returns 200
	// with status="protocol_unsupported" rather than 400 — the sensor's
	// curl uses -fsSL and would otherwise lose the body to "network_error",
	// hiding the real cause. Status-discriminator stays consistent with
	// the existing enrolled/disenrolled/unknown shape.
	sentProto := 1
	if req.ProtocolVersion != nil {
		sentProto = *req.ProtocolVersion
	}
	if _, ok := resolveQuiverProtocol(req.ProtocolVersion); !ok {
		quiverProtocolUnsupportedCheckin(w, sentProto)
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
			"protocol_version": QuiverProtocolVersion,
		})
		return
	}
	if s.store.HasMostRecentDisenrolled(req.Name) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":           "disenrolled",
			"protocol_version": QuiverProtocolVersion,
		})
		return
	}
	attempt := s.store.RecordUnauthorizedAttempt(req.Name, sourceIP(r), time.Now().Unix())
	// Push a live event so the Sensors modal updates the moment a fresh
	// unauthorized name shows up, without the analyst having to refresh.
	if data, err := json.Marshal(attempt); err == nil {
		s.broker.Publish(SSEEvent{Type: "unauthorized_attempt", Data: string(data)})
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status":           "unknown",
		"protocol_version": QuiverProtocolVersion,
	})
}

// randomMinute picks a uniformly random minute-of-hour for an enrolled
// sensor's hourly push. Using crypto/rand keeps every random source in
// this codebase consistent; predictable seeding wouldn't be a security
// flaw here, but the schedule is when the sensor's presence becomes
// observable to the network so randomness is still desirable.
func randomMinute() int {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return int(b[0]) % 60
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

// ensureSensorLogDir creates /logs/<name>/ for an enrolling sensor and
// chowns it to whoever owns the authorized_keys parent directory. That
// parent is /home/quiver/.ssh in the bundled image, which means the new
// dir ends up writable by the same uid sshd's privilege-separated
// process drops to before exec'ing rrsync. Without this step rrsync's
// chroot setup fails on first push with FileNotFoundError.
func (s *Server) ensureSensorLogDir(name string) error {
	dir := filepath.Join(s.logsDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if s.authKeysPath == "" {
		return nil
	}
	fi, err := os.Stat(filepath.Dir(s.authKeysPath))
	if err != nil {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(dir, int(st.Uid), int(st.Gid))
	}
	return nil
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
