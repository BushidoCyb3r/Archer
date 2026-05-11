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
	"io"
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

// validSensorHostRE is permissive — accepts hostnames, FQDNs, and IPv4
// literals as well as IPv6 (with embedded colons). Refuses control
// characters, whitespace, HTML metacharacters. The empty string is
// allowed because Host is purely informational; sensors can omit it.
// 253-char cap matches DNS spec for FQDNs.
var validSensorHostRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{0,253}$`)

// validSensorHost wraps the regex and explicitly accepts empty.
func validSensorHost(s string) bool { return validSensorHostRE.MatchString(s) }

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
	req.Host = strings.TrimSpace(req.Host)
	if req.Token == "" || req.Pubkey == "" || req.Name == "" {
		jsonError(w, "token, name, and pubkey are all required", http.StatusBadRequest)
		return
	}
	if !validSensorName.MatchString(req.Name) {
		jsonError(w, "invalid sensor name (allowed: a-z, 0-9, '-', '_'; max 52 chars; must start with alphanumeric)", http.StatusBadRequest)
		return
	}
	// req.Host is the sensor's self-reported FQDN, persisted in the
	// sensors row and surfaced in admin views (Sensors modal table,
	// JSON exports, log lines via fmt.Errorf wrappers). Pre-fix it
	// flowed through unvalidated, so a malformed host carrying
	// control characters or HTML could land in those sinks. The SPA
	// escapes today but the asymmetry with Name's validation was a
	// latent risk. Audit 2026-05-10 LOW.
	if !validSensorHost(req.Host) {
		jsonError(w, "invalid host (allowed: alphanumeric, '.', '-', '_', ':' for IPv6; max 253 chars)", http.StatusBadRequest)
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
	//
	// Token rollback on failure: every error path between here and the
	// successful CreateSensor must call ResetEnrollmentToken(tok.ID) so
	// the consumed token becomes reusable. Pre-fix the existing
	// RemoveAuthKey rollback partially captured the transactional
	// intent, but ConsumeEnrollmentToken's used_at flip never reverted
	// — leaving the operator with a permanently-burned token and no
	// sensor row. Audit 2026-05-10 NEW-19.
	finalName := req.Name
	if tok.OverrideName != "" {
		if !validSensorName.MatchString(tok.OverrideName) {
			_ = s.store.ResetEnrollmentToken(tok.ID)
			jsonError(w, "admin override name failed validation", http.StatusInternalServerError)
			return
		}
		finalName = tok.OverrideName
	}

	if _, exists := s.store.GetActiveSensorByName(finalName); exists {
		_ = s.store.ResetEnrollmentToken(tok.ID)
		jsonError(w, "a sensor with this name is already enrolled", http.StatusConflict)
		return
	}

	// Hourly cadence: pick a random minute-of-hour per sensor so 20
	// sensors don't all hit Archer at HH:00. ScheduleHour is preserved
	// in the row schema for backward-compat with daily-mode sensors but
	// is no longer consulted by the cron line install.sh writes.
	hour := 0
	minute := randomMinute()

	// Per-sensor checkin secret (Quiver protocol v2, NEW-16).
	// 32 random bytes encoded URL-safe base64 — same shape as the
	// enrollment token. The sensor persists this on disk and uses it
	// to HMAC-sign each checkin payload; the server stores it on the
	// sensor row so checkin verification is a single SQLite read.
	checkinSecret, err := b64Random(32)
	if err != nil {
		_ = s.store.ResetEnrollmentToken(tok.ID)
		jsonError(w, "could not generate checkin secret: "+err.Error(), http.StatusInternalServerError)
		return
	}

	authLine := BuildAuthKeyLine(finalName, req.Pubkey)
	if err := AppendAuthKey(s.authKeysPath, authLine); err != nil {
		_ = s.store.ResetEnrollmentToken(tok.ID)
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
		_ = s.store.ResetEnrollmentToken(tok.ID)
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
		CheckinSecret:  checkinSecret,
		ScheduleHour:   hour,
		ScheduleMinute: minute,
	}
	id, err := s.store.CreateSensor(sensor)
	if err != nil {
		// Roll back the authorized_keys append so the sensor isn't left
		// with implicit access without a server-side row to disenroll.
		// Reset the enrollment token too so the operator can retry
		// without minting a new one. Audit 2026-05-10 NEW-19.
		_ = RemoveAuthKey(s.authKeysPath, authLine)
		_ = s.store.ResetEnrollmentToken(tok.ID)
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

	// The checkin_secret is returned exactly once — at enrollment.
	// quiver.sh persists it locally (mode 0600) and uses it to HMAC
	// every subsequent checkin. The server never echoes it back on
	// any other endpoint; it's not in any GET response, not in any
	// SSE event, not in any export. Audit 2026-05-10 NEW-16.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"name":             sensor.Name,
		"schedule_hour":    sensor.ScheduleHour,
		"schedule_minute":  sensor.ScheduleMinute,
		"protocol_version": QuiverProtocolVersion,
		"checkin_secret":   checkinSecret,
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
//
// Authentication: under Quiver protocol v2 (NEW-16) every checkin must
// carry an X-Quiver-Sig header containing the HMAC-SHA256 (hex) of the
// raw request body, keyed on the sensor's checkin_secret. The server
// re-derives the expected signature and uses constant-time compare; a
// missing or wrong signature drops to the unknown path so the admin
// sees the attempt without the forger learning whether the name itself
// was valid.
//
// The signed material is the entire body — Name and ProtocolVersion
// included — so a forger can't change either without holding the
// secret. The body is read into memory in full (capped at 1 KiB by
// MaxBytesReader) before JSON decode so the same bytes serve both the
// HMAC verification and the field decode.
const checkinMaxBytes = 1 << 10

func (s *Server) handleQuiverCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Rate limit is applied INSIDE recordUnauthorizedCheckin (only on
	// auth-failure outcomes) rather than at the handler entrypoint —
	// see NEW-45. Pre-v0.14.4 the limit gated every request including
	// authenticated successful checkins, which broke fleets sharing a
	// NAT egress IP: 20 sensors behind one NAT all consuming from one
	// per-IP bucket would 429 the 11th-onward sensor during a fleet
	// burst (Archer restart, mass-reboot, mass-re-enrollment). The
	// asymmetric placement means legitimate sensor traffic never
	// touches the limiter; only unknown-name or bad-HMAC failures do.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, checkinMaxBytes))
	if err != nil {
		jsonError(w, "could not read body", http.StatusBadRequest)
		return
	}
	var req struct {
		Name            string `json:"name"`
		ProtocolVersion *int   `json:"protocol_version,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
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
	// Validate the same regex enrollment enforces. Pre-fix only !=""
	// was checked, so a malformed Name (e.g. "<script>alert(1)</script>"
	// or "../../etc/passwd") flowed straight through to
	// RecordUnauthorizedAttempt and into log lines, the SSE
	// unauthorized_attempt event, the Sensors-modal table, and any
	// future export of unauthorized attempts. The SPA escapes today,
	// so the immediate XSS vector is closed by defense-in-depth on
	// the frontend — but the SQL row, log entry, and any non-HTML
	// sink (CSV export, JSON API consumers) still receive the raw
	// payload. Validating once at enrollment but not at checkin was
	// the asymmetry. Audit 2026-05-10 NEW-15.
	if !validSensorName.MatchString(req.Name) {
		jsonError(w, "invalid sensor name", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	presentedSig := r.Header.Get("X-Quiver-Sig")

	if sn, ok := s.store.GetActiveSensorByName(req.Name); ok {
		// HMAC verification: every active-sensor checkin must
		// carry a valid signature derived from the secret we
		// returned at enrollment. A v1 sensor (CheckinSecret
		// empty) can never satisfy this — the operator's
		// re-enroll IS the upgrade path — so we treat empty-
		// secret rows as forgeable-by-design and route them to
		// "unknown" rather than blanket-trusting the name. A
		// signature mismatch on a sensor that DOES have a
		// secret means either the sensor lost its secret file
		// or someone else is forging checkins; same routing.
		// Audit 2026-05-10 NEW-16.
		if !validQuiverCheckinSig(sn.CheckinSecret, body, presentedSig) {
			s.recordUnauthorizedCheckin(r, w, req.Name, sourceIP(r), "bad_hmac")
			return
		}
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
	s.recordUnauthorizedCheckin(r, w, req.Name, sourceIP(r), "unknown_name")
}

// recordUnauthorizedCheckin pushes an unauthorized_attempts row +
// SSE event + audit_log entry and writes the standard "unknown"
// response. Pulled out so both the unknown-name path and the v2
// HMAC-failure path share a single implementation; previously the
// unknown-name path was inlined and the HMAC path didn't exist.
//
// The reason parameter narrows the failure mode to one of:
//   - "unknown_name" — sensor name not in the enrolled-or-disenrolled set
//   - "bad_hmac"     — name is enrolled but the v2 signature didn't verify
//
// Both produce audit-log rows with actor_id=NULL (sensors aren't
// users) for centralised incident-response queries; the existing
// unauthorized_attempts table remains the live UI surface and is
// not displaced. v0.14.1 NEW-33.
//
// Rate limit is applied here rather than at the handler entrypoint
// (v0.14.4 NEW-45) so legitimate authenticated checkins never
// consume from the per-IP bucket — only auth-failure attempts do.
// This is what makes the rate limit safe for deployments where
// multiple sensors share a NAT egress IP (a fleet behind one
// gateway can't accidentally 429 itself during a mass-reboot).
// Under sustained attack the request_rate_limited audit row lands
// once per bucket-trip; see rate_limit.go's NEW-47 notes.
func (s *Server) recordUnauthorizedCheckin(r *http.Request, w http.ResponseWriter, name, srcIP, reason string) {
	if allowed, shouldAudit := s.rateLimit.allow(srcIP); !allowed {
		if shouldAudit {
			s.recordAudit(r, "request_rate_limited", auditEvent{
				TargetType: "sensor",
				Details:    map[string]any{"path": "/api/quiver/checkin", "reason": "unauth_rate_limit"},
			})
		}
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	attempt := s.store.RecordUnauthorizedAttempt(name, srcIP, time.Now().Unix())
	if data, err := json.Marshal(attempt); err == nil {
		s.broker.Publish(SSEEvent{Type: "unauthorized_attempt", Data: string(data)})
	}
	// Sensors aren't users, so the audit row lands with actor_id=NULL
	// and actor_email="" via the standard recordAudit context flow.
	s.recordAudit(r, "sensor_unauthorized_attempt", auditEvent{
		TargetType: "sensor",
		TargetName: name,
		Details:    map[string]any{"reason": reason, "name": name},
	})
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":           "unknown",
		"protocol_version": QuiverProtocolVersion,
	})
}

// randomMinute picks a uniformly random minute-of-hour for an enrolled
// sensor's hourly push. Using crypto/rand keeps every random source in
// this codebase consistent; predictable seeding wouldn't be a security
// flaw here, but the schedule is when the sensor's presence becomes
// observable to the network so randomness is still desirable.
//
// Rejection sampling instead of `b % 60`. 256 / 60 = 4 rem 16, so
// `b % 60` makes minutes 0..15 each map from 5 byte values while
// 16..59 each map from 4 — a small but real bias. Drawing a fresh
// byte until one falls in [0, 240) eliminates the bias at the cost
// of, on average, 240/256 → ~94% acceptance per draw. Audit
// 2026-05-10 LOW.
func randomMinute() int {
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0
		}
		if b[0] < 240 {
			return int(b[0]) % 60
		}
	}
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
