package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/store"
	_ "modernc.org/sqlite"
)

// newCheckinTestServer is the version of the protocol-test helper that
// also has a real SQLite store wired up — checkin looks up the sensor
// row and reads its checkin_secret, so the in-memory bare store isn't
// enough.
func newCheckinTestServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := store.RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	st := store.New(config.Default())
	st.InitDB(db)
	return &Server{store: st, broker: NewBroker()}
}

// TestQuiverCheckin_HMACRequired covers the audit NEW-16 scenario —
// the v0.12.0 fix for forgeable sensor heartbeats. An attacker who
// knows the sensor name but not the secret POSTs an unsigned (or
// wrongly-signed) checkin. Pre-fix the sensor's LastSeenAt updates
// and the dashboard shows "healthy"; post-fix the request routes to
// the unauthorized_attempt path so the admin sees the forgery.
func TestQuiverCheckin_HMACRequired(t *testing.T) {
	s := newCheckinTestServer(t)

	const secret = "real-sensor-secret"
	if _, err := s.store.CreateSensor(store.Sensor{
		Name:           "host1",
		EnrolledAt:     1700000000,
		EnrolledBy:     "admin",
		PubkeyFP:       "fp",
		AuthKeyLine:    "line",
		CheckinSecret:  secret,
		ScheduleHour:   0,
		ScheduleMinute: 0,
	}); err != nil {
		t.Fatalf("CreateSensor: %v", err)
	}

	v2 := 2
	body, _ := json.Marshal(map[string]any{
		"name":             "host1",
		"protocol_version": v2,
	})

	cases := []struct {
		name       string
		sig        string
		wantStatus string
	}{
		{
			name:       "valid signature accepted",
			sig:        quiverCheckinSignature(secret, body),
			wantStatus: "enrolled",
		},
		{
			name:       "wrong signature rejected",
			sig:        quiverCheckinSignature("guessed-secret", body),
			wantStatus: "unknown",
		},
		{
			name:       "missing signature rejected",
			sig:        "",
			wantStatus: "unknown",
		},
		{
			name:       "garbage signature rejected",
			sig:        "00112233",
			wantStatus: "unknown",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/quiver/checkin", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if c.sig != "" {
				req.Header.Set("X-Quiver-Sig", c.sig)
			}
			w := httptest.NewRecorder()
			s.handleQuiverCheckin(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("response not JSON: %v", err)
			}
			if resp["status"] != c.wantStatus {
				t.Errorf("status=%v, want %v", resp["status"], c.wantStatus)
			}
		})
	}
}

// TestQuiverCheckin_BodyTamperingDetected asserts that flipping any
// byte of the signed body invalidates the HMAC even when the original
// signature was valid. This is the property that prevents an attacker
// who captures a legitimate checkin from replaying it with a different
// Name field — the HMAC is computed over the entire body, so changing
// the name breaks the signature.
func TestQuiverCheckin_BodyTamperingDetected(t *testing.T) {
	s := newCheckinTestServer(t)
	const secret = "tamper-test-secret"
	if _, err := s.store.CreateSensor(store.Sensor{
		Name:           "host2",
		EnrolledAt:     1700000000,
		PubkeyFP:       "fp",
		AuthKeyLine:    "line",
		CheckinSecret:  secret,
		ScheduleMinute: 0,
	}); err != nil {
		t.Fatalf("CreateSensor: %v", err)
	}

	v2 := 2
	originalBody, _ := json.Marshal(map[string]any{
		"name":             "host2",
		"protocol_version": v2,
	})
	sig := quiverCheckinSignature(secret, originalBody)

	tamperedBody, _ := json.Marshal(map[string]any{
		"name":             "host3",
		"protocol_version": v2,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/quiver/checkin", bytes.NewReader(tamperedBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Quiver-Sig", sig)
	w := httptest.NewRecorder()
	s.handleQuiverCheckin(w, req)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] == "enrolled" {
		t.Errorf("tampered body with replayed signature should be rejected; got status=enrolled")
	}
}
