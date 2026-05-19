package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/store"
)

// TestSensorHeartbeat_OnlyTriggersOnTransition codifies the
// dedup-by-episode invariant. A stale sensor must emit exactly one
// alarm per staleness episode — not one per tick, not one per
// restart while still stale. When the sensor comes back inside the
// window the active flag clears so a subsequent re-staleness fires
// a fresh alarm.
func TestSensorHeartbeat_OnlyTriggersOnTransition(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()

	// Three enrolled sensors:
	//   fresh:  checked in 30min ago      → never alarms
	//   stale:  checked in 3h ago         → alarms on first scan
	//   never:  enrolled but no checkin   → never alarms (clock hasn't started)
	mustCreateSensor(t, s.store, "fresh", "enrolled", now-int64(30*time.Minute.Seconds()))
	stale := mustCreateSensor(t, s.store, "stale", "enrolled", now-int64(3*time.Hour.Seconds()))
	mustCreateSensor(t, s.store, "never", "enrolled", 0)

	active := make(map[string]bool)
	rsyncActive := make(map[string]bool)
	var mu sync.Mutex

	// First scan: emits one alarm for "stale".
	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	notifs := s.store.GetNotifications()
	if len(notifs) != 1 {
		t.Fatalf("first scan emitted %d notifications, want 1; notifs=%+v", len(notifs), notifs)
	}
	if notifs[0].Kind != "sensor" || notifs[0].Target != "stale" {
		t.Errorf("notification = %+v; want Kind=sensor Target=stale", notifs[0])
	}
	if notifs[0].Type != "Sensor offline" {
		t.Errorf("notification Type = %q, want Sensor offline", notifs[0].Type)
	}
	if !active["stale"] {
		t.Error("active['stale'] not set after first emission")
	}

	// Second scan: dedup must hold — no new alarm even though the
	// sensor is still stale. Active map still has "stale" set.
	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	if got := len(s.store.GetNotifications()); got != 1 {
		t.Errorf("second scan emitted a duplicate; total notifications = %d, want 1", got)
	}

	// Sensor checks in → not stale. Active flag clears.
	if err := s.store.TouchSensor(stale, time.Now().Unix(), 1, 1024, "127.0.0.1"); err != nil {
		t.Fatalf("TouchSensor: %v", err)
	}
	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	mu.Lock()
	if active["stale"] {
		t.Error("active['stale'] still set after sensor recovered")
	}
	mu.Unlock()

	// Sensor goes stale again — fresh alarm emitted (episode count = 2).
	if err := s.store.TouchSensor(stale, now-int64(3*time.Hour.Seconds()), 1, 1024, "127.0.0.1"); err != nil {
		t.Fatalf("TouchSensor (re-stale): %v", err)
	}
	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	if got := len(s.store.GetNotifications()); got != 2 {
		t.Errorf("re-staleness episode didn't fire fresh alarm; total notifications = %d, want 2", got)
	}
}

// TestSensorHeartbeat_DisenrolledIgnored verifies that a disenrolled
// sensor whose last_seen_at is well outside the staleness window
// doesn't alarm. Disenrolled sensors aren't expected to check in.
func TestSensorHeartbeat_DisenrolledIgnored(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()
	mustCreateSensor(t, s.store, "old-decom", "disenrolled", now-int64(48*time.Hour.Seconds()))

	active := make(map[string]bool)
	rsyncActive := make(map[string]bool)
	var mu sync.Mutex
	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	if got := len(s.store.GetNotifications()); got != 0 {
		t.Errorf("disenrolled sensor alarmed; got %d notifications, want 0", got)
	}
}

// TestSensorsHealthEndpoint asserts the /api/sensors/health response
// shape and staleness classification. External monitoring (Prometheus,
// Nagios) reads this endpoint to decide whether to page.
func TestSensorsHealthEndpoint(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()
	mustCreateSensor(t, s.store, "fresh", "enrolled", now-int64(30*time.Minute.Seconds()))
	mustCreateSensor(t, s.store, "stale", "enrolled", now-int64(3*time.Hour.Seconds()))
	mustCreateSensor(t, s.store, "never", "enrolled", 0)

	req := httptest.NewRequest(http.MethodGet, "/api/sensors/health", nil)
	w := httptest.NewRecorder()
	s.handleSensorsHealth(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var payload struct {
		Sensors []struct {
			Name              string `json:"name"`
			LastSeenAt        int64  `json:"last_seen_at"`
			Stale             bool   `json:"stale"`
			StaleForSeconds   int64  `json:"stale_for_seconds"`
			StaleThresholdSec int64  `json:"stale_threshold_sec"`
		} `json:"sensors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantThreshold := sensorStaleSec(s.store.GetConfig())
	byName := map[string]bool{}
	staleByName := map[string]bool{}
	for _, h := range payload.Sensors {
		byName[h.Name] = true
		staleByName[h.Name] = h.Stale
		if h.StaleThresholdSec != wantThreshold {
			t.Errorf("%s.stale_threshold_sec = %d, want %d", h.Name, h.StaleThresholdSec, wantThreshold)
		}
	}
	for _, want := range []string{"fresh", "stale", "never"} {
		if !byName[want] {
			t.Errorf("missing %q in /api/sensors/health response", want)
		}
	}
	if staleByName["fresh"] {
		t.Error("fresh sensor classified stale")
	}
	if !staleByName["stale"] {
		t.Error("stale sensor not classified stale")
	}
	if staleByName["never"] {
		t.Error("never-checked-in sensor classified stale (staleness clock should not have started)")
	}
}

// TestSensorHeartbeat_RsyncAlarm codifies the rsync-alive/checkin-dead
// invariant: when a sensor's HMAC checkin is recent (within the offline
// threshold) but the gap between that checkin and the most recent rsync
// file mtime exceeds RsyncStaleThresholdHours, exactly one "Sensor rsync
// stopped" alarm fires per episode. The alarm clears when rsync resumes.
//
// Sensors that have never rsynced (no log dir) and sensors that are
// already fully offline must not trigger this alarm.
func TestSensorHeartbeat_RsyncAlarm(t *testing.T) {
	s := newAuditTestServer(t)
	logsDir := t.TempDir()
	s.logsDir = logsDir

	now := time.Now()

	// rsync-dead: checkin 30min ago, last rsync file 5h old → gap 4.5h > 4h default.
	mustCreateSensor(t, s.store, "rsync-dead", "enrolled", now.Add(-30*time.Minute).Unix())
	deadDir := filepath.Join(logsDir, "rsync-dead")
	if err := os.MkdirAll(deadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	deadLog := filepath.Join(deadDir, "conn.log")
	if err := os.WriteFile(deadLog, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldMtime := now.Add(-5 * time.Hour)
	if err := os.Chtimes(deadLog, oldMtime, oldMtime); err != nil {
		t.Fatal(err)
	}

	// rsync-ok: checkin 30min ago, last rsync 10min ago → gap 20min, no alarm.
	mustCreateSensor(t, s.store, "rsync-ok", "enrolled", now.Add(-30*time.Minute).Unix())
	okDir := filepath.Join(logsDir, "rsync-ok")
	if err := os.MkdirAll(okDir, 0o755); err != nil {
		t.Fatal(err)
	}
	okLog := filepath.Join(okDir, "conn.log")
	if err := os.WriteFile(okLog, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	recentMtime := now.Add(-10 * time.Minute)
	if err := os.Chtimes(okLog, recentMtime, recentMtime); err != nil {
		t.Fatal(err)
	}

	// no-rsync: checkin 30min ago, no log dir at all → no alarm (never rsynced).
	mustCreateSensor(t, s.store, "no-rsync", "enrolled", now.Add(-30*time.Minute).Unix())

	active := make(map[string]bool)
	rsyncActive := make(map[string]bool)
	var mu sync.Mutex

	// First scan: only rsync-dead should alarm.
	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	notifs := s.store.GetNotifications()
	if len(notifs) != 1 {
		t.Fatalf("first scan: want 1 notification, got %d: %+v", len(notifs), notifs)
	}
	if notifs[0].Type != "Sensor rsync stopped" {
		t.Errorf("notification Type = %q, want Sensor rsync stopped", notifs[0].Type)
	}
	if notifs[0].Target != "rsync-dead" {
		t.Errorf("notification Target = %q, want rsync-dead", notifs[0].Target)
	}

	// Second scan: dedup holds — no new alarm.
	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	if got := len(s.store.GetNotifications()); got != 1 {
		t.Errorf("second scan: duplicate alarm; got %d notifications, want 1", got)
	}

	// Rsync recovers — update file mtime to now, flush mtime cache.
	if err := os.Chtimes(deadLog, now, now); err != nil {
		t.Fatal(err)
	}
	s.sensorMtimeMu.Lock()
	s.sensorMtimeCache = nil
	s.sensorMtimeMu.Unlock()

	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	mu.Lock()
	recovered := !rsyncActive["rsync-dead"]
	mu.Unlock()
	if !recovered {
		t.Error("rsyncActive['rsync-dead'] still set after rsync recovered")
	}

	// Rsync stops again — fresh episode → second alarm.
	if err := os.Chtimes(deadLog, oldMtime, oldMtime); err != nil {
		t.Fatal(err)
	}
	s.sensorMtimeMu.Lock()
	s.sensorMtimeCache = nil
	s.sensorMtimeMu.Unlock()

	s.scanSensorHeartbeat(active, rsyncActive, &mu)
	if got := len(s.store.GetNotifications()); got != 2 {
		t.Errorf("re-staleness episode: want 2 total notifications, got %d", got)
	}
}

func mustCreateSensor(t *testing.T, st *store.Store, name, status string, lastSeenAt int64) int64 {
	t.Helper()
	id, err := st.CreateSensor(store.Sensor{
		Name:       name,
		Host:       name + ".test",
		EnrolledAt: time.Now().Unix(),
		EnrolledBy: "test",
		PubkeyFP:   "fp:" + name,
	})
	if err != nil {
		t.Fatalf("CreateSensor(%s): %v", name, err)
	}
	if status != "enrolled" {
		if err := st.SetSensorStatus(id, status); err != nil {
			t.Fatalf("SetSensorStatus(%s, %s): %v", name, status, err)
		}
	}
	if lastSeenAt > 0 {
		if err := st.TouchSensor(id, lastSeenAt, 0, 0, ""); err != nil {
			t.Fatalf("TouchSensor(%s): %v", name, err)
		}
	}
	return id
}
