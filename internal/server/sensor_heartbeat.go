package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Sensor heartbeat alarm — surfaces silent sensor death before a hunt
// team realises their corpus has gone stale. last_seen_at is updated
// on every Quiver checkin; this loop watches for sensors whose
// LastSeenAt has fallen outside the staleness window and emits a
// Kind=sensor notification (which routes through the bell with a
// Jump button that opens the Sensors modal).
//
// Threshold is hardcoded: 2h. Quiver's default checkin schedule is
// once per hour, so 2h covers two missed checkins plus jitter — long
// enough to avoid alarming on transient network blips, short enough
// to catch a dead agent within a half-shift.
//
// Dedup uses an in-memory map of "currently alerting" sensor names so
// the loop only emits on the transition from healthy → stale. When
// the sensor checks in again the entry clears and a future re-
// staleness fires a fresh alarm. The dismissed-by-operator case is
// handled by the same in-memory map: while the entry is set, no
// re-emit, even if the operator clears the alarm in the panel.
// Cold-start while a sensor is already stale: the first tick emits a
// fresh alarm (the map is empty); operators see one extra alarm per
// Archer restart while the condition persists, which we accept
// rather than persist alarm state to disk.

const (
	sensorStaleThreshold         = 2 * time.Hour
	sensorHeartbeatCheckInterval = 5 * time.Minute
)

// sensorHealth is the per-sensor row returned by /api/sensors/health,
// shaped for external monitoring tools (Prometheus textfile collector,
// Nagios-style checks). Stale=true is the alert signal; StaleForSeconds
// gives the duration past the threshold so monitoring can show how
// long the silence has been.
type sensorHealth struct {
	Name              string `json:"name"`
	Status            string `json:"status"`
	LastSeenAt        int64  `json:"last_seen_at"`
	Stale             bool   `json:"stale"`
	StaleForSeconds   int64  `json:"stale_for_seconds"`
	StaleThresholdSec int64  `json:"stale_threshold_sec"`
}

// startSensorHeartbeatLoop kicks off the staleness watcher. Runs once
// at startup (catches up a long-stopped instance whose sensors went
// silent during the downtime) then on the check interval forever.
func (s *Server) startSensorHeartbeatLoop() {
	active := make(map[string]bool)
	var mu sync.Mutex
	startPruneLoop("sensor_heartbeat", sensorHeartbeatCheckInterval, func() {
		s.scanSensorHeartbeat(active, &mu)
	})
}

// scanSensorHeartbeat walks the sensor list once, emits alarms for
// newly-stale sensors, and clears the active flag for sensors that
// have come back. Only "enrolled" sensors are checked — disenrolled
// rows aren't expected to check in. Sensors with LastSeenAt == 0
// (enrolled but never reported) are skipped: the absence may simply
// mean enrollment ran moments ago and the first checkin hasn't
// landed yet. Once a sensor has checked in at least once, the
// staleness clock starts.
func (s *Server) scanSensorHeartbeat(active map[string]bool, mu *sync.Mutex) {
	sensors := s.store.GetSensors()
	now := time.Now().Unix()
	threshold := int64(sensorStaleThreshold.Seconds())

	mu.Lock()
	defer mu.Unlock()

	stillStale := make(map[string]bool, len(active))
	for _, sn := range sensors {
		if sn.Status != "enrolled" {
			continue
		}
		// Refresh LastSeenAt against the on-disk log mtime, matching
		// what the Sensors modal shows. A sensor whose rsync is
		// landing files but whose HMAC checkin pings have stopped
		// shouldn't false-alarm; the mtime captures the real
		// "data is flowing" signal.
		latest := sn.LastSeenAt
		if t := s.lastLogMTime(sn.Name, sn.Status); t > latest {
			latest = t
		}
		if latest == 0 {
			continue
		}
		ageSec := now - latest
		if ageSec < threshold {
			continue
		}
		stillStale[sn.Name] = true
		if active[sn.Name] {
			continue
		}
		alarm := model.Notification{
			Kind:     "sensor",
			Target:   sn.Name,
			Severity: string(model.SevHigh),
			Type:     "Sensor offline",
			Detail:   "Sensor " + sn.Name + " hasn't checked in for " + humanDuration(ageSec),
		}
		n := s.store.AddAlarm(alarm)
		if data, err := json.Marshal(n); err == nil {
			s.broker.Publish(SSEEvent{Type: "notification", Data: string(data)})
		}
		active[sn.Name] = true
	}

	// Sensors no longer stale: clear the active flag so a future
	// staleness episode emits a fresh alarm. The dismissed alarm
	// (if any) stays in the panel until the operator dismisses it.
	for name := range active {
		if !stillStale[name] {
			delete(active, name)
		}
	}
}

// humanDuration renders a seconds value as "Hh MMm" for the alarm
// detail string ("Sensor lab-1 hasn't checked in for 2h 15m").
// Sub-hour values render just minutes; hour values show both
// components when the minute remainder is non-zero. time.Duration's
// String() formats as "2h15m0s" which buries the operator-relevant
// numbers in trailing zeros.
func humanDuration(sec int64) string {
	if sec < 60 {
		return "less than a minute"
	}
	mins := sec / 60
	if mins < 60 {
		return strconv.FormatInt(mins, 10) + "m"
	}
	hours := mins / 60
	rem := mins % 60
	if rem == 0 {
		return strconv.FormatInt(hours, 10) + "h"
	}
	return strconv.FormatInt(hours, 10) + "h " + strconv.FormatInt(rem, 10) + "m"
}

// handleSensorsHealth returns the per-sensor staleness state shaped
// for external monitoring. Same staleness threshold as the alarm
// loop so a monitoring tool's view and the operator's bell stay in
// sync. Enrolled-but-never-reported sensors render with Stale=false
// (the threshold hasn't started ticking).
func (s *Server) handleSensorsHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sensors := s.store.GetSensors()
	now := time.Now().Unix()
	threshold := int64(sensorStaleThreshold.Seconds())
	out := make([]sensorHealth, 0, len(sensors))
	for _, sn := range sensors {
		if sn.Status != "enrolled" {
			continue
		}
		latest := sn.LastSeenAt
		if t := s.lastLogMTime(sn.Name, sn.Status); t > latest {
			latest = t
		}
		h := sensorHealth{
			Name:              sn.Name,
			Status:            sn.Status,
			LastSeenAt:        latest,
			StaleThresholdSec: threshold,
		}
		if latest > 0 {
			age := now - latest
			if age >= threshold {
				h.Stale = true
				h.StaleForSeconds = age - threshold
			}
		}
		out = append(out, h)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sensors": out})
}
