package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Sensor heartbeat alarm — surfaces silent sensor death before a hunt
// team realises their corpus has gone stale. last_seen_at is updated
// on every Quiver checkin; this loop watches for sensors whose
// LastSeenAt has fallen outside the staleness window and emits a
// Kind=sensor notification (which routes through the bell with a
// Jump button that opens the Sensors modal).
//
// Thresholds are read from config on every scan tick so an operator
// change takes effect without a restart. The default constants below
// are fallbacks for zero-value configs (existing deployments that
// predate the tunable fields).
//
// Dedup uses in-memory maps of "currently alerting" sensor names so
// each loop emits only on the healthy → unhealthy transition. When
// the sensor recovers the entry clears and a future re-episode fires
// a fresh alarm. Cold-start while a sensor is already unhealthy: the
// first tick emits one alarm; operators see at most one extra alarm
// per Archer restart while the condition persists, which we accept
// rather than persist alarm state to disk.

const (
	sensorStaleThreshold         = 2 * time.Hour
	sensorHeartbeatCheckInterval = 5 * time.Minute
	defaultRsyncStaleHours       = 4
)

// sensorStaleSec returns the sensor-offline threshold in seconds.
// Reads from config; falls back to the built-in default when the
// config field is zero (older deployments without the setting).
func sensorStaleSec(cfg config.Config) int64 {
	if cfg.SensorStaleThresholdHours > 0 {
		return int64(cfg.SensorStaleThresholdHours) * 3600
	}
	return int64(sensorStaleThreshold.Seconds())
}

// rsyncStaleSec returns the rsync-gap threshold in seconds.
func rsyncStaleSec(cfg config.Config) int64 {
	if cfg.RsyncStaleThresholdHours > 0 {
		return int64(cfg.RsyncStaleThresholdHours) * 3600
	}
	return defaultRsyncStaleHours * 3600
}

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
	rsyncActive := make(map[string]bool)
	var mu sync.Mutex
	startPruneLoop("sensor_heartbeat", sensorHeartbeatCheckInterval, func() {
		s.scanSensorHeartbeat(active, rsyncActive, &mu)
	})
}

// scanSensorHeartbeat walks the sensor list once and emits two kinds
// of alarm:
//
//   - "Sensor offline": neither HMAC checkin nor rsync has produced
//     activity within the sensor-stale threshold. The max(checkin,
//     logMTime) signal means a sensor whose rsync is flowing but
//     whose checkin has stopped won't false-alarm here.
//
//   - "Sensor rsync stopped": checkin is still alive (within the
//     offline threshold) but the gap between the last checkin and
//     the last rsync file mtime exceeds the rsync-stale threshold.
//     Only fires when the sensor has rsynced at least once (logMTime
//     > 0) so a freshly enrolled sensor that hasn't pushed yet is
//     ignored.
//
// Both alarms use transition-edge dedup: one alarm fires per episode
// and the active flag clears when the condition resolves.
func (s *Server) scanSensorHeartbeat(active, rsyncActive map[string]bool, mu *sync.Mutex) {
	cfg := s.store.GetConfig()
	offlineThreshold := sensorStaleSec(cfg)
	rsyncThreshold := rsyncStaleSec(cfg)

	sensors := s.store.GetSensors()
	now := time.Now().Unix()

	mu.Lock()
	defer mu.Unlock()

	stillOffline := make(map[string]bool, len(active))
	stillRsyncDead := make(map[string]bool, len(rsyncActive))

	for _, sn := range sensors {
		if sn.Status != "enrolled" {
			continue
		}
		logMTime := s.lastLogMTime(sn.Name, sn.Status)

		// Offline alarm: use max(checkin, rsync mtime) so a sensor
		// whose rsync is landing files but whose HMAC ping stopped
		// doesn't false-alarm here.
		latest := sn.LastSeenAt
		if logMTime > latest {
			latest = logMTime
		}
		if latest == 0 {
			continue
		}
		if now-latest >= offlineThreshold {
			stillOffline[sn.Name] = true
			if !active[sn.Name] {
				alarm := model.Notification{
					Kind:     "sensor",
					Target:   sn.Name,
					Severity: string(model.SevHigh),
					Type:     "Sensor offline",
					Detail:   "Sensor " + sn.Name + " hasn't checked in for " + humanDuration(now-latest),
				}
				n := s.store.AddAlarm(alarm)
				if data, err := json.Marshal(n); err == nil {
					s.broker.Publish(SSEEvent{Type: "notification", Data: string(data)})
				}
				active[sn.Name] = true
			}
			continue
		}

		// Rsync-dead alarm: checkin is alive but rsync has stopped
		// landing files. The gap is measured as checkin_time -
		// last_log_mtime rather than now - last_log_mtime so brief
		// analysis delays don't inflate the apparent gap.
		if sn.LastSeenAt > 0 && logMTime > 0 {
			gap := sn.LastSeenAt - logMTime
			if gap >= rsyncThreshold {
				stillRsyncDead[sn.Name] = true
				if !rsyncActive[sn.Name] {
					alarm := model.Notification{
						Kind:     "sensor",
						Target:   sn.Name,
						Severity: string(model.SevHigh),
						Type:     "Sensor rsync stopped",
						Detail:   "Sensor " + sn.Name + " is checking in but rsync has not landed files in " + humanDuration(gap),
					}
					n := s.store.AddAlarm(alarm)
					if data, err := json.Marshal(n); err == nil {
						s.broker.Publish(SSEEvent{Type: "notification", Data: string(data)})
					}
					rsyncActive[sn.Name] = true
				}
			}
		}
	}

	for name := range active {
		if !stillOffline[name] {
			delete(active, name)
		}
	}
	for name := range rsyncActive {
		if !stillRsyncDead[name] {
			delete(rsyncActive, name)
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
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.store.GetConfig()
	sensors := s.store.GetSensors()
	now := time.Now().Unix()
	threshold := sensorStaleSec(cfg)
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
