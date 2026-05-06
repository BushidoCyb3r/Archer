package server

// Disk-usage reporting for the admin UI: per-sensor /logs sizes, total
// archive size, and free-space telemetry for the volumes that matter
// (the host bind for /logs and the named volume for /data). Surfaces
// in the Sensors modal (per-sensor breakdown) and the Settings → Log
// Archive section (archive size + free space). Cached for 5 minutes
// so repeated dialog opens don't burn CPU walking large trees.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

const diskUsageTTL = 5 * time.Minute

type sensorUsage struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

type volumeStats struct {
	FreeBytes  int64 `json:"free_bytes"`
	TotalBytes int64 `json:"total_bytes"`
}

type diskUsageResp struct {
	LogsTotalBytes    int64         `json:"logs_total_bytes"`
	BySensor          []sensorUsage `json:"by_sensor"`
	ArchiveTotalBytes int64         `json:"archive_total_bytes"`
	LogsVolume        volumeStats   `json:"logs_volume"`
	DataVolume        volumeStats   `json:"data_volume"`
	GeneratedAt       string        `json:"generated_at"`
}

// handleDiskUsage returns size telemetry for /logs (per-sensor + total),
// /data/archive (total), and the underlying volumes' free/total bytes.
// Read-only; analyst+ can see it (operations data, not credentials).
func (s *Server) handleDiskUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	s.diskCacheMu.Lock()
	if time.Since(s.diskCacheAt) < diskUsageTTL && s.diskCacheData != nil {
		_, _ = w.Write(s.diskCacheData)
		s.diskCacheMu.Unlock()
		return
	}
	s.diskCacheMu.Unlock()

	resp := s.computeDiskUsage()
	body, _ := json.Marshal(resp)

	s.diskCacheMu.Lock()
	s.diskCacheAt = time.Now()
	s.diskCacheData = body
	s.diskCacheMu.Unlock()

	_, _ = w.Write(body)
}

// computeDiskUsage walks the logs and archive trees and stats the volumes.
// The walk skips files that error on Stat (e.g. a sensor's tree mid-rsync)
// rather than failing the whole report.
func (s *Server) computeDiskUsage() diskUsageResp {
	resp := diskUsageResp{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}

	// Per-sensor /logs tree. The first level under logsDir is the sensor
	// name (matches how the rest of the app maps directory → sensor).
	if s.logsDir != "" {
		entries, _ := os.ReadDir(s.logsDir)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			// Skip the archive bucket (Quiver puts disenrolled trees there)
			// from the per-sensor breakdown — it's reported separately.
			if e.Name() == "_archived" {
				continue
			}
			path := filepath.Join(s.logsDir, e.Name())
			size := dirSize(path)
			resp.BySensor = append(resp.BySensor, sensorUsage{Name: e.Name(), Bytes: size})
			resp.LogsTotalBytes += size
		}
		sort.Slice(resp.BySensor, func(i, j int) bool { return resp.BySensor[i].Bytes > resp.BySensor[j].Bytes })
	}

	// Archive tree — fixed location set by archive.go.
	resp.ArchiveTotalBytes = dirSize(archiveDir)

	// Volume free/total. /logs is typically a host bind, /data is typically
	// a docker-managed volume; they may live on different filesystems so
	// we statfs each separately. Failures (path missing, etc.) yield zero
	// values which the UI renders as "—".
	resp.LogsVolume = statfsBytes(s.logsDir)
	resp.DataVolume = statfsBytes("/data")

	return resp
}

// dirSize returns the recursive byte total of a directory tree. Missing
// directories return 0 silently.
func dirSize(path string) int64 {
	if path == "" {
		return 0
	}
	if _, err := os.Stat(path); err != nil {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

// statfsBytes returns free + total bytes for the volume hosting path.
// Wrapped so non-Linux builds (none today, but cheap insurance) can stub
// it without breaking the JSON shape.
func statfsBytes(path string) volumeStats {
	if path == "" {
		return volumeStats{}
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return volumeStats{}
	}
	return volumeStats{
		FreeBytes:  int64(st.Bavail) * int64(st.Bsize),
		TotalBytes: int64(st.Blocks) * int64(st.Bsize),
	}
}
