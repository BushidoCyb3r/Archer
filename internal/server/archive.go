package server

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// archiveDir is where aged log files are relocated. It lives on the persistent
// /data volume so archived files survive container recreation. Declared as a
// var (not const) so tests can override it.
var archiveDir = "/data/archive"

// scanArchiveDir mirrors scanLogsDir but rooted at archiveDir. Used by the
// "Scan archive" admin action which retroactively matches archived logs
// against the current IOC list and TI feeds.
func (s *Server) scanArchiveDir() []string {
	var files []string
	if _, err := os.Stat(archiveDir); err != nil {
		return files
	}
	filepath.Walk(archiveDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if strings.HasSuffix(name, ".log") ||
			strings.HasSuffix(name, ".log.gz") ||
			strings.HasSuffix(name, ".gz") ||
			strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".ndjson") {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// ArchiveResult summarizes the outcome of a single archive run.
type ArchiveResult struct {
	FilesArchived  int    `json:"files_archived"`
	BytesArchived  int64  `json:"bytes_archived"`
	FindingsPruned int    `json:"findings_pruned"`
	Skipped        int    `json:"skipped"`
	Err            string `json:"error,omitempty"`
}

// dirDateFromPath returns the time.Time encoded in the first YYYY-MM-DD
// path segment, plus true. Zeek stores rotated logs under date-named
// subdirectories (/logs/<sensor>/YYYY-MM-DD/...), so this gives the actual
// log date independent of file mtime — which rsync does not always preserve
// when crossing mount-point boundaries. Returns false if no date segment
// is found; the caller falls back to mtime.
func dirDateFromPath(path string) (time.Time, bool) {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if t, err := time.Parse("2006-01-02", seg); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// runArchive moves files under logsDir older than `afterDays` into
// archiveDir, preserving the directory layout. Age is determined by the
// YYYY-MM-DD segment in the path when present (the Zeek date-tree structure)
// and falls back to file mtime for logs without that structure. If
// pruneFindings is set, findings with a Timestamp older than the cutoff
// are also removed.
//
// dryRun reports what would be moved/pruned without touching anything on
// disk or in the findings table — used to power the "preview before
// confirm" flow on Run Archive Now. triggeredBy is recorded into the
// last-run telemetry on a real run; it should be the admin's display
// name for manual triggers or "scheduled" for the watch-tick auto path.
func (s *Server) runArchive(afterDays int, pruneFindings, dryRun bool, triggeredBy string) ArchiveResult {
	var res ArchiveResult
	if afterDays <= 0 {
		res.Err = "archive_after_days must be positive"
		return res
	}
	if s.logsDir == "" {
		res.Err = "logs directory is not configured"
		return res
	}
	cutoff := time.Now().Add(-time.Duration(afterDays) * 24 * time.Hour)

	_ = filepath.Walk(s.logsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if !(strings.HasSuffix(name, ".log") ||
			strings.HasSuffix(name, ".log.gz") ||
			strings.HasSuffix(name, ".gz") ||
			strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".ndjson")) {
			return nil
		}
		logDate, hasDate := dirDateFromPath(path)
		if hasDate {
			if !logDate.Before(cutoff) {
				return nil
			}
		} else if !info.ModTime().Before(cutoff) {
			return nil
		}
		rel, err := filepath.Rel(s.logsDir, path)
		if err != nil {
			res.Skipped++
			return nil
		}
		dst := filepath.Join(archiveDir, rel)
		if dryRun {
			// Preview is a pure read — no MkdirAll, no moves. The
			// dst-collision check IS still safe to run as a stat()
			// because it only reads the destination state; mirroring
			// it here keeps the preview honest. Pre-fix the dry-run
			// counted every eligible source as movable and the real
			// run silently turned half of them into Skipped on a
			// re-trigger, so admins saw "23 files / 4.1 GiB" preview
			// → "12 files / 2.1 GiB, 11 skipped" actual. Audit
			// 2026-05-10 LOW.
			if _, err := os.Stat(dst); err == nil {
				res.Skipped++
				return nil
			}
			res.FilesArchived++
			res.BytesArchived += info.Size()
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			slog.Warn("archive: mkdir failed", "path", filepath.Dir(dst), "err", err)
			res.Skipped++
			return nil
		}
		if _, err := os.Stat(dst); err == nil {
			res.Skipped++
			return nil
		}
		if err := moveFile(path, dst); err != nil {
			slog.Warn("archive: move failed", "src", path, "dst", dst, "err", err)
			res.Skipped++
			return nil
		}
		res.FilesArchived++
		res.BytesArchived += info.Size()
		return nil
	})

	if !dryRun && res.FilesArchived > 0 {
		pruneEmptyDirs(s.logsDir)
	}

	if pruneFindings {
		if dryRun {
			res.FindingsPruned = s.store.CountFindingsBefore(cutoff)
		} else {
			res.FindingsPruned = s.store.PruneFindingsBefore(cutoff)
		}
	}

	if !dryRun {
		s.store.RecordArchiveRun(res.FilesArchived, res.BytesArchived, res.FindingsPruned, triggeredBy)
		slog.Info("archive: run complete",
			"relocated", res.FilesArchived,
			"bytes", res.BytesArchived,
			"skipped", res.Skipped,
			"pruned", res.FindingsPruned,
			"initiator", triggeredBy)
	}
	return res
}

// pruneEmptyDirs removes empty subdirectories under root, working from
// deepest paths upward so parent directories are reconsidered after their
// children are gone. root itself is never removed. Best-effort — failures
// are silent because the caller already considers the archive successful.
func pruneEmptyDirs(root string) {
	if root == "" {
		return
	}
	var dirs []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || path == root {
			return nil
		}
		dirs = append(dirs, path)
		return nil
	})
	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i], string(os.PathSeparator)) >
			strings.Count(dirs[j], string(os.PathSeparator))
	})
	for _, d := range dirs {
		_ = os.Remove(d) // succeeds only when the directory is empty
	}
}

// moveFile relocates src → dst. Uses os.Rename on the same filesystem and
// falls back to copy+remove when crossing a mount boundary (EXDEV) — /logs is
// a bind mount, /data is a volume, so that fallback is the normal case.
//
// Pre-fix the EXDEV check was an empty else-if body, so any rename failure
// (permission denied on dst, source vanished mid-archive, dst exists) fell
// through to the copy path and either silently masked the real failure or
// produced a misleading second error from os.Open. The fallback is now
// gated to EXDEV explicitly; every other error short-circuits with the
// real os.Rename diagnostic intact. Audit 2026-05-10 NEW-13.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	if srcInfo, err := os.Stat(src); err == nil {
		_ = os.Chtimes(dst, srcInfo.ModTime(), srcInfo.ModTime())
	}
	return os.Remove(src)
}
