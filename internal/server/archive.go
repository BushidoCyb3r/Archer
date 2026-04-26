package server

import (
	"errors"
	"io"
	"log"
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

// ArchiveResult summarizes the outcome of a single archive run.
type ArchiveResult struct {
	FilesArchived    int    `json:"files_archived"`
	BytesArchived    int64  `json:"bytes_archived"`
	FindingsPruned   int    `json:"findings_pruned"`
	Skipped          int    `json:"skipped"`
	Err              string `json:"error,omitempty"`
}

// runArchive moves files under logsDir whose mtime is older than `afterDays`
// into archiveDir, preserving the directory layout. If pruneFindings is set,
// findings with a Timestamp older than the cutoff are also removed.
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
		if !info.ModTime().Before(cutoff) {
			return nil
		}
		rel, err := filepath.Rel(s.logsDir, path)
		if err != nil {
			res.Skipped++
			return nil
		}
		dst := filepath.Join(archiveDir, rel)
		if dryRun {
			// Don't create directories or stat the destination — preview must
			// be a pure read. A naming collision would show up the same way
			// (Skipped) but for now we treat all eligible files as movable;
			// admins running back-to-back archives will see Skipped on the
			// second real run if collisions actually occur.
			res.FilesArchived++
			res.BytesArchived += info.Size()
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			log.Printf("archive: mkdir %s: %v", filepath.Dir(dst), err)
			res.Skipped++
			return nil
		}
		if _, err := os.Stat(dst); err == nil {
			res.Skipped++
			return nil
		}
		if err := moveFile(path, dst); err != nil {
			log.Printf("archive: move %s → %s: %v", path, dst, err)
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
		log.Printf("archive: %d files (%d bytes) relocated, %d skipped, %d findings pruned (by %s)",
			res.FilesArchived, res.BytesArchived, res.Skipped, res.FindingsPruned, triggeredBy)
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
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		// Rename failed for a reason other than cross-device; try copy anyway.
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
