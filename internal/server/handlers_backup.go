package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// handleAdminBackup snapshots the SQLite database and streams it to
// the client as a downloadable .db file. The snapshot uses
// `VACUUM INTO`, the textbook SQLite primitive for consistent
// hot-backups — raw file copy would miss data that hasn't been
// checkpointed out of the WAL yet. The temp file is removed after
// the stream completes (or fails); the live DB at /data/archer.db
// is untouched.
//
// Admin-only (registered via the admin() middleware). Audit-logged
// as action="db_backup" so an exfil-via-backup attempt leaves a
// trail. The file contains every finding, note, audit row, sensor
// secret, user credential hash, and TI feed indicator — treat
// downloaded backups with the same care as the live DB.
func (s *Server) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// VACUUM INTO refuses to write to an existing file. os.CreateTemp
	// creates the file to reserve the unique name, then we remove it
	// so SQLite has a clean target. The deferred Remove cleans up the
	// snapshot once the stream completes — backups don't accumulate
	// on the server.
	tmpFile, err := os.CreateTemp("", "archer-backup-*.db")
	if err != nil {
		log.Printf("backup: temp file create failed: %v", err)
		http.Error(w, "backup setup failed", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	if err := os.Remove(tmpPath); err != nil {
		log.Printf("backup: pre-VACUUM unlink failed: %v", err)
		http.Error(w, "backup setup failed", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpPath)

	db := s.users.DB()
	if _, err := db.ExecContext(r.Context(), "VACUUM INTO ?", tmpPath); err != nil {
		log.Printf("backup: VACUUM INTO failed: %v", err)
		http.Error(w, "backup snapshot failed", http.StatusInternalServerError)
		return
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		log.Printf("backup: open snapshot failed: %v", err)
		http.Error(w, "backup open failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	var size int64
	if stat, err := f.Stat(); err == nil {
		size = stat.Size()
	}

	filename := fmt.Sprintf("archer-backup-%s.db", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}

	if _, err := io.Copy(w, f); err != nil {
		// Client disconnect mid-stream is a benign cause; log and move
		// on. Headers are already sent so we can't usefully error the
		// response.
		log.Printf("backup: stream interrupted: %v", err)
		return
	}

	s.recordAudit(r, "db_backup", auditEvent{
		Details: map[string]any{
			"size_bytes": size,
			"filename":   filename,
		},
	})
}
