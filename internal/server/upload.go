package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// handleLogsScan manages the Zeek log file registry.
// GET  — returns configured dir + current file count without scanning (safe, read-only).
// POST — walks logsDir, registers all Zeek log files, returns results.
func (s *Server) handleLogsScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		files := s.store.GetUploadedFiles()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"dir":   s.logsDir,
			"count": len(files),
		})

	case http.MethodPost:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		dir := s.logsDir
		if dir == "" {
			jsonError(w, "no logs directory configured (start with --logs-dir)", http.StatusBadRequest)
			return
		}

		var found []string
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			name := info.Name()
			if strings.HasSuffix(name, ".log") ||
				strings.HasSuffix(name, ".log.gz") ||
				strings.HasSuffix(name, ".gz") ||
				strings.HasSuffix(name, ".json") ||
				strings.HasSuffix(name, ".ndjson") {
				found = append(found, path)
			}
			return nil
		})
		if err != nil {
			jsonError(w, "scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.store.SetUploadedFiles(found)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"dir":   dir,
			"count": len(found),
			"files": found,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 512 MB max upload
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		jsonError(w, "parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	tmpDir := filepath.Join(os.TempDir(), "archer_uploads")
	_ = os.MkdirAll(tmpDir, 0o750)

	var saved []string
	files := r.MultipartForm.File["files"]
	for _, fh := range files {
		name := filepath.Base(fh.Filename)
		if !strings.HasSuffix(name, ".log") && !strings.HasSuffix(name, ".log.gz") && !strings.HasSuffix(name, ".gz") {
			continue
		}
		dst := filepath.Join(tmpDir, fmt.Sprintf("%d_%s", len(saved), name))
		src, err := fh.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(dst)
		if err != nil {
			src.Close()
			continue
		}
		_, copyErr := io.Copy(out, src)
		src.Close()
		out.Close()
		if copyErr != nil {
			os.Remove(dst)
			continue
		}
		saved = append(saved, dst)
	}

	// Append to store
	for _, p := range saved {
		s.store.AppendUploadedFile(p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"saved": saved,
		"total": len(s.store.GetUploadedFiles()),
	})
}

func (s *Server) handleClearFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.store.SetUploadedFiles(nil)
	jsonOK(w)
}
