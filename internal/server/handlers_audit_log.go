package server

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// handleAuditLog serves GET /api/audit-log. Admin-only (enforced by
// the route middleware in server.go). Cursor-based pagination on
// id: `cursor` is exclusive, defaulting to 0 = most-recent page;
// `count` defaults to 100 and is capped at 500 server-side.
// Response shape:
//
//	{
//	  "entries": [{...}, {...}],
//	  "total":   1234,
//	  "next":    42   // cursor for the next page; 0 means no more
//	}
//
// Audit 2026-05-10 v0.14.0 audit-log addition.
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	cursor, _ := strconv.ParseInt(q.Get("cursor"), 10, 64)
	count, _ := strconv.Atoi(q.Get("count"))
	if count <= 0 {
		count = 100
	}

	entries := s.store.ListAuditLog(cursor, count)
	total := s.store.CountAuditLog()
	var next int64
	if len(entries) == count && len(entries) > 0 {
		// Another page may exist; advance the cursor to the
		// smallest id we just returned (results are id-DESC).
		next = entries[len(entries)-1].ID
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entries": entries,
		"total":   total,
		"next":    next,
	})
}
