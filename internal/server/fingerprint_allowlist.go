package server

// Fingerprint allowlist — the "mark benign" surface behind the TLS Fingerprints
// modal. An analyst marks a rare/cross-host JA3/JA4 shape benign so it drops out
// of the inventory wall (and matching findings carry an allowlisted marker).
// Known-bad C2 fingerprints are non-markable: the POST handler rejects them so a
// Cobalt Strike / Sliver match can never be muted. Pure view filter, mirroring
// the pair-allowlist surface — add hides on the next fetch, remove brings it
// back with no re-analysis.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// handleFingerprintAllowlist serves GET (list) and POST (mark benign) on
// /api/fingerprint-allowlist. Analyst+ for POST; viewers are read-only.
func (s *Server) handleFingerprintAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		entries := s.store.ListFingerprintAllowlist()
		if entries == nil {
			entries = []model.FingerprintAllowEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)

	case http.MethodPost:
		me := userFromCtx(r)
		if me.Role == model.RoleViewer {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Kind        string `json:"kind"`
			Fingerprint string `json:"fingerprint"`
			Note        string `json:"note"`
		}
		if err := decodeJSONBody(w, r, &req, suppressBodyMaxBytes); err != nil {
			return
		}
		req.Kind = strings.TrimSpace(strings.ToLower(req.Kind))
		req.Fingerprint = strings.TrimSpace(req.Fingerprint)
		if req.Kind != "ja3" && req.Kind != "ja4" {
			jsonError(w, "kind must be ja3 or ja4", http.StatusBadRequest)
			return
		}
		if req.Fingerprint == "" {
			jsonError(w, "fingerprint is required", http.StatusBadRequest)
			return
		}
		if isKnownBadFingerprint(req.Kind, req.Fingerprint) {
			jsonError(w, "cannot allowlist a known-bad C2 fingerprint", http.StatusBadRequest)
			return
		}
		id, err := s.store.AddFingerprintAllow(model.FingerprintAllowEntry{
			Kind:        req.Kind,
			Fingerprint: req.Fingerprint,
			Note:        req.Note,
			CreatedBy:   me.Email,
			CreatedAt:   time.Now().Unix(),
		})
		if err != nil {
			jsonError(w, "failed to add fingerprint allow entry", http.StatusInternalServerError)
			return
		}
		s.recordAudit(r, "fingerprint_allowlist_add", auditEvent{
			TargetType: "fingerprint_allowlist",
			TargetID:   strconv.FormatInt(id, 10),
			TargetName: req.Kind + ":" + req.Fingerprint,
			AfterValue: map[string]any{"kind": req.Kind, "fingerprint": req.Fingerprint, "note": req.Note},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeleteFingerprintAllow serves DELETE /api/fingerprint-allowlist/{id}
// (write roles). The fingerprint returns to the inventory on the next fetch.
func (s *Server) handleDeleteFingerprintAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/fingerprint-allowlist/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, "invalid entry id", http.StatusBadRequest)
		return
	}
	s.store.RemoveFingerprintAllow(id)
	s.recordAudit(r, "fingerprint_allowlist_remove", auditEvent{
		TargetType: "fingerprint_allowlist",
		TargetID:   idStr,
		TargetName: idStr,
	})
	jsonOK(w)
}

func isKnownBadFingerprint(kind, fp string) bool {
	switch kind {
	case "ja4":
		_, bad := analysis.KnownBadJA4[fp]
		return bad
	case "ja3":
		_, bad := analysis.KnownBadJA3[fp]
		return bad
	}
	return false
}
