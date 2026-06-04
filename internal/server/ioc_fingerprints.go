package server

// JA3/JA4 fingerprint IOC list — the operator-managed companion to the built-in
// KnownBadJA3/KnownBadJA4 C2 tables. Operator entries are merged into the SSL
// analyzer at analyze time (Analyzer.SetOperatorFingerprints) and emit the same
// Malicious JA3 / Malicious JA4 findings as the built-ins, so it doesn't matter
// where a flagged fingerprint originated.
//
// Two surfaces feed this list: the JA3/JA4 tab of the IOC modal (full-text PUT,
// handleIOCFingerprints) and the "Mark malicious" button on the TLS Fingerprints
// wall (single-entry POST, handleMarkFingerprintMalicious).

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/BushidoCyb3r/Archer/internal/analysis"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// builtinFP is one hardcoded C2 fingerprint surfaced to the UI so the JA3/JA4
// tab can show the always-active set as undeletable, re-injected lines.
type builtinFP struct {
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label"`
}

// builtinFingerprints returns the KnownBadJA3 + KnownBadJA4 tables flattened and
// sorted (JA3 first, then by fingerprint) for stable rendering.
func builtinFingerprints() []builtinFP {
	out := make([]builtinFP, 0, len(analysis.KnownBadJA3)+len(analysis.KnownBadJA4))
	for fp, label := range analysis.KnownBadJA3 {
		out = append(out, builtinFP{Kind: "ja3", Fingerprint: fp, Label: label})
	}
	for fp, label := range analysis.KnownBadJA4 {
		out = append(out, builtinFP{Kind: "ja4", Fingerprint: fp, Label: label})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// bareFingerprint reduces a textarea line to its first whitespace-delimited
// token, lowercased — dropping any inline ` # label` the UI rendered.
func bareFingerprint(line string) string {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		line = line[:i]
	}
	return strings.ToLower(line)
}

// handleIOCFingerprints serves GET/PUT for /api/ioc?kind=fp. GET returns the
// built-in set plus the operator additions so the UI can compose a single
// textarea; PUT replaces the operator list, dropping any built-in lines (they
// stay active from code and are re-added on the next GET) and comments.
func (s *Server) handleIOCFingerprints(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"builtin":  builtinFingerprints(),
			"operator": s.store.GetIOCFingerprints(),
		})
	case http.MethodPut:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var entries []string
		if err := decodeJSONBody(w, r, &entries, listBodyMaxBytes); err != nil {
			return
		}
		// Drop built-in fingerprints so the always-active set is never
		// double-stored; the store sanitizer lowercases, de-comments, and
		// dedupes the remainder.
		operator := make([]string, 0, len(entries))
		for _, e := range entries {
			fp := bareFingerprint(e)
			if fp == "" || strings.HasPrefix(strings.TrimSpace(e), "#") {
				continue
			}
			if isKnownBadFingerprint("ja3", fp) || isKnownBadFingerprint("ja4", fp) {
				continue
			}
			operator = append(operator, fp)
		}
		before := s.store.GetIOCFingerprints()
		s.store.SetIOCFingerprints(operator)
		after := s.store.GetIOCFingerprints()
		added, removed := diffStringSets(before, after)
		s.recordAudit(r, "ioc_fingerprint_edit", auditEvent{
			TargetType: "ioc_fp_list",
			BeforeValue: map[string]any{
				"entry_count": len(before),
				"sha256":      hashStringList(before),
			},
			AfterValue: map[string]any{
				"entry_count": len(after),
				"sha256":      hashStringList(after),
			},
			Details: listEditAuditDetail(added, removed),
		})
		jsonOK(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMarkFingerprintMalicious serves POST /api/ioc-fingerprint — the "Mark
// malicious" button on the TLS Fingerprints wall. Adds one JA3/JA4 fingerprint
// to the operator IOC list so it flags as Malicious JA3 / JA4 on the next
// analysis. Built-in fingerprints are already malicious, so a request for one
// is a no-op success.
func (s *Server) handleMarkFingerprintMalicious(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := decodeJSONBody(w, r, &req, suppressBodyMaxBytes); err != nil {
		return
	}
	fp := bareFingerprint(req.Fingerprint)
	if fp == "" {
		jsonError(w, "fingerprint is required", http.StatusBadRequest)
		return
	}
	already := isKnownBadFingerprint("ja3", fp) || isKnownBadFingerprint("ja4", fp)
	if !already {
		if s.store.AddIOCFingerprint(fp) {
			s.recordAudit(r, "ioc_fingerprint_add", auditEvent{
				TargetType: "ioc_fp_list",
				TargetName: fp,
				AfterValue: map[string]any{"fingerprint": fp},
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "builtin": already})
}
