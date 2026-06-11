package server

import (
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

func (s *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetAllowlist())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var entries []string
		if err := decodeJSONBody(w, r, &entries, listBodyMaxBytes); err != nil {
			return
		}
		beforeAllow := s.store.GetAllowlist()
		s.store.SetAllowlist(entries)
		added, removed := diffStringSets(beforeAllow, entries)
		s.recordAudit(r, "allowlist_edit", auditEvent{
			TargetType: "allowlist",
			BeforeValue: map[string]any{
				"entry_count": len(beforeAllow),
				"sha256":      hashStringList(beforeAllow),
			},
			AfterValue: map[string]any{
				"entry_count": len(entries),
				"sha256":      hashStringList(entries),
			},
			Details: listEditAuditDetail(added, removed),
		})
		jsonOK(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleIOC(w http.ResponseWriter, r *http.Request) {
	// kind=fp routes to the JA3/JA4 fingerprint IOC list (ioc_fingerprints.go);
	// the default (no kind / kind=net) is the IP/CIDR/domain list below. The
	// default branch is unchanged so the original /api/ioc contract still holds.
	if r.URL.Query().Get("kind") == "fp" {
		s.handleIOCFingerprints(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetIOCList())
	case http.MethodPut:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var entries []string
		if err := decodeJSONBody(w, r, &entries, listBodyMaxBytes); err != nil {
			return
		}
		beforeIOC := s.store.GetIOCList()
		s.store.SetIOCList(entries)
		added, removed := diffStringSets(beforeIOC, entries)
		s.recordAudit(r, "ioc_edit", auditEvent{
			TargetType: "ioc_list",
			BeforeValue: map[string]any{
				"entry_count": len(beforeIOC),
				"sha256":      hashStringList(beforeIOC),
			},
			AfterValue: map[string]any{
				"entry_count": len(entries),
				"sha256":      hashStringList(entries),
			},
			Details: listEditAuditDetail(added, removed),
		})
		jsonOK(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sups := s.store.GetSuppressions()
		out := make([]map[string]any, 0, len(sups))
		for target, entry := range sups {
			out = append(out, map[string]any{"target": target, "expiry": entry.Expiry.Unix(), "detail": entry.Detail})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)

	case http.MethodPost:
		if u := userFromCtx(r); u.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Target string  `json:"target"`
			Days   float64 `json:"days"`
			Detail string  `json:"detail"`
		}
		if err := decodeJSONBody(w, r, &req, suppressBodyMaxBytes); err != nil {
			return
		}
		if strings.TrimSpace(req.Target) == "" {
			jsonError(w, "target is required", http.StatusBadRequest)
			return
		}
		// Bounded validation. Pre-fix only `days > 0` was checked, so
		// {"days": 1e15} caused float→int64 overflow inside
		// time.Duration construction (1e15 * 86400e9 overflows the
		// signed int64 ceiling, wrapping to a negative or pathological
		// value). The resulting expiry could land in the past
		// (suppression immediately false), or thousands of years
		// in the future (suppression effectively forever). NaN/Inf
		// gave undefined-behavior conversions. Both surfaces were
		// soft-DoS / audit-bypass shapes for an analyst who could
		// reach this endpoint. 365-day cap is generous — the longest
		// realistic suppression window — and bounds the duration
		// math comfortably within int64. Audit 2026-05-10 NEW-7.
		if math.IsNaN(req.Days) || math.IsInf(req.Days, 0) {
			jsonError(w, "days must be a finite number", http.StatusBadRequest)
			return
		}
		if req.Days <= 0 || req.Days > 365 {
			jsonError(w, "days must be in (0, 365]", http.StatusBadRequest)
			return
		}
		expiry := time.Now().Add(time.Duration(req.Days * float64(24*time.Hour)))
		s.store.AddSuppression(req.Target, expiry, req.Detail)
		s.recordAudit(r, "suppression_add", auditEvent{
			TargetType: "suppression",
			TargetID:   req.Target,
			TargetName: req.Target,
			AfterValue: map[string]any{
				"days": req.Days, "detail": req.Detail, "expiry": expiry.Unix(),
			},
		})
		jsonOK(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	// Suppression keys are user-supplied identifiers (host/IP/regex)
	// that the frontend percent-encodes into the path. Pre-fix we
	// trimmed the prefix and passed the raw escaped form to the
	// store, so a key containing "/" or "%" never matched the stored
	// entry and the delete silently no-op'd from the analyst's POV.
	// Decode before lookup; reject malformed escapes with 400 instead
	// of guessing. Audit 2026-05-10 LOW.
	raw := strings.TrimPrefix(r.URL.Path, "/api/suppressions/")
	target, err := url.PathUnescape(raw)
	if err != nil {
		jsonError(w, "invalid suppression key", http.StatusBadRequest)
		return
	}
	s.store.RemoveSuppression(target)
	s.recordAudit(r, "suppression_delete", auditEvent{
		TargetType: "suppression",
		TargetID:   target,
		TargetName: target,
	})
	jsonOK(w)
}

// handleSuggestedAllowlist serves GET /api/pair-allowlist/suggested — a
// read-only list of beacon pairs that meet both suggestion gates (14+
// distinct history days and an acknowledged finding). Any authenticated
// role may read; applying a suggestion uses the existing POST
// /api/pair-allowlist endpoint which enforces the write-role gate there.
func (s *Server) handleSuggestedAllowlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	suggestions := s.store.SuggestedPairAllowlist()
	if suggestions == nil {
		suggestions = []model.SuggestedAllowEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(suggestions)
}

// handlePairAllowlist serves GET (list, any role) and POST (create,
// write roles) for the tuple-scoped finding filter. It is a pure view
// filter — see store.AddPairAllow / migrations/0017.
func (s *Server) handlePairAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := s.store.ListPairAllowlist()
		if rules == nil {
			rules = []model.PairAllowEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		me := userFromCtx(r)
		if me.Role == model.RoleViewer {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Src         string `json:"src"`
			Dst         string `json:"dst"`
			Port        string `json:"port"`
			FindingType string `json:"finding_type"`
			Sensor      string `json:"sensor"`
			Detail      string `json:"detail"`
		}
		if err := decodeJSONBody(w, r, &req, suppressBodyMaxBytes); err != nil {
			return
		}
		req.Src = strings.TrimSpace(req.Src)
		req.Dst = strings.TrimSpace(req.Dst)
		req.Port = strings.TrimSpace(req.Port)
		req.FindingType = strings.TrimSpace(req.FindingType)
		req.Sensor = strings.TrimSpace(req.Sensor)
		if req.Src == "" || req.Dst == "" {
			jsonError(w, "src and dst are required", http.StatusBadRequest)
			return
		}
		// Each side is an IP or a CIDR. Validated here so the store's
		// index rebuild never has to cope with a malformed rule (a bad
		// CIDR there is dropped as inert — see rebuildPairAllowIdxLocked).
		for _, side := range []struct{ name, v string }{{"src", req.Src}, {"dst", req.Dst}} {
			if strings.Contains(side.v, "/") {
				if _, _, err := net.ParseCIDR(side.v); err != nil {
					jsonError(w, side.name+" is not a valid CIDR: "+side.v, http.StatusBadRequest)
					return
				}
			} else if net.ParseIP(side.v) == nil {
				jsonError(w, side.name+" is not a valid IP or CIDR: "+side.v, http.StatusBadRequest)
				return
			}
		}
		id, err := s.store.AddPairAllow(model.PairAllowEntry{
			Src:         req.Src,
			Dst:         req.Dst,
			Port:        req.Port,
			FindingType: req.FindingType,
			Sensor:      req.Sensor,
			Detail:      req.Detail,
			CreatedBy:   me.Email,
			CreatedAt:   time.Now().Unix(),
		})
		if err != nil {
			jsonError(w, "failed to add pair allow rule", http.StatusInternalServerError)
			return
		}
		s.recordAudit(r, "pair_allowlist_add", auditEvent{
			TargetType: "pair_allowlist",
			TargetID:   strconv.FormatInt(id, 10),
			TargetName: req.Src + "→" + req.Dst + ":" + req.Port,
			AfterValue: map[string]any{
				"src": req.Src, "dst": req.Dst, "port": req.Port,
				"finding_type": req.FindingType, "detail": req.Detail,
			},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeletePairAllow serves DELETE /api/pair-allowlist/{id} (write
// roles). Removing a rule unhides its matching findings on the next
// /api/findings fetch — they were never dropped from the store.
func (s *Server) handleDeletePairAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/pair-allowlist/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, "invalid rule id", http.StatusBadRequest)
		return
	}
	s.store.RemovePairAllow(id)
	s.recordAudit(r, "pair_allowlist_remove", auditEvent{
		TargetType: "pair_allowlist",
		TargetID:   idStr,
		TargetName: idStr,
	})
	jsonOK(w)
}
