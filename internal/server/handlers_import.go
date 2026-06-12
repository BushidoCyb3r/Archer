package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// handleImportJSON accepts a previously-exported Archer state bundle and
// clears existing findings before inserting the imported set, making import
// a true replace. Allowlist and IOC list are updated only when the imported
// bundle includes them. Admin-only — see /api/import route comment for
// why analysts can't reach this surface.
//
// Two boundary defenses on top of the role gate. First, the body is
// capped at importMaxBytes; without the cap a malicious or buggy client
// could POST a multi-GB body and exhaust memory before the decode
// finishes. Second, every finding is validated up-front: rejected types,
// severities, scores, or timestamps fail the whole import rather than
// partially applying. Pre-fix the decoder accepted any shape and
// SetFindings would happily store a Type="<script>" finding with
// Score=99999 — the stored representation is then indistinguishable from
// analyzer output once it lives in the DB. Audit 2026-05-10 NEW-14.
const importMaxBytes = 64 << 20 // 64 MiB — large enough for a real export, small enough to bound memory

func (s *Server) handleImportJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Findings  []model.Finding `json:"findings"`
		Allowlist []string        `json:"allowlist"`
		IOCList   []string        `json:"ioc_list"`
	}
	// decodeJSONBody centralises the size-cap + 413-on-overflow +
	// no-decoder-internals-in-error-response discipline that NEW-40
	// established. Pre-fix this site reflected raw err.Error() text
	// back to the caller (decoder offsets, character positions) —
	// the exact echo-decoder-internals shape NEW-40 was meant to
	// eliminate for the admin endpoints. NEW-61 closes the gap.
	if err := decodeJSONBody(w, r, &payload, importMaxBytes); err != nil {
		return
	}
	for i, f := range payload.Findings {
		if err := validateImportedFinding(f); err != nil {
			jsonError(w, fmt.Sprintf("findings[%d]: %v", i, err), http.StatusBadRequest)
			return
		}
	}
	// Re-assign IDs into a fresh sequence and translate every
	// Correlations slice through an old→new map in the same pass.
	// Without the translation step, exports carrying cross-finding
	// references (Correlated Activity's contributor IDs, or any
	// participating row's sibling list) would silently lose those
	// references on import — the user's old IDs no longer match
	// anything in the new fresh-ID space, and SetFindings's
	// translation (NEW-91) drops IDs that resolve to neither a fresh
	// nor a historical finding. NEW-97, twenty-second audit round.
	oldToNew := make(map[int]int, len(payload.Findings))
	for i := range payload.Findings {
		oldToNew[payload.Findings[i].ID] = i + 1
		payload.Findings[i].ID = i + 1
	}
	for i := range payload.Findings {
		if len(payload.Findings[i].Correlations) == 0 {
			continue
		}
		translated := make([]int, 0, len(payload.Findings[i].Correlations))
		for _, oldID := range payload.Findings[i].Correlations {
			if newID, ok := oldToNew[oldID]; ok {
				translated = append(translated, newID)
			}
		}
		payload.Findings[i].Correlations = translated
	}
	if !s.store.TryStartAnalysis() {
		jsonError(w, "analysis in progress", http.StatusConflict)
		return
	}
	defer s.store.SetAnalyzing(false)
	cleared := s.store.ClearFindings()
	s.store.SetFindingsForImport(payload.Findings)
	if len(payload.Allowlist) > 0 {
		s.store.SetAllowlist(payload.Allowlist)
	}
	if len(payload.IOCList) > 0 {
		s.store.SetIOCList(payload.IOCList)
	}
	s.recordAudit(r, "finding_import", auditEvent{
		TargetType: "import",
		Details: map[string]any{
			"findings_imported": len(payload.Findings),
			"findings_cleared":  cleared,
			"allowlist":         len(payload.Allowlist),
			"ioc_list":          len(payload.IOCList),
		},
	})
	jsonOK(w)
}

// validateImportedFinding rejects any finding whose Type, Severity,
// Score, or Timestamp doesn't match the analyzer's output discipline.
// The known-Type set is derived from model.ScoreExplanations (the
// authoritative analyst-facing description map) plus the legacy
// "Threat Intel Hit" string, which pre-v0.7.0 builds may still have in
// exported bundles. Anything else means either an analyzer change that
// forgot to update the map or a hostile/malformed bundle — both
// scenarios are better surfaced as a 400 than silently stored.
func validateImportedFinding(f model.Finding) error {
	if _, ok := model.ScoreExplanations[f.Type]; !ok && f.Type != model.TypeTIHitLegacy {
		return fmt.Errorf("unknown finding type %q", f.Type)
	}
	switch f.Severity {
	case model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo:
	default:
		return fmt.Errorf("invalid severity %q", f.Severity)
	}
	if f.Score < 0 || f.Score > 100 {
		return fmt.Errorf("score %d outside [0, 100]", f.Score)
	}
	if f.Timestamp != "" {
		// Same format the analyzer emits everywhere (fmtTS in
		// internal/analysis): "YYYY-MM-DD HH:MM:SS". A bundle
		// produced by a real export round-trips this format, so a
		// stricter schema-level check is safe.
		if _, err := time.Parse("2006-01-02 15:04:05", f.Timestamp); err != nil {
			return fmt.Errorf("timestamp %q must be 2006-01-02 15:04:05", f.Timestamp)
		}
	}
	switch f.Status {
	case model.StatusOpen, model.StatusAcknowledged, model.StatusEscalated, model.StatusDismissed:
	default:
		return fmt.Errorf("invalid status %q", f.Status)
	}
	return nil
}
