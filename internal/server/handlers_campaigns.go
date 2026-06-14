package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// aggregateFindingPopulation returns the filtered findings the Campaigns and
// Hosts roll-ups are built from. It strips the params that never apply to an
// aggregate view (ioc_only, delta, and the paging params) but honors status:
// the top-level views send no status, so filterFindings default-excludes
// dismissed findings (the population the views show), while the Dismissed >
// Campaigns sub-tab sends status=dismissed to roll up only that bucket.
func (s *Server) aggregateFindingPopulation(r *http.Request) ([]model.Finding, error) {
	q := r.URL.Query()
	q.Del("ioc_only")
	q.Del("delta")
	q.Del("limit")
	q.Del("offset")
	return s.filterFindings(s.store.GetFindings(), q, newBoundaryFromCtx(r))
}

// handleCampaigns returns the destination-level campaign roll-up: every
// external destination contacted by ≥2 distinct source IPs, with its source
// list, max score, and finding types. The server does the reduce so the client
// no longer fetches the whole findings corpus to aggregate it in the browser.
// Honors the same filter surface as /api/findings (time / severity / type /
// score / q=). Sorting and pagination stay client-side — the campaign set is
// small enough to ship whole.
func (s *Server) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	findings, err := s.aggregateFindingPopulation(r)
	if err != nil {
		jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"campaigns": buildCampaignsRollup(findings)})
}

// handleHosts returns the per-host roll-up: every org-internal source IP with
// its risk score, finding count, beacon density, worst severity, and finding
// types. Counterpart to handleCampaigns for the Hosts tab; same population,
// same filter surface, client-side sort/paginate.
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	findings, err := s.aggregateFindingPopulation(r)
	if err != nil {
		jsonError(w, "invalid query: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"hosts": buildHostsRollup(findings, s.store.GetConfig().OrgInternalCIDRs),
	})
}

// handleCampaignDismiss dismisses every open finding belonging to one campaign
// — matched by (dst_ip, dst_port) — in a single request. It replaces the
// former client-side loop that resolved member findings from the in-memory
// aggregate cache and PATCHed each one individually. Write-gated (analyst+);
// already-dismissed findings are skipped, and each dismissal is audited
// individually so the trail matches an equivalent run of per-finding status
// changes.
func (s *Server) handleCampaignDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DstIP   string `json:"dst_ip"`
		DstPort string `json:"dst_port"`
		Note    string `json:"note"`
	}
	if err := decodeJSONBody(w, r, &req, noteBodyMaxBytes); err != nil {
		return
	}
	if req.DstIP == "" {
		jsonError(w, "dst_ip required", http.StatusBadRequest)
		return
	}
	user := userFromCtx(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	dismissed := 0
	for _, f := range s.store.GetFindings() {
		if f.DstIP != req.DstIP || f.DstPort != req.DstPort || f.Status == model.StatusDismissed {
			continue
		}
		before, found, err := s.store.UpdateFinding(f.ID, model.StatusDismissed, user.DisplayName(), req.Note, ts)
		if err != nil || !found {
			continue
		}
		if req.Note != "" {
			_, _ = s.store.AddNote(f.ID, model.Note{
				Text:        req.Note,
				Author:      user.DisplayName(),
				AuthorEmail: user.Email,
				Timestamp:   ts,
			})
		}
		s.recordAudit(r, "finding_status_change", auditEvent{
			TargetType:  "finding",
			TargetID:    strconv.Itoa(f.ID),
			TargetName:  findingAuditName(before),
			BeforeValue: map[string]any{"status": string(before.Status)},
			AfterValue:  map[string]any{"status": string(model.StatusDismissed)},
			Details:     map[string]any{"note_length": len(strings.TrimSpace(req.Note)), "bulk": "campaign"},
		})
		dismissed++
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"dismissed": dismissed})
}
