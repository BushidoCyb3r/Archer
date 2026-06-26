package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/llm"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// llmLocalProviders are the OpenAI-compatible providers that reach a model
// inside the operator's own boundary (local/LAN or an accredited enclave like
// the DoD GenAI platform) rather than a third-party cloud. The UI uses this to
// label the egress posture so an analyst knows whether clicking "AI Triage"
// sends evidence off-box.
var llmLocalProviders = map[string]bool{"ollama": true, "dod": true, "custom": true}

// llmSettingsFromConfig maps the persisted Config onto the provider-agnostic
// llm.Settings. Single source of truth for the mapping, used by the enrich
// handler, the status endpoint, and the config-PUT boundary check.
func llmSettingsFromConfig(cfg config.Config) llm.Settings {
	return llm.Settings{
		Provider:   cfg.LLMProvider,
		BaseURL:    cfg.LLMBaseURL,
		Model:      cfg.LLMModel,
		APIKey:     cfg.LLMAPIKey,
		TimeoutSec: cfg.LLMTimeoutSec,
	}
}

// handleLLMStatus reports whether AI enrichment is enabled and configured, the
// active provider, and whether that provider keeps evidence on the operator's
// network. No secrets are exposed. Any authenticated user — the detail pane
// needs it to decide whether to render the button.
func (s *Server) handleLLMStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.store.GetConfig()
	enabled := false
	if cfg.LLMEnabled {
		if _, err := llm.NewProvider(llmSettingsFromConfig(cfg)); err == nil {
			enabled = true
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"enabled":  enabled,
		"provider": cfg.LLMProvider,
		"local":    llmLocalProviders[strings.ToLower(cfg.LLMProvider)],
	})
}

// handleEnrich kicks off a background AI triage briefing for one finding. It is
// the LLM analog of handleEscalate's TI lookup: validated and dispatched on the
// request, then run off the response path so a slow model never blocks the UI.
func (s *Server) handleEnrich(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if u := userFromCtx(r); u.Role == model.RoleViewer {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	path = strings.TrimSuffix(path, "/enrich")
	id, err := strconv.Atoi(path)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	cfg := s.store.GetConfig()
	if !cfg.LLMEnabled {
		jsonError(w, "AI enrichment is disabled", http.StatusBadRequest)
		return
	}
	provider, err := llm.NewProvider(llmSettingsFromConfig(cfg))
	if err != nil {
		jsonError(w, "AI enrichment is misconfigured: "+err.Error(), http.StatusBadRequest)
		return
	}
	f, ok := s.store.GetFinding(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// In-flight guard: a double-click (or an auto-on-escalate racing a manual
	// click) must not spawn two goroutines that each append a briefing note.
	if !s.acquireEnrich(id) {
		jsonOK(w) // already running for this finding; the first run will publish
		return
	}
	s.auditEnrich(r, f, provider)
	go s.runLLMEnrichment(provider, f, cfg.OrgInternalCIDRs, cfg.OrgInternalDomains)
	jsonOK(w)
}

// acquireEnrich records that an enrichment is in flight for id, returning false
// if one already is. releaseEnrich clears it; runLLMEnrichment defers it.
func (s *Server) acquireEnrich(id int) bool {
	s.llmInflightMu.Lock()
	defer s.llmInflightMu.Unlock()
	if s.llmInflight[id] {
		return false
	}
	if s.llmInflight == nil {
		s.llmInflight = map[int]bool{}
	}
	s.llmInflight[id] = true
	return true
}

func (s *Server) releaseEnrich(id int) {
	s.llmInflightMu.Lock()
	defer s.llmInflightMu.Unlock()
	delete(s.llmInflight, id)
}

// auditEnrich records that a finding's evidence was sent for AI triage —
// who, which finding, which provider, and whether that provider keeps the
// evidence on the operator's network (local) or sends it off-box (cloud). For
// accredited deployments this is the egress trail the escalate path already has.
func (s *Server) auditEnrich(r *http.Request, f model.Finding, provider llm.Provider) {
	posture := "cloud"
	if llmLocalProviders[strings.ToLower(provider.Name())] {
		posture = "local"
	}
	s.recordAudit(r, "finding_ai_enrich", auditEvent{
		TargetType: "finding",
		TargetID:   strconv.Itoa(f.ID),
		TargetName: findingAuditName(f),
		Details:    map[string]any{"provider": provider.Name(), "egress": posture},
	})
}

// runLLMEnrichment assembles the finding's already-collected evidence, redacts
// internal addresses, asks the provider for a triage briefing, expands the
// redaction tokens back, and writes the result as a finding note. It never
// touches Score/Severity/Status — annotation-only by construction. Live
// progress is signalled over SSE so the detail pane can spin and then refresh.
func (s *Server) runLLMEnrichment(provider llm.Provider, f model.Finding, orgCIDRs, orgDomains []string) {
	defer s.releaseEnrich(f.ID)
	publishDone := func(ok bool, errMsg string) {
		data, _ := json.Marshal(map[string]any{
			"finding_id": f.ID,
			"ok":         ok,
			"error":      errMsg,
			"provider":   provider.Name(),
		})
		s.broker.Publish(SSEEvent{Type: "llm_done", Data: string(data)})
	}

	redactor := llm.NewRedactor(orgCIDRs, orgDomains)
	// Finding-intrinsic evidence plus the store-derived decision context (host
	// reputation, fingerprint rarity, campaign roll-ups, related findings) — the
	// full workup, so the verdict rests on everything an analyst would check.
	raw := buildEnrichmentEvidence(f, redactor) + s.decisionContext(f)
	evidence, mapping := redactor.Redact(raw)

	ctx := context.Background()
	text, err := provider.Summarize(ctx, llm.SystemPrompt, evidence)
	if err == llm.ErrRefused {
		publishDone(false, "the model declined to summarize this finding")
		return
	}
	if err != nil {
		slog.Warn("LLM enrichment failed", "finding_id", f.ID, "provider", provider.Name(), "err", err)
		publishDone(false, "AI enrichment request failed")
		return
	}
	briefing := strings.TrimSpace(llm.Expand(text, mapping))
	if briefing == "" {
		publishDone(false, "the model returned an empty briefing")
		return
	}
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	note := model.Note{
		Text:        fmt.Sprintf("AI Triage (%s) — decision support, not a verdict\n\n%s", provider.Name(), briefing),
		Author:      model.AuthorAITriage,
		AuthorEmail: "system",
		Timestamp:   ts,
	}
	if _, err := s.store.AddNote(f.ID, note); err != nil {
		publishDone(false, "could not save the briefing")
		return
	}
	publishDone(true, "")
}

// buildEnrichmentEvidence renders the finding's detector output and existing
// notes into the plain-text block sent to the model. Only fields already
// resident on the finding are used — no new data is gathered. It also adds
// non-identifying structural facts (host class, port context) derived from the
// IPs/port: these restore the discriminators the redactor strips — the model
// can't see that a redacted destination is a broadcast address unless we tell
// it so in a form that carries no real address. The AI Triage notes from prior
// runs are excluded so a re-enrich doesn't feed the model its own output.
func buildEnrichmentEvidence(f model.Finding, r *llm.Redactor) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Finding type: %s\n", f.Type)
	fmt.Fprintf(&b, "Severity: %s  Score: %d\n", f.Severity, f.Score)
	if f.Timestamp != "" {
		fmt.Fprintf(&b, "Observed at: %s\n", f.Timestamp)
	}
	// The detector's own description of what this type means, the benign shapes
	// that mimic it, and how the score is computed — grounds the model in what's
	// actually being claimed and how much weight the score carries, instead of
	// letting it guess from the type name.
	if ex, ok := model.ScoreExplanations[f.Type]; ok {
		if ex.Summary != "" {
			fmt.Fprintf(&b, "\nWhat this detector flags: %s\n", ex.Summary)
		}
		if ex.FalsePositives != "" {
			fmt.Fprintf(&b, "Known benign causes of this detection: %s\n", ex.FalsePositives)
		}
		if ex.Scoring != "" {
			fmt.Fprintf(&b, "How this type is scored: %s\n", strings.TrimRight(ex.Scoring, "\n"))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Source: %s  Destination: %s:%s\n", f.SrcIP, f.DstIP, f.DstPort)
	if cls := r.HostClass(f.SrcIP); cls != "" {
		fmt.Fprintf(&b, "Source address class: %s\n", cls)
	}
	if cls := r.HostClass(f.DstIP); cls != "" {
		fmt.Fprintf(&b, "Destination address class: %s\n", cls)
	}
	if pc := portContext(f.DstPort, f.Service); pc != "" {
		fmt.Fprintf(&b, "Destination port context: %s\n", pc)
	}
	if f.Service != "" {
		fmt.Fprintf(&b, "Service (Zeek DPD): %s\n", f.Service)
	}
	if f.Hostname != "" {
		fmt.Fprintf(&b, "Destination hostname: %s\n", f.Hostname)
	}
	if f.IOCMatch && f.IOCSource != "" {
		fmt.Fprintf(&b, "Threat-intel match: %s\n", f.IOCSource)
	}
	// Structured beacon evidence — the timing/regularity numbers behind the
	// score, surfaced as fields so the model can reason about them (e.g. a high
	// jitter undercuts a "tight beacon" read) instead of fishing them out of the
	// detail prose.
	if model.IsBeaconType(f.Type) {
		if f.SampleSize > 0 {
			fmt.Fprintf(&b, "Beacon timing: mean interval %.1fs, median %.1fs, jitter(CV) %.2f, over %d observations\n",
				f.MeanInterval, f.MedianInterval, f.Jitter, f.SampleSize)
		}
		fmt.Fprintf(&b, "Beacon sub-scores (0=weak, 1=strong): timing %.2f, data-size %.2f, histogram %.2f, duration %.2f\n",
			f.TSScore, f.DSScore, f.HistScore, f.DurScore)
		if f.JA3 != "" || f.JA4 != "" {
			fmt.Fprintf(&b, "TLS client fingerprint: JA3=%s JA4=%s\n", orNone(f.JA3), orNone(f.JA4))
		}
	}
	// Byte volume is meaningful beyond beacons — exfil, long connections — so
	// surface it whenever the pair carries it, not just for beacon types.
	if f.OrigBytes > 0 || f.RespBytes > 0 {
		fmt.Fprintf(&b, "Volume: %d bytes sent (orig), %d bytes received (resp) over the window\n", f.OrigBytes, f.RespBytes)
	}
	// HTTP beacon request paths are highly diagnostic — C2 frameworks ship
	// tell-tale default URIs. Surface the path plus the most-frequent paths.
	if f.URI != "" {
		fmt.Fprintf(&b, "Request path: %s\n", f.URI)
	}
	if len(f.TopURIs) > 0 {
		paths := make([]string, 0, len(f.TopURIs))
		for _, u := range f.TopURIs {
			paths = append(paths, fmt.Sprintf("%s (%d)", u.URI, u.Count))
		}
		fmt.Fprintf(&b, "Most-frequent request paths: %s\n", strings.Join(paths, ", "))
	}
	if f.Detail != "" {
		fmt.Fprintf(&b, "\nDetector detail:\n%s\n", f.Detail)
	}
	var notes []string
	for _, n := range f.Notes {
		if n.Author == model.AuthorAITriage {
			continue
		}
		notes = append(notes, fmt.Sprintf("- [%s] %s", n.Author, n.Text))
	}
	if len(notes) > 0 {
		fmt.Fprintf(&b, "\nAnalyst and threat-intel notes:\n%s\n", strings.Join(notes, "\n"))
	}
	return b.String()
}

// orNone renders an empty string as "(none)" so a fingerprint line reads
// cleanly when only one of JA3/JA4 is present.
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// decisionContext gathers everything the store knows that bears on a verdict
// but isn't on the finding itself — the workup an analyst does before deciding:
//
//   - Destination reputation: operator allowlist, pair-allowlist (analyst-marked
//     known-good are strong benign signals; absence is stated explicitly so the
//     model knows it was checked).
//   - TLS client-fingerprint rarity across the dataset (a rare client clustered
//     across hosts is a strong C2 tell; reuses the detail-pane computation).
//   - The analyzer's own campaign verdict: whether a Multi-Stage Beacon or
//     Correlated Activity roll-up grouped this finding into a coordinated set.
//   - Source host overall risk roll-up (Host Risk Score).
//   - Related findings on the same pair / source / destination, plus how many
//     distinct internal sources reach this destination (fan-out = multi-host C2
//     vs. an isolated pair).
//
// One O(findings) scan plus a few direct lookups — fine for a deliberate click,
// not a hot path. Returns "" only when nothing is known beyond the finding.
func (s *Server) decisionContext(f model.Finding) string {
	var b strings.Builder

	// Destination reputation — known-good markings are decisive benign signals.
	b.WriteString("\nDestination reputation:\n")
	if f.DstIP != "" && s.store.AllowlistMatcher().Matches(f.DstIP) {
		b.WriteString("- Destination IS on the operator allowlist (analyst-marked known-good — strong benign signal).\n")
	} else if f.Hostname != "" && s.store.AllowlistMatcher().Matches(f.Hostname) {
		b.WriteString("- Destination hostname IS on the operator allowlist (analyst-marked known-good — strong benign signal).\n")
	} else {
		b.WriteString("- Destination is NOT on any operator allowlist (no known-good marking).\n")
	}
	if s.store.IsPairAllowed(f.SrcIP, f.DstIP, f.DstPort, f.Type, f.Sensor) {
		b.WriteString("- This exact source→destination relationship is explicitly allowlisted (analyst accepted this pair — strong benign signal).\n")
	}

	// TLS fingerprint rarity / known-bad — only for findings carrying a JA3/JA4.
	if f.JA3 != "" || f.JA4 != "" {
		if level, detail := s.store.FingerprintConcern(f.JA4, f.JA3); level != "" && level != "none" && detail != "" {
			fmt.Fprintf(&b, "TLS client-fingerprint assessment: %s (%s)\n", detail, level)
		}
	}

	// One scan for related findings, the campaign roll-ups that reference this
	// finding, the source host's risk roll-up, and destination fan-out.
	all := s.store.GetFindings()
	corr := map[int]bool{}
	for _, id := range f.Correlations {
		corr[id] = true
	}
	correlated := map[string]int{}
	sameSrc := map[string]int{}
	sameDst := map[string]int{}
	// Count distinct internal sources reaching this destination, including this
	// finding's own source, so the fan-out reflects all hosts hitting the dst.
	dstSources := map[string]bool{}
	if f.SrcIP != "" {
		dstSources[f.SrcIP] = true
	}
	var campaigns []string
	var srcHRS *model.Finding
	for i := range all {
		o := all[i]
		if model.IsRollupType(o.Type) {
			// A roll-up whose correlation set includes this finding is the
			// analyzer's own "this is part of a coordinated campaign" verdict.
			for _, id := range o.Correlations {
				if id == f.ID {
					campaigns = append(campaigns, fmt.Sprintf("%s (%s, groups %d findings)", o.Type, o.Severity, len(o.Correlations)))
					break
				}
			}
			if o.Type == model.TypeHostRiskScore && o.SrcIP == f.SrcIP {
				srcHRS = &all[i]
			}
			continue
		}
		if o.ID == f.ID {
			continue
		}
		if corr[o.ID] {
			correlated[o.Type]++
		}
		if f.SrcIP != "" && o.SrcIP == f.SrcIP && o.ID != f.ID {
			sameSrc[o.Type]++
		}
		if f.DstIP != "" && o.DstIP == f.DstIP {
			sameDst[o.Type]++
			if o.SrcIP != "" {
				dstSources[o.SrcIP] = true
			}
		}
	}

	if len(campaigns) > 0 {
		fmt.Fprintf(&b, "Analyzer campaign verdict: this finding was grouped into %s — the analyzer's own multi-signal correlation.\n", strings.Join(campaigns, "; "))
	}
	if srcHRS != nil {
		fmt.Fprintf(&b, "Source host overall risk roll-up: %s (Host Risk Score %d, aggregating all findings for this host).\n", srcHRS.Severity, srcHRS.Score)
	}

	if len(correlated) > 0 || len(sameSrc) > 0 || len(sameDst) > 0 {
		b.WriteString("Related activity on the same hosts:\n")
		if len(correlated) > 0 {
			fmt.Fprintf(&b, "- Same source→destination pair also tripped: %s\n", typeBreakdown(correlated))
		}
		if len(sameSrc) > 0 {
			fmt.Fprintf(&b, "- This source host has other findings: %s\n", typeBreakdown(sameSrc))
		}
		if len(sameDst) > 0 {
			n := len(dstSources)
			fmt.Fprintf(&b, "- This destination has findings from %d distinct internal source host(s): %s\n", n, typeBreakdown(sameDst))
		}
	}
	return b.String()
}

// typeBreakdown renders a type→count map as "Beacon×3, Lateral Movement",
// count-descending, capped so a noisy host doesn't blow up the prompt.
func typeBreakdown(m map[string]int) string {
	type tc struct {
		t string
		n int
	}
	items := make([]tc, 0, len(m))
	for t, n := range m {
		items = append(items, tc{t, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].t < items[j].t
	})
	const maxTypes = 8
	parts := make([]string, 0, maxTypes)
	for i, it := range items {
		if i >= maxTypes {
			parts = append(parts, fmt.Sprintf("+%d more types", len(items)-maxTypes))
			break
		}
		if it.n > 1 {
			parts = append(parts, fmt.Sprintf("%s×%d", it.t, it.n))
		} else {
			parts = append(parts, it.t)
		}
	}
	return strings.Join(parts, ", ")
}

// wellKnownPorts names the common services so the model can weigh "well-known
// service port" (benign-leaning) vs "uncommon/custom port" (suspicious-leaning).
// Deliberately small — Zeek DPD (f.Service) already labels protocols by content
// when it recognizes them; this fills the gap when DPD was silent and helps the
// model call out a custom high port like 15600 for what it is.
var wellKnownPorts = map[string]string{
	"22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "67": "DHCP",
	"68": "DHCP", "80": "HTTP", "88": "Kerberos", "110": "POP3", "123": "NTP",
	"135": "MSRPC", "137": "NetBIOS", "138": "NetBIOS", "139": "NetBIOS-SMB",
	"143": "IMAP", "161": "SNMP", "389": "LDAP", "443": "HTTPS", "445": "SMB",
	"465": "SMTPS", "514": "syslog", "587": "SMTP", "636": "LDAPS",
	"993": "IMAPS", "995": "POP3S", "1433": "MSSQL", "1521": "Oracle",
	"3306": "MySQL", "3389": "RDP", "5353": "mDNS", "5432": "PostgreSQL",
	"5985": "WinRM", "5986": "WinRM", "5900": "VNC", "6379": "Redis",
	"8080": "HTTP-alt", "8443": "HTTPS-alt", "27017": "MongoDB",
}

// portContext describes the destination port for the model. A DPD-recognized
// service is already surfaced separately, so this only adds value for the
// not-recognized case — naming a well-known port or flagging an uncommon one.
func portContext(port, service string) string {
	if port == "" {
		return ""
	}
	if name, ok := wellKnownPorts[port]; ok {
		return "port " + port + " (well-known: " + name + ")"
	}
	if service != "" {
		// DPD recognized the protocol; the Service line already carries it.
		return ""
	}
	return "port " + port + " (no well-known service — uncommon/custom port)"
}
