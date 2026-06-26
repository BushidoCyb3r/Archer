package server

import (
	"context"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/llm"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// The structural-facts enrichment must give the model the discriminators the
// redactor strips — a broadcast destination, a custom port — WITHOUT leaking
// the real internal addresses. This is what makes the difference between a
// useless "could be C2 or could be benign" briefing and a correct downgrade on
// internal broadcast traffic.
func TestBuildEnrichmentEvidence_StructuralFactsSurviveRedaction(t *testing.T) {
	f := model.Finding{
		Type:    "Beacon",
		SrcIP:   "172.16.10.186",
		DstIP:   "172.16.10.255", // subnet broadcast — the benign tell
		DstPort: "15600",         // custom port — no well-known service
	}
	r := llm.NewRedactor(nil, nil)
	evidence := buildEnrichmentEvidence(f, r)

	// The structural classification reaches the model...
	for _, want := range []string{"broadcast", "uncommon/custom port"} {
		if !strings.Contains(evidence, want) {
			t.Errorf("evidence missing structural signal %q:\n%s", want, evidence)
		}
	}
	// ...but after redaction, neither raw internal address leaks.
	redacted, _ := r.Redact(evidence)
	for _, ip := range []string{"172.16.10.186", "172.16.10.255"} {
		if strings.Contains(redacted, ip) {
			t.Errorf("internal address %s leaked despite redaction:\n%s", ip, redacted)
		}
	}
	// The broadcast classification line carries no address, so it survives
	// redaction intact.
	if !strings.Contains(redacted, "broadcast") {
		t.Errorf("broadcast tell was lost in redaction:\n%s", redacted)
	}
}

// The richer evidence must carry the detector's own meaning, the structured
// beacon metrics, and what else fired on the same hosts — the context that
// turns a hedge into a verdict.
func TestEnrichmentEvidence_GroundingAndRelatedContext(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{Type: "Beacon", SrcIP: "10.5.5.5", DstIP: "8.8.8.8", DstPort: "443",
			Severity: model.SevHigh, Score: 80, SampleSize: 200,
			MeanInterval: 60, MedianInterval: 60, Jitter: 0.1,
			TSScore: 1, DSScore: 0.5, HistScore: 0.8, DurScore: 0.9},
		{Type: "Lateral Movement", SrcIP: "10.5.5.5", DstIP: "10.5.5.9", DstPort: "445",
			Severity: model.SevHigh, Score: 78},
	})

	var beacon model.Finding
	for _, f := range s.store.GetFindings() {
		if f.Type == "Beacon" {
			beacon = f
		}
	}

	r := llm.NewRedactor(nil, nil)
	evidence := buildEnrichmentEvidence(beacon, r) + s.decisionContext(beacon)

	for _, want := range []string{
		"What this detector flags",     // detector self-explanation
		"Known benign causes",          // false-positive grounding
		"How this type is scored",      // scoring rationale
		"Beacon timing: mean interval", // structured metrics
		"Beacon sub-scores",            //
		"Destination reputation:",      // allowlist/known-good check
		"Related activity on the same hosts:",
		"Lateral Movement", // the same-source sibling
	} {
		if !strings.Contains(evidence, want) {
			t.Errorf("enriched evidence missing %q:\n%s", want, evidence)
		}
	}
}

// The decision context must surface the signals an analyst leans on hardest:
// a known-good allowlist match, the source host's overall risk roll-up, and how
// many internal hosts fan out to a destination.
func TestDecisionContext_ReputationRiskAndFanout(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetAllowlist([]string{"8.8.8.8"})
	s.store.SetFindings([]model.Finding{
		{Type: "Beacon", SrcIP: "10.1.1.1", DstIP: "8.8.8.8", DstPort: "443", Severity: model.SevHigh, Score: 80},
		{Type: "Beacon", SrcIP: "10.1.1.2", DstIP: "8.8.8.8", DstPort: "443", Severity: model.SevHigh, Score: 80},
		// Host Risk Score roll-up for the first source host.
		{Type: model.TypeHostRiskScore, SrcIP: "10.1.1.1", Severity: model.SevCritical, Score: 92},
	})

	var beacon model.Finding
	for _, f := range s.store.GetFindings() {
		if f.Type == "Beacon" && f.SrcIP == "10.1.1.1" {
			beacon = f
		}
	}
	ctx := s.decisionContext(beacon)

	for _, want := range []string{
		"IS on the operator allowlist",                     // known-good destination
		"Source host overall risk roll-up",                 // HRS corroboration
		"Host Risk Score 92",                               //
		"findings from 2 distinct internal source host(s)", // fan-out incl. self
	} {
		if !strings.Contains(ctx, want) {
			t.Errorf("decision context missing %q:\n%s", want, ctx)
		}
	}
}

// A well-known service port is named so the model can lean benign on it.
func TestPortContext(t *testing.T) {
	cases := map[string]struct{ port, service, want string }{
		"well-known no DPD": {"123", "", "NTP"},
		"custom no DPD":     {"15600", "", "uncommon/custom port"},
		"DPD recognized":    {"40000", "ssl", ""}, // Service line already covers it
		"empty":             {"", "", ""},
	}
	for name, c := range cases {
		if got := portContext(c.port, c.service); !strings.Contains(got, c.want) || (c.want == "" && got != "") {
			t.Errorf("%s: portContext(%q,%q) = %q, want contains %q", name, c.port, c.service, got, c.want)
		}
	}
}

// stubLLM is a Provider that records the evidence it was handed and returns a
// fixed briefing — so the test can prove both that internal addresses were
// redacted before send and that the redaction tokens were expanded back.
type stubLLM struct {
	gotEvidence string
	reply       string
}

func (p *stubLLM) Name() string { return "stub" }
func (p *stubLLM) Summarize(_ context.Context, _, user string) (string, error) {
	p.gotEvidence = user
	return p.reply, nil
}

// TestEnrichment_IsAnnotationOnly is the system-breaking-surface guard for the
// AI-enrichment feature. The invariant: enriching a finding adds exactly one
// note and changes NOTHING else — Score, Severity, and Status are untouched.
// This is the locked contract that keeps non-deterministic model output clear
// of the detection-semantics surface; if a future change ever let enrichment
// influence a score, this fails.
//
// It also pins the redaction boundary end-to-end through the server path: the
// internal source address must not appear in the evidence that left the box,
// and the HOST_n token the model echoes back must expand to the real address
// in the saved note.
func TestEnrichment_IsAnnotationOnly(t *testing.T) {
	s := newAuditTestServer(t)
	st := s.store

	const internalSrc = "10.7.7.7"
	const externalDst = "203.0.113.40" // TEST-NET-3: external, must NOT be redacted
	st.SetFindings([]model.Finding{{
		Type:     "Beacon",
		Severity: model.SevHigh,
		Score:    80,
		Status:   model.StatusOpen,
		SrcIP:    internalSrc,
		DstIP:    externalDst,
		DstPort:  "443",
		Detail:   "regular 60s check-ins",
	}})

	// SetFindings assigns IDs; read the assigned one back rather than guess.
	all := st.GetFindings()
	if len(all) != 1 {
		t.Fatalf("expected 1 seeded finding, got %d", len(all))
	}
	id := all[0].ID
	before, ok := st.GetFinding(id)
	if !ok {
		t.Fatal("seed finding missing")
	}

	stub := &stubLLM{reply: "HOST_1 is beaconing to the external host; investigate."}
	// Called synchronously (not via the go in handleEnrich) so the note is
	// written before we assert.
	s.runLLMEnrichment(stub, before, nil, nil, "")

	after, ok := st.GetFinding(id)
	if !ok {
		t.Fatal("finding vanished after enrichment")
	}

	// The invariant: detection fields are identical.
	if after.Score != before.Score {
		t.Errorf("enrichment changed Score: %d -> %d", before.Score, after.Score)
	}
	if after.Severity != before.Severity {
		t.Errorf("enrichment changed Severity: %s -> %s", before.Severity, after.Severity)
	}
	if after.Status != before.Status {
		t.Errorf("enrichment changed Status: %q -> %q", before.Status, after.Status)
	}
	if after.Type != before.Type || after.Detail != before.Detail {
		t.Errorf("enrichment mutated detector fields (type/detail)")
	}

	// Exactly one note added, authored by the system identity.
	if len(after.Notes) != len(before.Notes)+1 {
		t.Fatalf("expected exactly one new note, before=%d after=%d", len(before.Notes), len(after.Notes))
	}
	note := after.Notes[len(after.Notes)-1]
	if note.Author != "AI Triage" {
		t.Errorf("note author = %q, want \"AI Triage\"", note.Author)
	}

	// Redaction boundary: the internal source must not have left the box.
	if strings.Contains(stub.gotEvidence, internalSrc) {
		t.Errorf("internal address %s leaked into the evidence sent to the model:\n%s", internalSrc, stub.gotEvidence)
	}
	if !strings.Contains(stub.gotEvidence, "HOST_1") {
		t.Errorf("internal address was not tokenized in the outbound evidence:\n%s", stub.gotEvidence)
	}
	// External indicator must survive (it's the point of the briefing).
	if !strings.Contains(stub.gotEvidence, externalDst) {
		t.Errorf("external indicator %s was wrongly redacted", externalDst)
	}
	// Expansion: the saved note shows the real internal address, not the token.
	if strings.Contains(note.Text, "HOST_1") {
		t.Errorf("redaction token was not expanded in the saved note: %q", note.Text)
	}
	if !strings.Contains(note.Text, internalSrc) {
		t.Errorf("expanded note should reference the real internal address %s: %q", internalSrc, note.Text)
	}
}
