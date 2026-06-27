package siem

import (
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("missing %q in:\n%s", sub, s)
	}
}

func TestFormatCEF_Beacon(t *testing.T) {
	f := model.Finding{
		ID: 42, Type: "HTTP Beacon", Score: 98,
		SrcIP: "10.0.0.5", DstIP: "8.8.8.8", DstPort: "443",
		Service: "ssl", Sensor: "node1", Analyst: "alice",
		JA3: "abc123", JA4: "t13d",
		Hostname: "cdn.example.com", URI: "/submit.php",
		IOCMatch: true, IOCSource: "Feed: URLhaus",
		Timestamp: "2026-06-08 04:11:00",
		Detail:    "Connections: 200 | Mean interval: 7214.7s",
	}
	line := FormatCEF(f, "v0.63.0", "https://archer/?finding=42")

	// Bare CEF: the line must begin at "CEF:" (no syslog header) so the
	// Elastic decode_cef input parses it directly, like UniFi's bare CEF.
	if !strings.HasPrefix(line, "CEF:0|Archer|Archer|") {
		t.Errorf("line must start with bare CEF header, got:\n%s", line)
	}
	mustContain(t, line, "CEF:0|Archer|Archer|v0.63.0|HTTP Beacon|HTTP Beacon|10|")
	mustContain(t, line, "externalId=42")
	mustContain(t, line, "src=10.0.0.5")
	mustContain(t, line, "dst=8.8.8.8")
	mustContain(t, line, "dpt=443")
	mustContain(t, line, "app=ssl")
	// rt is intentionally NOT emitted — Security Onion's decode_cef rejects an
	// epoch-millis rt and drops the whole event; @timestamp falls back to
	// ingest time. Guard against a regression that re-adds it.
	if strings.Contains(line, "rt=") {
		t.Errorf("rt must not be emitted (SO decode_cef rejects epoch-millis rt):\n%s", line)
	}
	mustContain(t, line, "cs1Label=ArcherScore cs1=98")
	mustContain(t, line, "cs2Label=ArcherSensor cs2=node1")
	mustContain(t, line, `cs3Label=ArcherUrl cs3=https://archer/?finding\=42`)
	mustContain(t, line, "cs4Label=ArcherAnalyst cs4=alice")
	mustContain(t, line, "cs5Label=ja3 cs5=abc123")
	mustContain(t, line, "cs6Label=ja4 cs6=t13d")
	mustContain(t, line, "msg=Connections: 200 | Mean interval: 7214.7s")
	// Enrichment fields (standard CEF keys).
	mustContain(t, line, "dhost=cdn.example.com")
	mustContain(t, line, "request=/submit.php")
	mustContain(t, line, "reason=Feed: URLhaus")
	mustContain(t, line, "flexString1Label=ATT&CK flexString1=T1071.001") // HTTP Beacon → T1071.001
	mustContain(t, line, "flexString2Label=ArcherEventTime flexString2=2026-06-08 04:11:00")
}

func TestFormatCEF_ReasonFromIOC(t *testing.T) {
	withSrc := FormatCEF(model.Finding{ID: 1, Type: "Beacon", Score: 90, IOCMatch: true, IOCSource: "Operator IOC list", Analyst: "x"}, "v", "u")
	mustContain(t, withSrc, "reason=Operator IOC list")

	noSrc := FormatCEF(model.Finding{ID: 1, Type: "Beacon", Score: 90, IOCMatch: true, Analyst: "x"}, "v", "u")
	mustContain(t, noSrc, "reason=IOC/TI match")

	none := FormatCEF(model.Finding{ID: 1, Type: "Beacon", Score: 90, Analyst: "x"}, "v", "u")
	if strings.Contains(none, "reason=") {
		t.Errorf("reason must be omitted when no IOC match:\n%s", none)
	}
}

func TestFormatCEF_SeverityScaling(t *testing.T) {
	cases := map[int]string{0: "|0|", 35: "|4|", 94: "|9|", 95: "|10|", 98: "|10|"}
	for score, want := range cases {
		line := FormatCEF(model.Finding{ID: 1, Type: "X", Score: score}, "v", "u")
		mustContain(t, line, want)
	}
}

func TestFormatCEF_Escaping(t *testing.T) {
	f := model.Finding{ID: 7, Type: "A|B", Score: 50, Detail: "k=v\nline2", Analyst: "x"}
	line := FormatCEF(f, "v", "u")
	mustContain(t, line, `A\|B`)            // pipe escaped in header
	mustContain(t, line, `msg=k\=v\nline2`) // = and newline escaped in value
}

func TestFormatCEF_OmitsEmptyAndNonNumericPort(t *testing.T) {
	f := model.Finding{ID: 9, Type: "X", Score: 50, DstPort: "n/a", Analyst: "x"}
	line := FormatCEF(f, "v", "u")
	if strings.Contains(line, "dpt=") {
		t.Errorf("non-numeric port should be omitted:\n%s", line)
	}
	if strings.Contains(line, "src=") || strings.Contains(line, "cs5Label") {
		t.Errorf("empty fields should be omitted:\n%s", line)
	}
}

func TestTruncateDetail_ClauseBoundaryNoEllipsis(t *testing.T) {
	s := "Connections: 200 | Mean interval: 7214.7s | Prevalence: 1/50 (<2%) — rare dst, score boosted | co-traffic to dst: 22x8"
	got := truncateDetail(s, 60)
	if strings.Contains(got, "…") || strings.HasSuffix(got, "Prevalence:") {
		t.Errorf("bad trim: %q", got)
	}
	if got != "Connections: 200 | Mean interval: 7214.7s" {
		t.Errorf("want clause-bounded trim, got %q", got)
	}
}

func TestFormatCEF_EscapesEqualsInNonMsgField(t *testing.T) {
	f := model.Finding{ID: 1, Type: "X", Score: 50, Sensor: "a=b", Analyst: "x"}
	mustContain(t, FormatCEF(f, "v", "u"), `cs2Label=ArcherSensor cs2=a\=b`)
}

func TestFormatCEFEnriched_TriagePrependsMsg(t *testing.T) {
	f := model.Finding{
		ID: 10, Type: "DNS Beacon", Score: 95,
		SrcIP: "10.0.0.5", DstIP: "1.2.3.4", DstPort: "53",
		Detail:  "Connections: 144 | Mean interval: 600s",
		Analyst: "alice",
	}
	triage := &TriageData{Verdict: "LIKELY MALICIOUS", Confidence: "high", Provider: "anthropic"}
	line := FormatCEFEnriched(f, triage, "v0.77.0", "https://archer/?finding=10")

	mustContain(t, line, "msg=AI: LIKELY MALICIOUS (high) | Connections: 144 | Mean interval: 600s")
	// cs slots and all other fields must be unchanged from non-enriched path.
	mustContain(t, line, "cs1Label=ArcherScore cs1=95")
	mustContain(t, line, "cs4Label=ArcherAnalyst cs4=alice")
}

func TestFormatCEFEnriched_NoTriageMatchesFormatCEF(t *testing.T) {
	f := model.Finding{ID: 5, Type: "Beacon", Score: 80, SrcIP: "10.0.0.1", Analyst: "x"}
	want := FormatCEF(f, "v0.77.0", "u")
	got := FormatCEFEnriched(f, nil, "v0.77.0", "u")
	if want != got {
		t.Errorf("FormatCEFEnriched(nil) must equal FormatCEF\nwant: %s\n got: %s", want, got)
	}
}

func TestFormatAITriageCEF(t *testing.T) {
	f := model.Finding{
		ID: 42, Type: "Multi-Stage Beacon", Score: 99,
		SrcIP: "10.10.40.84", DstIP: "172.233.181.138", DstPort: "443",
		Timestamp: "2026-06-26 21:47:55",
	}
	triage := TriageData{
		Verdict:    "LIKELY MALICIOUS",
		Confidence: "high",
		Reason:     "Multi-stage C2 indicators to unlisted external IP, 9 internal hosts",
		Provider:   "anthropic",
	}
	line := FormatAITriageCEF(f, triage, "v0.77.0", "https://archer/?finding=42")

	// Device event class ID must be "ai_triage" so SIEM rules can target it.
	mustContain(t, line, "CEF:0|Archer|Archer|v0.77.0|ai_triage|AI Triage #42: LIKELY MALICIOUS|10|")
	mustContain(t, line, "externalId=42")
	mustContain(t, line, "src=10.10.40.84")
	mustContain(t, line, "dst=172.233.181.138")
	mustContain(t, line, "dpt=443")
	mustContain(t, line, "msg=LIKELY MALICIOUS (high) — Multi-stage C2 indicators")
	mustContain(t, line, "cs1Label=ArcherScore cs1=99")
	mustContain(t, line, "cs2Label=AIVerdict cs2=LIKELY MALICIOUS")
	mustContain(t, line, "cs3Label=AIConfidence cs3=high")
	mustContain(t, line, `cs4Label=ArcherUrl cs4=https://archer/?finding\=42`)
	mustContain(t, line, "cs5Label=AIProvider cs5=anthropic")
	mustContain(t, line, "cs6Label=FindingType cs6=Multi-Stage Beacon")
	mustContain(t, line, "flexString2Label=ArcherEventTime flexString2=2026-06-26 21:47:55")
	// rt must never appear — same constraint as the escalation event.
	if strings.Contains(line, "rt=") {
		t.Errorf("rt must not be emitted:\n%s", line)
	}
}

func TestFormatAITriageCEF_EmptyConfidenceOmitted(t *testing.T) {
	f := model.Finding{ID: 1, Type: "Beacon", Score: 80, SrcIP: "10.0.0.1"}
	triage := TriageData{Verdict: "INVESTIGATE", Reason: "ambiguous traffic"}
	line := FormatAITriageCEF(f, triage, "v", "u")
	mustContain(t, line, "msg=INVESTIGATE — ambiguous traffic")
	mustContain(t, line, "cs2Label=AIVerdict cs2=INVESTIGATE")
	if strings.Contains(line, "cs3Label=AIConfidence") {
		t.Errorf("empty confidence must be omitted:\n%s", line)
	}
}
