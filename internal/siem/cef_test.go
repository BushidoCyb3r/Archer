package siem

import (
	"strconv"
	"strings"
	"testing"
	"time"

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
	wantRT := time.Date(2026, 6, 8, 4, 11, 0, 0, time.UTC).UnixMilli()
	mustContain(t, line, "rt="+strconv.FormatInt(wantRT, 10))
	mustContain(t, line, "cs1Label=ArcherScore cs1=98")
	mustContain(t, line, "cs2Label=ArcherSensor cs2=node1")
	mustContain(t, line, `cs3Label=ArcherUrl cs3=https://archer/?finding\=42`)
	mustContain(t, line, "cs4Label=ArcherAnalyst cs4=alice")
	mustContain(t, line, "cs5Label=ja3 cs5=abc123")
	mustContain(t, line, "cs6Label=ja4 cs6=t13d")
	mustContain(t, line, "msg=Connections: 200 | Mean interval: 7214.7s")
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

func TestFormatCEF_BadTimestampOmitsRT(t *testing.T) {
	f := model.Finding{ID: 9, Type: "X", Score: 50, Timestamp: "not-a-time", Analyst: "x"}
	if strings.Contains(FormatCEF(f, "v", "u"), "rt=") {
		t.Error("unparseable timestamp must omit rt")
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
