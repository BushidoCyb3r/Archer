package server

import (
	"bytes"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

func TestBuildCampaignsRollup_FiltersByDistinctSources(t *testing.T) {
	findings := []model.Finding{
		// 198.51.100.10:443 from two distinct sources → should land
		{Type: "Beaconing", SrcIP: "192.168.1.5", DstIP: "198.51.100.10", DstPort: "443", Score: 80},
		{Type: "Long Connection", SrcIP: "192.168.1.7", DstIP: "198.51.100.10", DstPort: "443", Score: 60},
		// 203.0.113.5:80 from one source → filtered out
		{Type: "Beaconing", SrcIP: "192.168.1.5", DstIP: "203.0.113.5", DstPort: "80", Score: 70},
		// (network) is excluded
		{Type: "Lateral Movement", SrcIP: "192.168.1.5", DstIP: "(network)", DstPort: "445", Score: 60},
	}
	got := buildCampaignsRollup(findings)
	if len(got) != 1 {
		t.Fatalf("want 1 campaign (filtered to ≥2 sources, network excluded), got %d: %+v", len(got), got)
	}
	r := got[0]
	if r.Dst != "198.51.100.10" || r.Port != "443" {
		t.Errorf("wrong dst:port: %s:%s", r.Dst, r.Port)
	}
	if r.HostCount != 2 {
		t.Errorf("HostCount = %d, want 2", r.HostCount)
	}
	if r.MaxScore != 80 {
		t.Errorf("MaxScore = %d, want 80", r.MaxScore)
	}
	if len(r.Types) != 2 {
		t.Errorf("Types = %v, want 2 entries", r.Types)
	}
}

func TestBuildHostsRollup_OrgIPOnly(t *testing.T) {
	findings := []model.Finding{
		// Org private IP — should land
		{Type: "Beaconing", SrcIP: "192.168.1.5", DstIP: "1.2.3.4", Score: 80, Severity: model.SevCritical},
		// Public src IP without an admin CIDR — excluded
		{Type: "Beaconing", SrcIP: "8.8.8.8", DstIP: "1.2.3.4", Score: 50, Severity: model.SevMedium},
		// Admin-CIDR IP — should land
		{Type: "Lateral Movement", SrcIP: "100.64.5.5", DstIP: "10.0.0.5", Score: 60, Severity: model.SevHigh},
	}
	got := buildHostsRollup(findings, []string{"100.64.0.0/10"})
	if len(got) != 2 {
		t.Fatalf("want 2 hosts (8.8.8.8 excluded, two org IPs counted), got %d: %+v", len(got), got)
	}
	// Default sort is risk score desc; 192.168.1.5 has score 80
	if got[0].IP != "192.168.1.5" || got[0].Score != 80 || got[0].TopSev != "CRITICAL" {
		t.Errorf("first host = %+v, want IP=192.168.1.5 Score=80 TopSev=CRITICAL", got[0])
	}
	if got[1].IP != "100.64.5.5" || got[1].TopSev != "HIGH" {
		t.Errorf("second host = %+v, want IP=100.64.5.5 TopSev=HIGH", got[1])
	}
}

func TestWriteFindingsSheet_RoundTripsViaExcelize(t *testing.T) {
	xf := excelize.NewFile()
	defer xf.Close()
	findings := []model.Finding{
		{Score: 95, Severity: model.SevCritical, Type: "Beaconing",
			SrcIP: "192.168.1.5", DstIP: "1.2.3.4", DstPort: "443"},
	}
	writeFindingsSheet(xf, "Findings", findings)
	val, err := xf.GetCellValue("Findings", "C2")
	if err != nil {
		t.Fatalf("GetCellValue: %v", err)
	}
	if val != "Beaconing" {
		t.Errorf("C2 = %q, want %q (type column)", val, "Beaconing")
	}

	// Workbook should write to bytes without error
	var buf bytes.Buffer
	if err := xf.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if buf.Len() < 1024 {
		t.Errorf("xlsx output suspiciously small: %d bytes", buf.Len())
	}
}
