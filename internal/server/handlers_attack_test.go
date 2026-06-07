package server

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

func TestAttackCoverage(t *testing.T) {
	findings := []model.Finding{
		{Type: "Beacon"},              // T1071
		{Type: "Beacon"},              // T1071
		{Type: "DNS Beacon"},          // T1071.004
		{Type: "Port-Hopping Beacon"}, // T1071 + T1571
		{Type: "Host Risk Score"},     // exempt → unmapped
		{Type: "TI Hit (IP)"},         // exempt → unmapped
	}
	res := attackCoverage(findings)

	if res.Total != 6 {
		t.Errorf("Total = %d, want 6", res.Total)
	}

	counts := map[string]int{}
	for _, tk := range res.Techniques {
		counts[tk.ID] = tk.Count
	}
	// Beacon ×2 + Port-Hopping ×1 all carry T1071.
	if counts["T1071"] != 3 {
		t.Errorf("T1071 count = %d, want 3", counts["T1071"])
	}
	if counts["T1071.004"] != 1 {
		t.Errorf("T1071.004 count = %d, want 1", counts["T1071.004"])
	}
	if counts["T1571"] != 1 {
		t.Errorf("T1571 count = %d, want 1", counts["T1571"])
	}

	// Sorted by count desc: T1071 (3) must lead.
	if len(res.Techniques) == 0 || res.Techniques[0].ID != "T1071" {
		t.Errorf("expected T1071 first, got %+v", res.Techniques)
	}
	// URL is populated from the technique.
	if res.Techniques[0].URL != "https://attack.mitre.org/techniques/T1071/" {
		t.Errorf("T1071 URL = %q", res.Techniques[0].URL)
	}

	// Two distinct exempt types land in unmapped.
	unmapped := map[string]int{}
	for _, u := range res.Unmapped {
		unmapped[u.Type] = u.Count
	}
	if unmapped["Host Risk Score"] != 1 || unmapped["TI Hit (IP)"] != 1 {
		t.Errorf("unmapped = %+v, want Host Risk Score=1, TI Hit (IP)=1", res.Unmapped)
	}
}
