package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestCheckTI_HTTPHostCaseInsensitive is the LG-2 regression: a mixed-case
// HTTP Host header for a known-bad domain must still produce a TI Hit
// (Domain). The host reaches checkTI only via http.log (direct-IP
// resolution, no dns.log entry), so the DNS scan's normalization can't save
// it — the HTTP scan must lowercase to match the lowercased URLhaus/feed
// keys. Before the fix, "EVIL.com" never matched urlhausHosts["evil.com"]
// and a confirmed malware-distribution contact produced no finding at all.
func TestCheckTI_HTTPHostCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http.log")
	// Mixed-case Host with a :port suffix, dst is a bare IP (direct-IP
	// resolution → no dns.log). Both the case and the port must be normalized.
	rec := `{"ts":1700000000.0,"id.orig_h":"192.168.1.50","id.resp_h":"203.0.113.9","id.resp_p":443,"host":"EVIL.com:443","uri":"/payload"}` + "\n"
	if err := os.WriteFile(path, []byte(rec), 0o644); err != nil {
		t.Fatalf("write http.log: %v", err)
	}

	a := New(config.Default(), "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{"evil.com": true}

	a.checkTI([]string{path})

	f := findingOfType(a.findings, model.TypeTIHitDomain)
	if f == nil {
		t.Fatalf("expected a TI Hit (Domain) for evil.com from a mixed-case Host header; got types: %v", findingTypes(a.findings))
	}
	if f.DstIP != "evil.com" {
		t.Errorf("DstIP = %q, want evil.com (normalized)", f.DstIP)
	}
	if f.SrcIP != "192.168.1.50" {
		t.Errorf("SrcIP = %q, want 192.168.1.50 — host attribution lost", f.SrcIP)
	}
}
