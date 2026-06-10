package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestDNSSubdomainDGA_ApexNotCountedOnMultiPartETLD is the Info-3 regression.
// The subdomain-diversity counter computed the subdomain as labels[:len-2],
// which assumes a 2-label eTLD. On a multi-part eTLD like co.uk a bare-apex
// query (bbc.co.uk, 3 labels) recorded "bbc" as a subdomain — an off-by-one
// that inflated the DGA diversity gate. The subdomain is now the query with the
// PSL apex stripped, so a bare apex contributes nothing. Here the threshold is
// 3 and exactly 3 real subdomains exist under bbc.co.uk plus one bare-apex
// query: the finding must fire reporting 3 unique subdomains, not 4.
func TestDNSSubdomainDGA_ApexNotCountedOnMultiPartETLD(t *testing.T) {
	cfg := config.Default()
	cfg.DNSUniqueSubdomainMin = 3

	dir := t.TempDir()
	path := filepath.Join(dir, "dns.log")
	var b strings.Builder
	queries := []string{"bbc.co.uk", "a.bbc.co.uk", "b.bbc.co.uk", "c.bbc.co.uk"}
	for i, q := range queries {
		fmt.Fprintf(&b, `{"ts":%d.0,"id.orig_h":"192.168.1.50","id.resp_h":"10.0.0.1","id.resp_p":53,"query":%q,"qtype_name":"A"}`+"\n", 1700000000+i, q)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write dns.log: %v", err)
	}

	a := New(cfg, "", nil, nil)
	a.feodoIPs = map[string]bool{}
	a.urlhausIPs = map[string]bool{}
	a.urlhausHosts = map[string]bool{}

	findings := a.Analyze([]string{path})

	f := findingOfType(findings, "DNS Subdomain DGA")
	if f == nil {
		t.Fatalf("DNS Subdomain DGA did not fire on 3 subdomains at threshold 3; got: %v", findingTypes(findings))
	}
	if f.DstIP != "bbc.co.uk" {
		t.Errorf("apex = %q, want bbc.co.uk", f.DstIP)
	}
	if !strings.Contains(f.Detail, "Unique subdomains: 3") {
		t.Errorf("detail = %q; want it to report 3 unique subdomains (the bare apex must not count as a 4th)", f.Detail)
	}
}
