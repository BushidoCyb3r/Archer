package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestAnnotateDNSContext pins the three-way disambiguation contract for a
// port-53 conn beacon: a pair the dns.log resolver index knows gets the
// active-resolver annotation, a pair it doesn't know gets the
// no-DNS-semantics evasion callout (softened to a coverage-gap note when
// DPD recognized dns), and a sensor with no dns.log coverage at all gets
// no claim either way. Non-53 beacons and other types stay untouched.
// Annotation-only: score and severity must not move.
func TestAnnotateDNSContext(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.dnsSensorSeen = map[string]bool{"s1": true}
	a.dnsResolverIdx = map[resolverKey]*resolverStat{
		{"s1", "10.0.0.1", "10.0.0.53"}: {queries: 412, apexes: map[string]bool{"example.com": true, "example.org": true}},
	}

	a.add(model.Finding{Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "10.0.0.53", DstPort: "53", Score: 70, Severity: model.SevHigh, Detail: "base"})
	a.add(model.Finding{Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.2", DstIP: "203.0.113.9", DstPort: "53", Score: 80, Severity: model.SevHigh, Detail: "base"})
	a.add(model.Finding{Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.3", DstIP: "203.0.113.10", DstPort: "53", Score: 80, Severity: model.SevHigh, Detail: "base", Service: "dns"})
	a.add(model.Finding{Type: "Beacon", Sensor: "s2", SrcIP: "10.0.0.4", DstIP: "203.0.113.11", DstPort: "53", Score: 80, Severity: model.SevHigh, Detail: "base"})
	a.add(model.Finding{Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.12", DstPort: "443", Score: 80, Severity: model.SevHigh, Detail: "base"})
	a.add(model.Finding{Type: "Data Exfiltration", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.13", DstPort: "53", Score: 60, Severity: model.SevMedium, Detail: "base"})

	a.annotateDNSContext()

	det := func(i int) string { return a.findings[i].Detail }
	if !strings.Contains(det(0), "active resolver for this source (412 queries, 2 domains)") {
		t.Errorf("resolver-pair beacon missing resolver annotation: %q", det(0))
	}
	if !strings.Contains(det(1), "no DNS queries observed on this pair — port-53 transport without DNS semantics") {
		t.Errorf("non-resolver beacon missing evasion callout: %q", det(1))
	}
	if !strings.Contains(det(2), "possible dns.log coverage gap") {
		t.Errorf("DPD-dns beacon should get the coverage-gap nuance, not the evasion claim: %q", det(2))
	}
	if det(3) != "base" {
		t.Errorf("sensor without dns.log coverage must get no annotation: %q", det(3))
	}
	if det(4) != "base" {
		t.Errorf("non-53 beacon must stay untouched: %q", det(4))
	}
	if det(5) != "base" {
		t.Errorf("non-Beacon type must stay untouched: %q", det(5))
	}
	if a.findings[1].Score != 80 || a.findings[1].Severity != model.SevHigh {
		t.Error("annotation pass must not move score or severity")
	}
}

// TestAnnotateDNSContext_NoDNSLogsAtAll: with no dns.log anywhere the pass
// is a no-op — "no DNS queries observed" would be a false claim when the
// log simply isn't shipped (the deployment gap, not the evasion).
func TestAnnotateDNSContext_NoDNSLogsAtAll(t *testing.T) {
	a := New(config.Default(), "", nil, nil)
	a.add(model.Finding{Type: "Beacon", Sensor: "s1", SrcIP: "10.0.0.1", DstIP: "203.0.113.9", DstPort: "53", Detail: "base"})
	a.annotateDNSContext()
	if a.findings[0].Detail != "base" {
		t.Errorf("annotation fired with zero dns.log coverage: %q", a.findings[0].Detail)
	}
}

// TestDNSResolverIndexAndResolvedIPs drives analyzeDNS over a synthetic
// dns.log and pins the two collection contracts feeding the annotations:
// the per-(sensor,src,resolver) index counts queries and distinct apexes,
// and a DNS Beacon's Detail carries the sorted, IP-only resolved set
// (CNAMEs filtered out, capped at dnsAnswerCap).
func TestDNSResolverIndexAndResolvedIPs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns.log")
	var b strings.Builder
	for i := 0; i < 40; i++ {
		// 300s heartbeat to one FQDN — the §2g DNS Beacon shape — with a
		// CNAME and two addresses in the answers vector.
		fmt.Fprintf(&b, `{"ts": %d.0, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.53", "id.resp_p": 53, "query": "gateway.update-svc.net", "rcode_name": "NOERROR", "answers": ["edge.update-svc.net", "198.51.100.7", "198.51.100.8"]}`+"\n", 1705320000+i*300)
	}
	// A second apex through the same resolver bumps the distinct-apex count.
	b.WriteString(`{"ts": 1705320010.0, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.53", "id.resp_p": 53, "query": "www.example.com", "rcode_name": "NOERROR"}` + "\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	a := New(config.Default(), "", nil, nil)
	a.analyzeDNS([]string{path})

	sensor := a.sensorOf(path)
	if !a.dnsSensorSeen[sensor] {
		t.Fatalf("dnsSensorSeen missing sensor %q", sensor)
	}
	rs := a.dnsResolverIdx[resolverKey{sensor, "10.0.0.1", "10.0.0.53"}]
	if rs == nil {
		t.Fatal("resolver index missing the (src, resolver) pair")
	}
	if rs.queries != 41 || len(rs.apexes) != 2 {
		t.Errorf("resolver stats = %d queries / %d apexes, want 41 / 2", rs.queries, len(rs.apexes))
	}

	beacon := findingOfType(a.findings, "DNS Beacon")
	if beacon == nil {
		t.Fatalf("DNS Beacon did not fire on the heartbeat; types: %v", findingTypes(a.findings))
	}
	if !strings.Contains(beacon.Detail, "Resolved: 198.51.100.7, 198.51.100.8") {
		t.Errorf("DNS Beacon detail missing sorted IP-only resolved set: %q", beacon.Detail)
	}
	if strings.Contains(beacon.Detail, "edge.update-svc.net") {
		t.Errorf("CNAME answer leaked into the resolved set: %q", beacon.Detail)
	}
}
