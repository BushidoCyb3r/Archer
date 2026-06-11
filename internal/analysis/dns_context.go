package analysis

import "fmt"

// annotateDNSContext settles the ambiguity of a conn-level Beacon on port
// 53, which has three possible truths: cadence to a resolver the host
// legitimately uses, DNS C2 riding through that resolver (the DNS Beacon
// detector's finding), or raw-socket C2 squatting on 53 because it
// egresses everywhere. The dns.log resolver index built in analyzeDNS
// tells the first apart from the last: a pair that carried real queries is
// labelled with its resolver volume, a pair with no DNS semantics at all
// gets the evasion callout.
//
// Annotation-only, mirroring corroborateBeacons: Detail is outside the
// fingerprint, so merge identity and analyst state are unaffected, and no
// score or severity moves — whether the no-DNS-semantics case deserves a
// boost is a calibration-gated decision, not an enrichment side effect.
//
// A sensor with no dns.log records at all is skipped entirely: "no DNS
// queries observed" would be a false claim when the log simply isn't
// shipped, and the resolver story can't be told either.
func (a *Analyzer) annotateDNSContext() {
	if len(a.dnsSensorSeen) == 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.findings {
		f := &a.findings[i]
		if f.Type != "Beacon" || f.DstPort != "53" || !a.dnsSensorSeen[f.Sensor] {
			continue
		}
		if rs := a.dnsResolverIdx[resolverKey{f.Sensor, f.SrcIP, f.DstIP}]; rs != nil {
			apexCount := fmt.Sprint(len(rs.apexes))
			if rs.apexOverflow {
				apexCount += "+"
			}
			f.Detail += fmt.Sprintf(" | DNS context: active resolver for this source (%d queries, %s domains) — per-domain cadence is scored by DNS Beacon.", rs.queries, apexCount)
			continue
		}
		// DPD nuance: if Zeek's protocol detection labelled the flow dns
		// but dns.log has nothing for the pair, the honest read is a
		// coverage gap, not an evasion claim.
		dpdDNS := false
		for _, svc := range splitServices(f.Service) {
			if svc == "dns" {
				dpdDNS = true
				break
			}
		}
		if dpdDNS {
			f.Detail += " | DNS context: DPD recognized DNS on this pair but dns.log carries no queries for it — possible dns.log coverage gap."
		} else {
			f.Detail += " | DNS context: no DNS queries observed on this pair — port-53 transport without DNS semantics."
		}
	}
}
