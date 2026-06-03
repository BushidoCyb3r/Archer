package model

import "testing"

// TestIsKnownFindingType asserts the query language's type-validation
// vocabulary stays aligned with the finding types the rest of the model
// already names as constants, and that lookup is case-insensitive. The
// invariant: every type the analyzer emits through a model constant — and
// every beacon type IsBeaconType recognizes — must validate as known, or an
// exact `type:` query for it gets falsely rejected at the query bar.
func TestIsKnownFindingType(t *testing.T) {
	// Constant-backed types that must always be recognized. These drift the
	// most because they live as both a constant here and a literal at the
	// emit site; pinning them catches a rename that updates only one.
	known := []string{
		TypeHostRiskScore, TypeCorrelatedActivity,
		TypeTIHitIP, TypeTIHitDomain, TypeTIHitHash, TypeTIHitLegacy,
		TypeSuspiciousURL,
		"Beacon", "HTTP Beacon", "DNS Beacon", "Port-Hopping Beacon", // the IsBeaconType set
		"Strobe", "Lateral Movement", "Data Exfiltration", "Zeek Notice",
	}
	for _, ty := range known {
		if !IsKnownFindingType(ty) {
			t.Errorf("IsKnownFindingType(%q) = false; want true (drifted vocabulary)", ty)
		}
	}

	// IsBeaconType members are a subset of the known vocabulary by
	// construction — a beacon type the query layer can't validate would be a
	// silent gap. Assert the coupling directly.
	for _, ty := range []string{"Beacon", "HTTP Beacon", "DNS Beacon", "Port-Hopping Beacon"} {
		if IsBeaconType(ty) && !IsKnownFindingType(ty) {
			t.Errorf("%q is a beacon type but not a known finding type", ty)
		}
	}

	// Case-insensitive: type:beacon and type:"correlated activity" resolve.
	for _, ty := range []string{"beacon", "BEACON", "correlated activity", "dns tunneling"} {
		if !IsKnownFindingType(ty) {
			t.Errorf("IsKnownFindingType(%q) = false; want true (case-insensitive)", ty)
		}
	}

	// Misspellings and non-types must not validate.
	for _, ty := range []string{"Beaon", "Correlatd Activity", "Beaconing", "", "nonsense"} {
		if IsKnownFindingType(ty) {
			t.Errorf("IsKnownFindingType(%q) = true; want false", ty)
		}
	}
}
