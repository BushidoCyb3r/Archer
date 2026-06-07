package model

import "testing"

// TestEveryFindingTypeMappedOrExempt is the drift guard: every finding type the
// analyzer can emit must be either mapped to ≥1 ATT&CK technique or explicitly
// listed as exempt. A new finding type added to knownFindingTypes without a
// conscious ATT&CK decision fails here instead of silently rendering no tag.
func TestEveryFindingTypeMappedOrExempt(t *testing.T) {
	for ft := range knownFindingTypes {
		_, mapped := attackByType[ft]
		exempt := attackExemptTypes[ft]
		switch {
		case mapped && exempt:
			t.Errorf("finding type %q is both mapped and exempt — pick one", ft)
		case !mapped && !exempt:
			t.Errorf("finding type %q has no ATT&CK mapping and is not exempt — "+
				"add it to attackByType or attackExemptTypes", ft)
		}
	}
	// Inverse drift: no mapping/exempt entry for a type the analyzer can't emit.
	for ft := range attackByType {
		if !knownFindingTypes[ft] {
			t.Errorf("attackByType has %q which is not a known finding type", ft)
		}
	}
	for ft := range attackExemptTypes {
		if !knownFindingTypes[ft] {
			t.Errorf("attackExemptTypes has %q which is not a known finding type", ft)
		}
	}
}

func TestAttackTechniqueURL(t *testing.T) {
	cases := map[string]string{
		"T1071":     "https://attack.mitre.org/techniques/T1071/",
		"T1071.004": "https://attack.mitre.org/techniques/T1071/004/",
		"T1090.004": "https://attack.mitre.org/techniques/T1090/004/",
	}
	for id, want := range cases {
		got := AttackTechnique{ID: id}.URL()
		if got != want {
			t.Errorf("URL(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestAttackTechniquesFor(t *testing.T) {
	if got := AttackTechniquesFor("Beacon"); len(got) != 1 || got[0].ID != "T1071" {
		t.Errorf("Beacon → %+v, want [T1071]", got)
	}
	if got := AttackTechniquesFor("DNS Beacon"); len(got) != 1 || got[0].ID != "T1071.004" {
		t.Errorf("DNS Beacon → %+v, want [T1071.004]", got)
	}
	// Exempt type returns nothing.
	if got := AttackTechniquesFor(TypeHostRiskScore); got != nil {
		t.Errorf("Host Risk Score → %+v, want nil", got)
	}
	// Unknown type returns nothing.
	if got := AttackTechniquesFor("Not A Real Type"); got != nil {
		t.Errorf("unknown type → %+v, want nil", got)
	}
}
