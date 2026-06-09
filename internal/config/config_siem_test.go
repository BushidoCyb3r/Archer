package config

import "testing"

func TestDefault_SIEM(t *testing.T) {
	d := Default()
	if d.SIEMEnabled {
		t.Error("SIEMEnabled should default false")
	}
	if d.SIEMHost != "" {
		t.Errorf("SIEMHost should default empty, got %q", d.SIEMHost)
	}
	if d.SIEMPort != 9003 {
		t.Errorf("SIEMPort should default 9003, got %d", d.SIEMPort)
	}
}
