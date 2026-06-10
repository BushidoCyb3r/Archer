package analysis

import (
	"reflect"
	"testing"
)

func TestSplitServices(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty is no DPD result", "", nil},
		{"whitespace only", "   ", nil},
		{"single label", "ssh", []string{"ssh"}},
		{"uppercased is normalized", "SSL", []string{"ssl"}},
		{"multi label", "smb,gssapi,ntlm", []string{"smb", "gssapi", "ntlm"}},
		{"trims segment whitespace", " ssl , http ", []string{"ssl", "http"}},
		{"drops empty segments", "ssl,,http,", []string{"ssl", "http"}},
		{"dedupes repeats", "http,HTTP,http", []string{"http"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitServices(c.raw)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("splitServices(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

func TestServiceCategoryOf(t *testing.T) {
	cases := []struct {
		label string
		want  serviceCategory
	}{
		{"ssh", svcRemoting},
		{"rdp", svcRemoting},
		{"rfb", svcRemoting},
		{"telnet", svcRemoting},
		{"http", svcWeb},
		{"ssl", svcWeb},
		{"smtp", svcMail},
		{"ftp", svcFileTransfer},
		{"smb", svcFileTransfer},
		{"mysql", svcDatabase},
		{"dns", svcInfra},
		{"kerberos", svcInfra},
		{"SSH", svcRemoting}, // case-insensitive
		{" ssl ", svcWeb},    // trims
		{"quic", svcOther},   // DPD-recognized, uncategorized here
		{"", svcOther},       // empty label
	}
	for _, c := range cases {
		if got := serviceCategoryOf(c.label); got != c.want {
			t.Errorf("serviceCategoryOf(%q) = %q, want %q", c.label, got, c.want)
		}
	}
}

func TestServiceCategories(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []serviceCategory
	}{
		{"empty is nil", "", nil},
		{"single", "ssh", []serviceCategory{svcRemoting}},
		{"distinct categories preserve order", "smb,gssapi,ntlm", []serviceCategory{svcFileTransfer, svcInfra}},
		{"same-category labels collapse", "ssl,http", []serviceCategory{svcWeb}},
		{"unrecognized label maps to other", "ssl,quic", []serviceCategory{svcWeb, svcOther}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := serviceCategories(c.raw)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("serviceCategories(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}
