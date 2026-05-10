package analysis

import (
	"testing"
	"time"
)

// TestParseZeekCertTime_BothFormats covers the regression that prompted
// NEW-20: real Zeek default JSON output emits the time type as a
// Unix-epoch float, not RFC3339. The pre-fix analyzer only handled
// RFC3339, so on any production Zeek capture the validity-window check
// silently never fired. The bug was invisible because the golden
// fixture happened to use RFC3339 — same fixture-vs-reality drift the
// audit (NEW-24) called out as a class failure mode.
func TestParseZeekCertTime_BothFormats(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Time
		ok   bool
	}{
		{
			name: "Zeek default float (production reality)",
			in:   "1704067200.0",
			want: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			ok:   true,
		},
		{
			name: "Zeek default float without trailing zero",
			in:   "1704067200",
			want: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			ok:   true,
		},
		{
			name: "Zeek default float with sub-second nanos",
			in:   "1704067200.5",
			want: time.Date(2024, 1, 1, 0, 0, 0, 500_000_000, time.UTC),
			ok:   true,
		},
		{
			name: "RFC3339 fallback (custom Zeek config)",
			in:   "2024-01-01T00:00:00Z",
			want: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			ok:   true,
		},
		{
			name: "empty",
			in:   "",
			ok:   false,
		},
		{
			name: "garbage",
			in:   "not-a-time",
			ok:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseZeekCertTime(c.in)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if !got.Equal(c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
