package model

import "testing"

// TestFingerprint_KeyComposition pins the exact field composition of the
// fingerprint merge key. Fingerprint() is the identity SetFindings uses to
// carry analyst state (status/notes) and IDs forward across re-analyses, so a
// silent change to which fields enter the key is a breaking change to
// persistence — a too-broad key splits one finding's history in two; a
// too-narrow key collapses distinct findings onto one row. The invariants:
//   - the base key is always (Type, SrcIP, DstIP, DstPort, Sensor);
//   - Hostname/URI enter the key ONLY for "HTTP Beacon";
//   - Channel enters the key for ANY type when non-empty (the per-channel
//     beacon discriminator), and is absent when empty.
//
// If this test fails, the change to Fingerprint() was deliberate — update the
// expectations AND add a `### Breaking` CHANGELOG entry per RELEASING.md.
func TestFingerprint_KeyComposition(t *testing.T) {
	cases := []struct {
		name string
		in   Finding
		want Fingerprint
	}{
		{
			name: "plain beacon ignores Hostname/URI/Channel",
			in: Finding{
				Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Sensor: "s1",
				Hostname: "ignored.example", URI: "/ignored", Channel: "",
			},
			want: Fingerprint{Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Sensor: "s1"},
		},
		{
			name: "HTTP Beacon folds in Hostname and URI",
			in: Finding{
				Type: "HTTP Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.6", DstPort: "80", Sensor: "s1",
				Hostname: "cdn.example", URI: "/submit.php",
			},
			want: Fingerprint{
				Type: "HTTP Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.6", DstPort: "80", Sensor: "s1",
				Hostname: "cdn.example", URI: "/submit.php",
			},
		},
		{
			name: "per-channel beacon folds in Channel",
			in: Finding{
				Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "203.0.113.7", DstPort: "443", Sensor: "s1",
				Channel: "ja3:abc123",
			},
			want: Fingerprint{
				Type: "Beacon", SrcIP: "10.0.0.3", DstIP: "203.0.113.7", DstPort: "443", Sensor: "s1",
				Channel: "ja3:abc123",
			},
		},
		{
			name: "non-HTTP-Beacon type does NOT fold in Hostname/URI even when set",
			in: Finding{
				Type: "TI Hit (Domain)", SrcIP: "10.0.0.4", DstIP: "evil.example", DstPort: "53", Sensor: "s2",
				Hostname: "evil.example", URI: "/x",
			},
			want: Fingerprint{Type: "TI Hit (Domain)", SrcIP: "10.0.0.4", DstIP: "evil.example", DstPort: "53", Sensor: "s2"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Fingerprint(); got != c.want {
				t.Errorf("Fingerprint() = %#v\n            want %#v", got, c.want)
			}
		})
	}
}
