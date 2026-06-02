package model

import "testing"

// TestBeaconHistoryKey_ScrubsSeparatorInjection codifies NEW-85. The
// canonical-string key joins six fields with \x1f. If any field
// contains the delimiter byte itself, the field structure of the key
// becomes ambiguous and two distinct findings can produce the same
// byte string:
//
//	Finding 1: Hostname="evil.com\x1fa", URI="/b"
//	Finding 2: Hostname="evil.com",      URI="a\x1f/b"
//
// Both produce "Beacon\x1f10.0.0.1\x1f2.2.2.2\x1f443\x1fevil.com\x1fa\x1f/b"
// pre-scrub. The threat model accepts that compromised sensors can
// ship crafted Host headers, so we defensively scrub the delimiter
// byte out of each field before join. After the scrub, the keys diverge.
func TestBeaconHistoryKey_ScrubsSeparatorInjection(t *testing.T) {
	base := Finding{
		Type:    "Beacon",
		SrcIP:   "10.0.0.1",
		DstIP:   "2.2.2.2",
		DstPort: "443",
	}

	a := base
	a.Hostname = "evil.com\x1fa"
	a.URI = "/b"

	b := base
	b.Hostname = "evil.com"
	b.URI = "a\x1f/b"

	keyA := a.BeaconHistoryKey()
	keyB := b.BeaconHistoryKey()

	if keyA == keyB {
		t.Errorf("crafted Findings produced colliding BeaconHistoryKey: %q", keyA)
	}
}

// TestBeaconHistoryKey_NormalInputUnchanged guards the cheap-path
// optimization in scrubSeparator: typical hostnames/IPs/URIs that
// don't contain \x1f must not allocate or otherwise mutate.
func TestBeaconHistoryKey_NormalInputUnchanged(t *testing.T) {
	f := Finding{
		Type:     "HTTP Beacon",
		SrcIP:    "10.0.0.1",
		DstIP:    "2.2.2.2",
		DstPort:  "443",
		Hostname: "tracker.evil.com",
		URI:      "/heartbeat",
	}
	got := f.BeaconHistoryKey()
	want := "HTTP Beacon\x1f10.0.0.1\x1f2.2.2.2\x1f443\x1ftracker.evil.com\x1f/heartbeat\x1f"
	if got != want {
		t.Errorf("normal-input BeaconHistoryKey = %q, want %q", got, want)
	}
}
