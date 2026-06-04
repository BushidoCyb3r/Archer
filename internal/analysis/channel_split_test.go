package analysis

import (
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestPerChannelBeacon_HiddenC2Surfaces is the end-to-end invariant test for
// per-channel beacon scoring (Fork A). It asserts the contract the golden
// snapshot only captures by value: a blended beacon that hides a sharper TLS
// channel must yield BOTH the blend (kept — non-destructive) AND a distinct,
// strictly-sharper channel sub-finding, while a channel that does NOT beat the
// blend is never promoted (no duplicate, no fragmentation flood).
func TestPerChannelBeacon_HiddenC2Surfaces(t *testing.T) {
	dir := filepath.Join("testdata", "zeek", "beacon_channel_split")
	files := collectFixtureLogs(t, dir)

	a := New(config.Default(), "", nil, nil)
	findings := a.Analyze(files)

	const dst = "203.0.113.90"
	const c2JA3 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	var blend *model.Finding
	var channels []*model.Finding
	for i := range findings {
		f := &findings[i]
		if f.Type != "Beacon" || f.DstIP != dst {
			continue
		}
		if f.Channel == "" {
			if blend != nil {
				t.Fatalf("two blended beacons to %s; expected exactly one (Channel=\"\")", dst)
			}
			blend = f
		} else {
			channels = append(channels, f)
		}
	}

	// (1) The blend must survive — the overlay never replaces it.
	if blend == nil {
		t.Fatal("blended beacon missing: the overlay must keep the blend, never replace it")
	}
	// (2) Exactly one channel promoted (the C2); the noisy CDN channel scores
	// below the blend and must not be promoted.
	if len(channels) != 1 {
		t.Fatalf("promoted channels = %d, want exactly 1 (only the C2 should beat the blend)", len(channels))
	}
	ch := channels[0]
	// (3) The promoted channel is the clean C2 (by JA3) and carries its
	// fingerprint + channel discriminator.
	if ch.Channel != "ja3:"+c2JA3 {
		t.Errorf("promoted channel = %q, want %q", ch.Channel, "ja3:"+c2JA3)
	}
	if ch.JA3 != c2JA3 {
		t.Errorf("channel JA3 = %q, want %q", ch.JA3, c2JA3)
	}
	// (4) Strictly sharper than the blend — the reason to surface it at all.
	if ch.Score <= blend.Score {
		t.Errorf("channel score %d must be strictly greater than blend score %d (hidden-beacon contract)", ch.Score, blend.Score)
	}
	// (5) The hidden C2 is materially sharper here: blend MEDIUM, channel
	// CRITICAL. Lock the severity gap so a regression that flattens the split
	// is caught, not just an off-by-one score drift.
	if blend.Severity != model.SevMedium {
		t.Errorf("blend severity = %q, want MEDIUM (the concentrated CDN noise should drag the blend down)", blend.Severity)
	}
	if ch.Severity != model.SevCritical {
		t.Errorf("channel severity = %q, want CRITICAL (the clean C2 channel scored alone)", ch.Severity)
	}
}
