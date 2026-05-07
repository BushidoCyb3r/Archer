package store

import (
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

func TestSanitizeListEntries_PreservesCommentsAndStripsInlineTails(t *testing.T) {
	in := []string{
		"# Section: org office IPs",
		"192.0.2.5",
		"  ",
		"192.0.2.6 # printer",
		"# Section: cloud build agents",
		"10.0.0.0/8",
		"192.0.2.5", // duplicate, should be dropped
		"# trailing comment",
	}
	// Whole-line comments survive verbatim; inline tails are stripped;
	// duplicate entries are dropped; order is preserved.
	want := []string{
		"# Section: org office IPs",
		"192.0.2.5",
		"192.0.2.6",
		"# Section: cloud build agents",
		"10.0.0.0/8",
		"# trailing comment",
	}

	got := sanitizeListEntries(in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sanitizeListEntries = %#v\n         want %#v", got, want)
	}
}

func TestSanitizeListEntries_StripsTabSeparatedInlineTail(t *testing.T) {
	in := []string{"192.0.2.5\t# office printer"}
	want := []string{"192.0.2.5"}
	got := sanitizeListEntries(in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tab-separated inline tail not stripped: got %v want %v", got, want)
	}
}

func TestSanitizeListEntries_PreservesHashInsideContent(t *testing.T) {
	// '#' immediately adjacent to content (no whitespace before) is part
	// of the content, not a comment marker. This protects entries like
	// `host#weird` from accidental truncation.
	in := []string{"host#weird"}
	want := []string{"host#weird"}
	got := sanitizeListEntries(in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hash-inside-content was wrongly stripped: got %v want %v", got, want)
	}
}

func TestSanitizeListEntries_DropsEmptyAndWhitespaceOnly(t *testing.T) {
	in := []string{"", "   ", "\t", "192.0.2.5", "  "}
	want := []string{"192.0.2.5"}
	got := sanitizeListEntries(in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("empty/whitespace handling: got %v want %v", got, want)
	}
}

func TestSetAllowlist_PreservesOrderIncludingCommentsAcrossSetGet(t *testing.T) {
	s := New(config.Default())

	in := []string{
		"# Section header",
		"203.0.113.10",
		"203.0.113.11",
		"# Cloud agents",
		"198.51.100.0/24",
		"# Trailing comment",
	}
	s.SetAllowlist(in)

	got := s.GetAllowlist()
	// Comments survive verbatim; IPs/CIDRs hold their position; section
	// structure is preserved across the save/reload round-trip.
	if !reflect.DeepEqual(got, in) {
		t.Errorf("GetAllowlist after Set should round-trip exactly:\n got  %v\n want %v", got, in)
	}

	// Idempotent: setting the same input twice produces the same order.
	// This is what protects an operator's grouping across analyst-UI
	// save/reload cycles.
	s.SetAllowlist(in)
	got2 := s.GetAllowlist()
	if !reflect.DeepEqual(got2, in) {
		t.Errorf("GetAllowlist after second Set drifted:\n got  %v\n want %v", got2, in)
	}
}

func TestSetAllowlist_StripsInlineTailsButKeepsHeaders(t *testing.T) {
	s := New(config.Default())
	s.SetAllowlist([]string{
		"# org office",
		"192.0.2.5 # printer",
		"192.0.2.6",
	})
	want := []string{"# org office", "192.0.2.5", "192.0.2.6"}
	got := s.GetAllowlist()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestSetIOCList_PreservesOrderIncludingComments(t *testing.T) {
	s := New(config.Default())

	in := []string{
		"# Cobalt Strike beacons seen 2026-04",
		"198.51.100.42",
		"203.0.113.99",
		"203.0.113.100",
		"# Phishing kit hosts",
		"evil.example",
	}
	s.SetIOCList(in)

	got := s.GetIOCList()
	if !reflect.DeepEqual(got, in) {
		t.Errorf("GetIOCList round-trip mismatch:\n got  %v\n want %v", got, in)
	}
}

func TestSetAllowlist_DedupesWithoutLosingOrder(t *testing.T) {
	s := New(config.Default())
	s.SetAllowlist([]string{"a", "b", "a", "c", "b", "d"})
	got := s.GetAllowlist()
	want := []string{"a", "b", "c", "d"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dedupe-preserving-order failed: got %v want %v", got, want)
	}
}
