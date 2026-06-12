package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

func newCIDRTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pair.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)
	return s
}

// TestPairAllowlist_CIDRRules pins the ranged-rule contract: a rule whose
// Src and/or Dst is a CIDR hides any finding whose IPs fall inside the
// range(s), with the exact-side / port / type / sensor semantics identical
// to exact rules — and exact rules keep working alongside. Both the
// direct store path and the FilterSnapshot path (the hot /api/findings
// path) must agree, and an unparseable CIDR row is inert, never a panic
// or an accidental match-everything.
func TestPairAllowlist_CIDRRules(t *testing.T) {
	s := newCIDRTestStore(t)

	// The motivating rule: the whole LAN may talk DNS to the resolver.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "10.0.0.0/24", Dst: "10.0.0.53", Port: "53"}); err != nil {
		t.Fatalf("AddPairAllow LAN→resolver: %v", err)
	}
	// Both sides ranged, type-scoped, sensor-scoped.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "172.16.0.0/12", Dst: "192.0.2.0/24", Port: "443", FindingType: "Beacon", Sensor: "boxA"}); err != nil {
		t.Fatalf("AddPairAllow ranged pair: %v", err)
	}
	// IPv6 range.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "2001:db8::/32", Dst: "2001:db8:1::53", Port: "53"}); err != nil {
		t.Fatalf("AddPairAllow v6: %v", err)
	}
	// Exact rule still goes through the hash index.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "10.9.9.9", Dst: "203.0.113.1", Port: "22"}); err != nil {
		t.Fatalf("AddPairAllow exact: %v", err)
	}

	checks := []struct {
		name                          string
		src, dst, port, ftype, sensor string
		want                          bool
	}{
		{"LAN member → resolver hidden", "10.0.0.7", "10.0.0.53", "53", "Beacon", "", true},
		{"any type on the LAN rule", "10.0.0.250", "10.0.0.53", "53", "DNS Tunneling", "s9", true},
		{"outside the /24 stays visible", "10.0.1.7", "10.0.0.53", "53", "Beacon", "", false},
		{"wrong dst stays visible", "10.0.0.7", "10.0.0.54", "53", "Beacon", "", false},
		{"wrong port stays visible", "10.0.0.7", "10.0.0.53", "443", "Beacon", "", false},
		{"non-IP src never matches a range", "not-an-ip", "10.0.0.53", "53", "Beacon", "", false},
		{"both-ranged rule, in both ranges", "172.20.4.4", "192.0.2.99", "443", "Beacon", "boxA", true},
		{"both-ranged rule, sensor mismatch", "172.20.4.4", "192.0.2.99", "443", "Beacon", "boxB", false},
		{"both-ranged rule, type mismatch", "172.20.4.4", "192.0.2.99", "443", "Strobe", "boxA", false},
		{"v6 range member hidden", "2001:db8:ffff::1", "2001:db8:1::53", "53", "Beacon", "", true},
		{"v6 outside range visible", "2001:db9::1", "2001:db8:1::53", "53", "Beacon", "", false},
		{"exact rule still matches", "10.9.9.9", "203.0.113.1", "22", "Lateral Movement", "", true},
	}
	snap := s.NewFilterSnapshot()
	for _, c := range checks {
		if got := s.IsPairAllowed(c.src, c.dst, c.port, c.ftype, c.sensor); got != c.want {
			t.Errorf("store %s: IsPairAllowed=%v, want %v", c.name, got, c.want)
		}
		if got := snap.IsPairAllowed(c.src, c.dst, c.port, c.ftype, c.sensor); got != c.want {
			t.Errorf("snapshot %s: IsPairAllowed=%v, want %v", c.name, got, c.want)
		}
	}

	// A malformed CIDR (only reachable via a hand-edited DB row — the API
	// validates) is dropped at index rebuild: inert, not a panic, and
	// emphatically not a match-everything.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "10.0.0.0/99", Dst: "1.1.1.1", Port: "53"}); err != nil {
		t.Fatalf("AddPairAllow malformed: %v", err)
	}
	if s.IsPairAllowed("10.0.0.1", "1.1.1.1", "53", "Beacon", "") {
		t.Error("malformed-CIDR rule must be inert, not matching")
	}
}

// TestPairAllowlist_WildcardDomainRules pins the *.domain ranged-rule
// contract: a wildcard side hides any finding whose value is the apex or
// any name under it, case-insensitively (DNS names are; the detectors
// lowercase but x509 subjects and hand-fed values may not be). Exact
// domain sides keep the hash-index semantics, lookalike domains never
// match, both sides accept wildcards, and CIDR + wildcard mix on one
// rule. Store and FilterSnapshot paths must agree, and a malformed
// wildcard row (hand-edited DB) is inert.
func TestPairAllowlist_WildcardDomainRules(t *testing.T) {
	s := newCIDRTestStore(t)

	// The motivating rule: one host may talk DNS to skype.com and below.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "192.168.20.55", Dst: "*.skype.com", Port: "53"}); err != nil {
		t.Fatalf("AddPairAllow wildcard dst: %v", err)
	}
	// Exact domain dst goes through the hash index, no wildcard expansion.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "10.1.1.1", Dst: "telemetry.example.com", Port: "443"}); err != nil {
		t.Fatalf("AddPairAllow exact domain: %v", err)
	}
	// Wildcard src, type-scoped.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "*.corp.internal", Dst: "203.0.113.9", Port: "22", FindingType: "Lateral Movement"}); err != nil {
		t.Fatalf("AddPairAllow wildcard src: %v", err)
	}
	// CIDR src + wildcard dst on one rule.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "10.2.0.0/16", Dst: "*.updates.example.net", Port: "80"}); err != nil {
		t.Fatalf("AddPairAllow CIDR+wildcard: %v", err)
	}

	checks := []struct {
		name                          string
		src, dst, port, ftype, sensor string
		want                          bool
	}{
		{"apex hidden", "192.168.20.55", "skype.com", "53", "DNS Tunneling", "", true},
		{"subdomain hidden", "192.168.20.55", "edge.skype.com", "53", "TI Hit (Domain)", "", true},
		{"deep subdomain hidden", "192.168.20.55", "a.b.skype.com", "53", "Beacon", "s1", true},
		{"case-insensitive", "192.168.20.55", "EDGE.Skype.COM", "53", "Beacon", "", true},
		{"lookalike apex visible", "192.168.20.55", "notskype.com", "53", "Beacon", "", false},
		{"suffix-spoof visible", "192.168.20.55", "skype.com.evil.net", "53", "Beacon", "", false},
		{"wrong src visible", "192.168.20.56", "edge.skype.com", "53", "Beacon", "", false},
		{"wrong port visible", "192.168.20.55", "edge.skype.com", "443", "Beacon", "", false},
		{"exact domain hidden", "10.1.1.1", "telemetry.example.com", "443", "Beacon", "", true},
		{"exact domain is not a wildcard", "10.1.1.1", "sub.telemetry.example.com", "443", "Beacon", "", false},
		{"wildcard src hidden", "ws1.corp.internal", "203.0.113.9", "22", "Lateral Movement", "", true},
		{"wildcard src type mismatch", "ws1.corp.internal", "203.0.113.9", "22", "Beacon", "", false},
		{"CIDR+wildcard both match", "10.2.9.9", "cdn.updates.example.net", "80", "Beacon", "", true},
		{"CIDR+wildcard src outside range", "10.3.9.9", "cdn.updates.example.net", "80", "Beacon", "", false},
	}
	snap := s.NewFilterSnapshot()
	for _, c := range checks {
		if got := s.IsPairAllowed(c.src, c.dst, c.port, c.ftype, c.sensor); got != c.want {
			t.Errorf("store %s: IsPairAllowed=%v, want %v", c.name, got, c.want)
		}
		if got := snap.IsPairAllowed(c.src, c.dst, c.port, c.ftype, c.sensor); got != c.want {
			t.Errorf("snapshot %s: IsPairAllowed=%v, want %v", c.name, got, c.want)
		}
	}

	// A bare "*." side (only reachable via a hand-edited DB row — the API
	// validates) is dropped at index rebuild: inert, never match-everything.
	if _, err := s.AddPairAllow(model.PairAllowEntry{Src: "192.168.20.55", Dst: "*.", Port: "53"}); err != nil {
		t.Fatalf("AddPairAllow malformed wildcard: %v", err)
	}
	if s.IsPairAllowed("192.168.20.55", "anything.at.all", "53", "Beacon", "") {
		t.Error("malformed wildcard rule must be inert, not matching")
	}
}
