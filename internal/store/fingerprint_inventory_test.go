package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestFingerprintInventory pins the contract behind the TLS Fingerprints modal.
// The invariant: the inventory surfaces exactly the high-signal fingerprints —
// any known-bad C2 match (always critical, regardless of how common it is) plus
// any fingerprint whose rarity/cross-host concern reaches medium or higher —
// and nothing else. Common browser shapes and low-confidence single-host JA3s
// are excluded. Rows carry the prevalence counts and a finding count that
// includes non-beacon findings (so a known-bad row pivots onto its Malicious
// JA3/JA4 finding), and the list is ordered by severity then prevalence.
//
// Articulating the invariant rather than a single failure case: the gate is a
// threshold over a derived level shared with the detail-pane badge, so the test
// exercises one fingerprint per outcome (known-bad-but-common, rare-clustered,
// rare-single, common, low) on both JA3 and JA4 to catch a future change that
// shifts the threshold or the JA4-vs-JA3 confidence cap.
func TestFingerprintInventory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer db.Close()

	badJA4 := map[string]string{"kb_ja4": "Cobalt Strike v4.9.1"}
	badJA3 := map[string]string{"kb_ja3": "Cobalt Strike beacon"}

	s := New(config.Default())
	s.InitDB(db)
	s.SetFingerprintPrevalence(
		map[string]model.FingerprintStat{
			"kb_ja4":             {Conns: 1000, SrcHosts: 1, Dsts: 500},    // known-bad but common: still critical
			"rare_clustered_ja4": {Conns: 43, SrcHosts: 3, Dsts: 1},        // critical
			"rare_single_ja4":    {Conns: 20, SrcHosts: 1, Dsts: 1},        // high
			"common_ja4":         {Conns: 600000, SrcHosts: 2, Dsts: 2000}, // none — excluded
		},
		map[string]model.FingerprintStat{
			"kb_ja3":             {Conns: 5, SrcHosts: 1, Dsts: 1},  // known-bad: critical
			"rare_clustered_ja3": {Conns: 30, SrcHosts: 2, Dsts: 1}, // medium
			"rare_single_ja3":    {Conns: 12, SrcHosts: 1, Dsts: 1}, // low — excluded
		},
	)
	// Findings give the per-fingerprint count. Two beacons share the rare
	// clustered JA4; one Malicious JA3 finding carries the known-bad JA3.
	s.SetFindings([]model.Finding{
		{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-18 09:00:00", JA4: "rare_clustered_ja4"},
		{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-18 09:01:00", JA4: "rare_clustered_ja4"},
		{ID: 3, Type: "Malicious JA3", SrcIP: "10.0.0.3", DstIP: "2.2.2.2", DstPort: "443",
			Score: 95, Severity: model.SevCritical, Timestamp: "2026-05-18 09:02:00", JA3: "kb_ja3"},
	})

	rows := s.FingerprintInventory(badJA4, badJA3)

	// Expected high-signal set and order: three criticals (ranked by
	// src-hosts then conns), then the high, then the medium.
	wantOrder := []string{"rare_clustered_ja4", "kb_ja4", "kb_ja3", "rare_single_ja4", "rare_clustered_ja3"}
	if len(rows) != len(wantOrder) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(wantOrder), rows)
	}
	for i, want := range wantOrder {
		if rows[i].Fingerprint != want {
			t.Errorf("row %d = %q, want %q (full order: %v)", i, rows[i].Fingerprint, want, fpList(rows))
		}
	}

	// Excluded fingerprints must not appear at all.
	for _, fp := range rows {
		if fp.Fingerprint == "common_ja4" || fp.Fingerprint == "rare_single_ja3" {
			t.Errorf("excluded fingerprint %q present in inventory", fp.Fingerprint)
		}
	}

	by := map[string]model.FingerprintRow{}
	for _, r := range rows {
		by[r.Fingerprint] = r
	}

	// Known-bad overrides rarity: a common known-bad JA4 is still critical,
	// flagged, and labelled.
	if r := by["kb_ja4"]; r.Level != "critical" || !r.KnownBad || r.Label != "Cobalt Strike v4.9.1" {
		t.Errorf("kb_ja4 = %+v; want critical/known-bad/labelled", r)
	}
	if r := by["kb_ja3"]; r.Level != "critical" || !r.KnownBad {
		t.Errorf("kb_ja3 = %+v; want critical/known-bad", r)
	}
	// Non-bad rows carry their derived level and are not flagged.
	if r := by["rare_clustered_ja4"]; r.Level != "critical" || r.KnownBad {
		t.Errorf("rare_clustered_ja4 = %+v; want critical/not-known-bad", r)
	}
	if r := by["rare_single_ja4"]; r.Level != "high" {
		t.Errorf("rare_single_ja4 level = %q; want high", r.Level)
	}
	if r := by["rare_clustered_ja3"]; r.Level != "medium" {
		t.Errorf("rare_clustered_ja3 level = %q; want medium", r.Level)
	}

	// Finding counts include non-beacon findings so the pivot lands.
	if r := by["rare_clustered_ja4"]; r.FindingCount != 2 {
		t.Errorf("rare_clustered_ja4 finding_count = %d; want 2", r.FindingCount)
	}
	if r := by["kb_ja3"]; r.FindingCount != 1 {
		t.Errorf("kb_ja3 finding_count = %d; want 1 (Malicious JA3 finding)", r.FindingCount)
	}
	// Prevalence counts pass through unchanged.
	if r := by["rare_clustered_ja4"]; r.Conns != 43 || r.SrcHosts != 3 || r.Dsts != 1 {
		t.Errorf("rare_clustered_ja4 prevalence = %d/%d/%d; want 43/3/1", r.Conns, r.SrcHosts, r.Dsts)
	}

	t.Run("empty snapshot yields no rows", func(t *testing.T) {
		fresh := New(config.Default())
		fresh.InitDB(db)
		if got := fresh.FingerprintInventory(badJA4, badJA3); len(got) != 0 {
			t.Errorf("expected no rows with empty snapshot, got %d", len(got))
		}
	})
}

func fpList(rows []model.FingerprintRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Fingerprint
	}
	return out
}
