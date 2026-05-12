package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestPruneFindingsBefore_DropsOldAndTimestamplessFindings exercises the
// destructive prune used by the archive worker's "Also remove findings"
// toggle. Findings older than the cutoff and findings with empty or
// unparseable timestamps must both be dropped — keeping timestampless
// findings would let Strobe and Data Exfiltration findings outlive the
// retention window indefinitely.
func TestPruneFindingsBefore_DropsOldAndTimestamplessFindings(t *testing.T) {
	s := New(config.Default())

	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour).Format("2006-01-02 15:04:05")
	fresh := now.Add(-1 * time.Hour).Format("2006-01-02 15:04:05")

	s.findings = []model.Finding{
		{Type: "Beaconing", Timestamp: old},         // dropped — old
		{Type: "Long Connection", Timestamp: fresh}, // kept — within window
		{Type: "Strobe", Timestamp: ""},             // dropped — empty (was kept under old behavior)
		{Type: "Data Exfiltration", Timestamp: ""},  // dropped — empty
		{Type: "Beaconing", Timestamp: "garbage"},   // dropped — unparseable
	}

	cutoff := now.Add(-24 * time.Hour)
	dropped := s.PruneFindingsBefore(cutoff)

	if dropped != 4 {
		t.Errorf("expected 4 findings dropped, got %d", dropped)
	}
	if len(s.findings) != 1 {
		t.Fatalf("expected 1 finding kept, got %d", len(s.findings))
	}
	if s.findings[0].Type != "Long Connection" {
		t.Errorf("unexpected survivor: %+v", s.findings[0])
	}
}

// TestPruneFindingsBefore_NoOp confirms a prune that drops nothing leaves
// the slice and database untouched (and doesn't panic on a fresh store
// without a DB attached).
func TestPruneFindingsBefore_NoOp(t *testing.T) {
	s := New(config.Default())
	now := time.Now().UTC()
	fresh := now.Add(-1 * time.Hour).Format("2006-01-02 15:04:05")

	s.findings = []model.Finding{
		{Type: "Beaconing", Timestamp: fresh},
		{Type: "Long Connection", Timestamp: fresh},
	}

	cutoff := now.Add(-24 * time.Hour)
	if dropped := s.PruneFindingsBefore(cutoff); dropped != 0 {
		t.Errorf("expected 0 dropped on no-op, got %d", dropped)
	}
	if len(s.findings) != 2 {
		t.Errorf("findings slice should be unchanged, got len=%d", len(s.findings))
	}
}

// TestTryStartAnalysis_AtomicClaim covers NEW-31. Two near-
// simultaneous callers must not both observe success. Pre-NEW-31
// the call site was IsAnalyzing() followed by SetAnalyzing(true)
// with a real TOCTOU window between the two; TryStartAnalysis
// folds them into a single mutex-protected operation.
func TestTryStartAnalysis_AtomicClaim(t *testing.T) {
	s := New(config.Default())

	// Serial: first claim wins, second loses, then a release lets
	// the next claim win.
	if !s.TryStartAnalysis() {
		t.Fatal("first claim must succeed on a fresh store")
	}
	if s.TryStartAnalysis() {
		t.Fatal("second claim must fail while first is still held")
	}
	s.SetAnalyzing(false)
	if !s.TryStartAnalysis() {
		t.Fatal("post-release claim must succeed")
	}
	s.SetAnalyzing(false)

	// Concurrent: spawn N goroutines that all try to claim at once.
	// Exactly one must observe true.
	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	winners := make(chan bool, N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			winners <- s.TryStartAnalysis()
		}()
	}
	close(start)
	wg.Wait()
	close(winners)
	wins := 0
	for w := range winners {
		if w {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("expected exactly 1 winner among %d concurrent claims; got %d", N, wins)
	}
}

// TestFindingsIdx_StaysConsistentAcrossMutations exercises the id→index
// map maintained alongside s.findings. Every operation that rebuilds or
// mutates the slice must rebuild the index too, otherwise GetFinding /
// UpdateFinding / AddNote drift into either returning stale rows or
// missing-id false negatives. Audit 2026-05-10 follow-up.
func TestFindingsIdx_StaysConsistentAcrossMutations(t *testing.T) {
	s := New(config.Default())

	notifs := s.SetFindings([]model.Finding{
		{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-10 12:00:00"},
		{Type: "Long Connection", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Score: 40, Severity: model.SevMedium, Timestamp: "2026-05-10 12:01:00"},
	})
	_ = notifs

	if len(s.findingsIdx) != len(s.findings) {
		t.Fatalf("index size %d != findings len %d after SetFindings",
			len(s.findingsIdx), len(s.findings))
	}
	for i, f := range s.findings {
		if got := s.findingsIdx[f.ID]; got != i {
			t.Errorf("findingsIdx[%d] = %d, want %d", f.ID, got, i)
		}
	}

	// GetFinding by id should resolve in O(1) and match the slice row.
	wantID := s.findings[0].ID
	got, ok := s.GetFinding(wantID)
	if !ok || got.ID != wantID {
		t.Errorf("GetFinding(%d) ok=%v id=%d", wantID, ok, got.ID)
	}
	if _, ok := s.GetFinding(999_999); ok {
		t.Error("GetFinding for unknown id should return ok=false")
	}

	// UpdateFinding mutates in-place and the index keeps pointing at
	// the same slot — the row's mutated state must be visible after.
	before, ok := s.UpdateFinding(wantID, model.StatusAcknowledged, "alice", "looking", "2026-05-10 12:02:00")
	if !ok {
		t.Fatal("UpdateFinding returned false on a known id")
	}
	// NEW-36: snapshot must reflect the pre-mutation state — same id,
	// status from the seed row, not the post-update status.
	if before.ID != wantID || before.Status == model.StatusAcknowledged {
		t.Errorf("UpdateFinding before snapshot wrong: id=%d status=%s", before.ID, before.Status)
	}
	got2, _ := s.GetFinding(wantID)
	if got2.Status != model.StatusAcknowledged || got2.Analyst != "alice" {
		t.Errorf("mutation not visible via index: %+v", got2)
	}

	// PruneFindingsBefore drops a row; the index must be rebuilt so
	// the surviving id resolves to its NEW slot, not the old slot.
	cutoff, _ := time.Parse("2006-01-02 15:04:05", "2026-05-10 12:00:30")
	if dropped := s.PruneFindingsBefore(cutoff); dropped != 1 {
		t.Fatalf("expected 1 dropped, got %d", dropped)
	}
	survivorID := s.findings[0].ID
	if i, ok := s.findingsIdx[survivorID]; !ok || i != 0 {
		t.Errorf("findingsIdx[%d] = (%d,%v) after prune, want (0,true)", survivorID, i, ok)
	}
	if _, ok := s.GetFinding(wantID); ok {
		t.Errorf("GetFinding(%d) should be false after prune", wantID)
	}

	// ClearFindings empties everything; index must drop too.
	if n := s.ClearFindings(); n != 1 {
		t.Errorf("ClearFindings returned %d, want 1", n)
	}
	if len(s.findingsIdx) != 0 {
		t.Errorf("findingsIdx not cleared: %v", s.findingsIdx)
	}
}

// TestSetFindings_PurgesStaleRollups verifies the IsRollupType filter
// in the preserve-historical loop. A Host Risk Score or Correlated
// Activity row from a prior run whose fingerprint isn't regenerated
// this run must be dropped — preserving it would leave an orphan
// pointing at contributors that no longer exist or that have dropped
// below the roll-up's threshold. Closes the narrow case left open by
// NEW-67 (HRS) and the same shape introduced alongside Correlated
// Activity.
func TestSetFindings_PurgesStaleRollups(t *testing.T) {
	s := New(config.Default())

	// Seed: Beaconing finding + an HRS row for the same host + a
	// Correlated Activity row for the same pair.
	s.SetFindings([]model.Finding{
		{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-10 12:00:00"},
		{Type: "Host Risk Score", SrcIP: "10.0.0.1", DstIP: "(network)", Score: 50, Severity: model.SevHigh, Timestamp: "2026-05-10 12:00:00"},
		{Type: "Correlated Activity", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 85, Severity: model.SevCritical, Timestamp: "2026-05-10 12:00:00"},
	})

	// Second run regenerates only the Beaconing finding — neither
	// the roll-up phase has anything to emit (suppose the operator
	// re-ran analysis after toggling a setting that suppresses HRS
	// and correlation). Both roll-up rows should be purged; the
	// Beaconing finding should remain.
	s.SetFindings([]model.Finding{
		{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00"},
	})

	gotTypes := map[string]int{}
	for _, f := range s.findings {
		gotTypes[f.Type]++
	}
	if gotTypes["Beaconing"] != 1 {
		t.Errorf("Beaconing count = %d, want 1", gotTypes["Beaconing"])
	}
	if gotTypes["Host Risk Score"] != 0 {
		t.Errorf("stale Host Risk Score not purged; got %d row(s)", gotTypes["Host Risk Score"])
	}
	if gotTypes["Correlated Activity"] != 0 {
		t.Errorf("stale Correlated Activity not purged; got %d row(s)", gotTypes["Correlated Activity"])
	}
}

// TestSetFindings_CorrelationsPersistAcrossReload codifies NEW-72.
// Pre-fix Finding.Correlations was in-memory only: saveFindings didn't
// serialize it and loadFindings didn't read it back, so the "+N corr"
// chip in the Findings table disappeared on every server restart and
// only reappeared after the next analysis run repopulated the field.
// Schema migration 0010 added a correlations TEXT column; this test
// asserts the round-trip preserves the slice through a save-and-reload.
func TestSetFindings_CorrelationsPersistAcrossReload(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db1, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db1.SetMaxOpenConns(1)
	if err := RunMigrations(db1); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	s1 := New(config.Default())
	s1.InitDB(db1)
	// Seed: three findings, two of which carry Correlations referencing
	// the third (a Correlated Activity roll-up).
	s1.SetFindings([]model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00",
			Correlations: []int{2, 3}},
		{ID: 2, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53",
			Score: 60, Severity: model.SevMedium, Timestamp: "2026-05-11 09:00:00",
			Correlations: []int{1, 3}},
		{ID: 3, Type: model.TypeCorrelatedActivity, SrcIP: "10.0.0.1", DstIP: "1.1.1.1",
			Score: 85, Severity: model.SevCritical, Timestamp: "2026-05-11 09:00:00",
			Correlations: []int{1, 2}},
	})

	// Capture the post-translation persisted Correlations from s1.
	want := make(map[string][]int, 3)
	for _, f := range s1.findings {
		want[f.Type] = append([]int{}, f.Correlations...)
		if len(f.Correlations) == 0 {
			t.Errorf("setup: %s has no Correlations after first SetFindings", f.Type)
		}
	}
	_ = db1.Close()

	// Reload from the same on-disk DB into a fresh Store. The
	// correlations column read in loadFindings must restore each
	// finding's slice byte-for-byte.
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	db2.SetMaxOpenConns(1)
	defer db2.Close()

	s2 := New(config.Default())
	s2.InitDB(db2)

	for _, f := range s2.findings {
		got := f.Correlations
		exp := want[f.Type]
		if !sameIntSet(got, exp) {
			t.Errorf("%s.Correlations after reload = %v; want %v", f.Type, got, exp)
		}
	}
}

// TestSetFindings_TranslatesCorrelationIDs codifies NEW-71. correlate.go
// populates Finding.Correlations with the per-run fresh a.nextID++ IDs
// at emit time; SetFindings then rewrites each finding's ID via
// fingerprint match. Without translation, the Correlations slice
// retains stale fresh-IDs that either don't exist or collide with
// unrelated findings from prior runs.
//
// Worked example: a fresh Beaconing emitted at fresh ID 1 with
// Correlations=[2,3] (sibling + correlation-row IDs from the same
// run) lands on top of a preserved Beaconing fingerprint at persisted
// ID 47. After SetFindings, the merged row must have ID 47 AND
// Correlations translated to the corresponding persisted IDs of
// findings 2 and 3 in the same run — not the raw [2,3] from the
// analyzer's perspective.
func TestSetFindings_TranslatesCorrelationIDs(t *testing.T) {
	s := New(config.Default())

	// Seed two findings whose fingerprints will be re-fired in run 2.
	// They get high persisted IDs because they're the only seed rows.
	s.SetFindings([]model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-10 09:00:00"},
		{ID: 2, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53", Score: 60, Severity: model.SevMedium, Timestamp: "2026-05-10 09:00:00"},
	})

	// Capture the post-merge IDs (post-run-1 SetFindings may have
	// assigned different IDs than the inputs supplied above).
	var bcnPersisted, dnsPersisted int
	for _, f := range s.findings {
		switch f.Type {
		case "Beaconing":
			bcnPersisted = f.ID
		case "DNS Tunneling":
			dnsPersisted = f.ID
		}
	}
	if bcnPersisted == 0 || dnsPersisted == 0 {
		t.Fatal("setup: failed to locate seeded findings by type")
	}

	// Run 2: analyzer emits the same two findings with FRESH IDs (1, 2)
	// plus a Correlated Activity row at fresh ID 3 that annotates each
	// contributor's Correlations with sibling + correlation-row IDs.
	// This is the shape correlate.go produces in-memory before
	// SetFindings has had a chance to rewrite IDs.
	freshBcnID, freshDnsID, freshCorrID := 1, 2, 3
	s.SetFindings([]model.Finding{
		{
			ID: freshBcnID, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00",
			Correlations: []int{freshDnsID, freshCorrID}, // sibling + roll-up
		},
		{
			ID: freshDnsID, Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53",
			Score: 60, Severity: model.SevMedium, Timestamp: "2026-05-11 09:00:00",
			Correlations: []int{freshBcnID, freshCorrID},
		},
		{
			ID: freshCorrID, Type: model.TypeCorrelatedActivity, SrcIP: "10.0.0.1", DstIP: "1.1.1.1",
			Score: 85, Severity: model.SevCritical, Timestamp: "2026-05-11 09:00:00",
			Correlations: []int{freshBcnID, freshDnsID}, // contributors
		},
	})

	// Locate the persisted findings by type/fingerprint.
	var bcn, dns, corr *model.Finding
	for i := range s.findings {
		f := &s.findings[i]
		switch f.Type {
		case "Beaconing":
			bcn = f
		case "DNS Tunneling":
			dns = f
		case model.TypeCorrelatedActivity:
			corr = f
		}
	}
	if bcn == nil || dns == nil || corr == nil {
		t.Fatalf("missing finding after run 2: bcn=%v dns=%v corr=%v", bcn, dns, corr)
	}

	// Beaconing/DNS Tunneling kept their preserved IDs (fingerprint match).
	if bcn.ID != bcnPersisted {
		t.Errorf("Beaconing.ID = %d; want preserved %d", bcn.ID, bcnPersisted)
	}
	if dns.ID != dnsPersisted {
		t.Errorf("DNS Tunneling.ID = %d; want preserved %d", dns.ID, dnsPersisted)
	}

	// Correlations must reference the post-translation persisted IDs,
	// not the analyzer's fresh per-run IDs. Specifically:
	//   Beaconing.Correlations should be [dnsPersisted, corr.ID]
	//   DNS Tunneling.Correlations should be [bcnPersisted, corr.ID]
	//   Correlated Activity.Correlations should be [bcnPersisted, dnsPersisted]
	if !sameIntSet(bcn.Correlations, []int{dnsPersisted, corr.ID}) {
		t.Errorf("Beaconing.Correlations = %v; want [%d, %d] (translated fresh→persisted)", bcn.Correlations, dnsPersisted, corr.ID)
	}
	if !sameIntSet(dns.Correlations, []int{bcnPersisted, corr.ID}) {
		t.Errorf("DNS Tunneling.Correlations = %v; want [%d, %d]", dns.Correlations, bcnPersisted, corr.ID)
	}
	if !sameIntSet(corr.Correlations, []int{bcnPersisted, dnsPersisted}) {
		t.Errorf("Correlated Activity.Correlations = %v; want [%d, %d] (the two contributors)", corr.Correlations, bcnPersisted, dnsPersisted)
	}
}

// TestSetFindings_PreservesHistoricalCorrelationIDs codifies NEW-91
// (twenty-first audit round). correlate.go's historical-union path
// puts persisted IDs directly into this-run findings' Correlations
// slices (when a contributor exists in the store from a prior run
// but doesn't re-fire this run). Pre-fix SetFindings's translation
// looked up every ID in freshToPersisted; historical persisted IDs
// aren't keys in that map, so they were silently dropped.
//
// Worked example (the common case):
//
//	Run 1: Beaconing fires, persisted ID 47.
//	       DNS Tunneling fires, persisted ID 92.
//	Run 2: Beaconing fires (fresh ID 5) — DNS Tunneling does NOT.
//	       correlate.go consults findingsProvider, sees historical
//	       DNS Tunneling, includes its persisted ID 92 in Beaconing's
//	       Correlations alongside the fresh correlation-row ID.
//
// The post-SetFindings invariant: Beaconing.Correlations must
// contain BOTH the translated correlation-row persisted ID AND the
// historical DNS Tunneling persisted ID (92), unchanged. Pre-fix,
// only the translated ID survived; the historical reference was
// dropped, and the "+N corr" chip on Beaconing showed the wrong
// count for every cross-run correlation.
//
// The fix: SetFindings builds a historicalIDs set from s.findings
// before the translation pass, and treats IDs in that set as
// identity-mapped during translation.
func TestSetFindings_PreservesHistoricalCorrelationIDs(t *testing.T) {
	s := New(config.Default())

	// Pad run 1 with junk findings so the target contributor (DNS
	// Tunneling) gets a high persisted ID. This represents the
	// common deployment shape the auditor analyzed: fresh IDs are
	// small (1..n where n is the per-run finding count), historical
	// persisted IDs are large (after many runs, persisted IDs grow
	// into the thousands).
	//
	// Without the padding, fresh IDs in run 2 (1, 2) collide
	// numerically with historical persisted IDs (1, 2 from run 1)
	// — case B2 in the audit notes, a known limitation of the
	// fresh-vs-historical-ID disambiguation. With padding, DNS
	// Tunneling lands at persisted ID 20, well above run 2's fresh
	// range of 1..2, and translation can disambiguate cleanly.
	run1 := []model.Finding{}
	for i := 0; i < 18; i++ {
		run1 = append(run1, model.Finding{
			Type: "Suspicious URL", SrcIP: "10.0.0.99",
			DstIP: fmt.Sprintf("198.51.100.%d", i+1), DstPort: "443",
			Score: 50, Severity: model.SevMedium,
			Timestamp: "2026-05-10 09:00:00",
		})
	}
	run1 = append(run1,
		model.Finding{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-10 09:00:00"},
		model.Finding{Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "53",
			Score: 60, Severity: model.SevMedium, Timestamp: "2026-05-10 09:00:00"},
	)
	s.SetFindings(run1)
	var bcnPersisted, dnsPersisted int
	for _, f := range s.findings {
		if f.SrcIP != "10.0.0.1" {
			continue
		}
		switch f.Type {
		case "Beaconing":
			bcnPersisted = f.ID
		case "DNS Tunneling":
			dnsPersisted = f.ID
		}
	}
	if bcnPersisted == 0 || dnsPersisted == 0 {
		t.Fatalf("setup: failed to locate seeded contributors: bcn=%d dns=%d", bcnPersisted, dnsPersisted)
	}

	// Run 2: only Beaconing re-fires. correlate.go would build the
	// pair from a.findings (fresh Beaconing) + findingsProvider
	// (historical Beaconing + historical DNS Tunneling) and emit a
	// Correlated Activity row. With NEW-92's fingerprint-dedup
	// preferring the historical Beaconing's persisted ID, the
	// resulting Correlations slice on the Correlated Activity row
	// would be [bcnPersisted, dnsPersisted]. We simulate that
	// directly here — the contract under test is SetFindings's
	// translation, not correlate.go.
	freshBcnID, freshCorrID := 1, 2
	s.SetFindings([]model.Finding{
		{
			ID: freshBcnID, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00",
			// Historical DNS Tunneling's persisted ID is in this slice
			// directly (not a fresh ID). Pre-NEW-91, the translation
			// would drop it.
			Correlations: []int{dnsPersisted, freshCorrID},
		},
		{
			ID: freshCorrID, Type: model.TypeCorrelatedActivity, SrcIP: "10.0.0.1", DstIP: "1.1.1.1",
			Score: 85, Severity: model.SevCritical, Timestamp: "2026-05-11 09:00:00",
			// Contributors: fresh Beaconing + historical DNS Tunneling
			// (already in persisted-ID space).
			Correlations: []int{freshBcnID, dnsPersisted},
		},
	})

	var bcn, corr *model.Finding
	for i := range s.findings {
		f := &s.findings[i]
		switch f.Type {
		case "Beaconing":
			bcn = f
		case model.TypeCorrelatedActivity:
			corr = f
		}
	}
	if bcn == nil || corr == nil {
		t.Fatalf("missing finding after run 2: bcn=%v corr=%v", bcn, corr)
	}

	if !sameIntSet(bcn.Correlations, []int{dnsPersisted, corr.ID}) {
		t.Errorf("Beaconing.Correlations = %v; want [%d, %d] (historical DNS persisted ID preserved + fresh corr translated)",
			bcn.Correlations, dnsPersisted, corr.ID)
	}
	if !sameIntSet(corr.Correlations, []int{bcnPersisted, dnsPersisted}) {
		t.Errorf("Correlated Activity.Correlations = %v; want [%d, %d] (fresh bcn translated + historical dns preserved)",
			corr.Correlations, bcnPersisted, dnsPersisted)
	}
}

// sameIntSet compares two int slices ignoring order.
func sameIntSet(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[int]int, len(a))
	for _, v := range a {
		set[v]++
	}
	for _, v := range b {
		set[v]--
		if set[v] < 0 {
			return false
		}
	}
	return true
}

// TestSetFindings_PreservesNonRollupHistorical confirms the purge is
// scoped to roll-up types only. A Beaconing finding from a prior run
// that doesn't re-fire must still be preserved — its absence from the
// TestSetFindings_WritesBeaconHistory codifies the slice-3 contract:
// a SetFindings call carrying a Beaconing or HTTP Beaconing finding
// also writes a row to beacon_history keyed by (BeaconHistoryKey,
// today_UTC). Non-beacon types must NOT write history rows — the
// table is per-beacon-evolution, not a general finding log.
func TestSetFindings_WritesBeaconHistory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	beacon := model.Finding{
		Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
		Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00",
		Hostname:  "kx9j3qm2pflw.com",
		TSScore:   0.92,
		DSScore:   0.88,
		HistScore: 0.10,
		DurScore:  0.95,
	}
	httpBeacon := model.Finding{
		Type: "HTTP Beaconing", SrcIP: "10.0.0.2", DstIP: "1.1.1.2", DstPort: "443",
		Score: 65, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00",
		Hostname:  "tracker.evil.com",
		URI:       "/heartbeat",
		TSScore:   1.0,
		DSScore:   1.0,
		HistScore: 0.0,
		DurScore:  0.0,
	}
	dns := model.Finding{
		Type: "DNS Tunneling", SrcIP: "10.0.0.3", DstIP: "8.8.8.8", DstPort: "53",
		Score: 60, Severity: model.SevMedium, Timestamp: "2026-05-11 09:00:00",
	}
	s.SetFindings([]model.Finding{beacon, httpBeacon, dns})

	today := time.Now().UTC().Format("2006-01-02")

	if maxScore, lastScore, ok := s.beaconHistoryRowSnapshot(beacon.BeaconHistoryKey(), today); !ok {
		t.Errorf("Beaconing history row missing for %s on %s", beacon.BeaconHistoryKey(), today)
	} else if maxScore != 80 || lastScore != 80 {
		t.Errorf("Beaconing first-write: max=%d last=%d, want max=80 last=80", maxScore, lastScore)
	}
	if maxScore, lastScore, ok := s.beaconHistoryRowSnapshot(httpBeacon.BeaconHistoryKey(), today); !ok {
		t.Errorf("HTTP Beaconing history row missing")
	} else if maxScore != 65 || lastScore != 65 {
		t.Errorf("HTTP Beaconing first-write: max=%d last=%d, want max=65 last=65", maxScore, lastScore)
	}
	if _, _, ok := s.beaconHistoryRowSnapshot(dns.BeaconHistoryKey(), today); ok {
		t.Errorf("DNS Tunneling wrote a beacon_history row; only beacon types should")
	}
}

// TestSetFindings_BeaconHistorySameDayUPSERT codifies the v0.16.1
// NEW-76 redesign: a single (fingerprint, day_utc) row carries both
// max_score (the spike — what the chart renders) and last_score (the
// most recent reading). Pre-v0.16.1 used INSERT … ON CONFLICT DO
// NOTHING which silently dropped subsequent same-day writes, hiding
// the adversarial-tuning case where a C2 operator changes dwell
// mid-day.
//
// Three writes simulating a tuning attempt across one UTC day:
//   - morning write at score 60 → row created, max=60, last=60
//   - noon write at score 88 (the spike) → max upgrades to 88, last=88
//   - evening write at score 50 (fallback) → max holds at 88, last=50
//
// By the next morning's chart render, max=88 captures the spike;
// last=50 records what the beacon was last actually emitting.
func TestSetFindings_BeaconHistorySameDayUPSERT(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	morning := model.Finding{
		Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
		Score: 60, Severity: model.SevHigh, Timestamp: "2026-05-11 06:00:00",
	}
	s.SetFindings([]model.Finding{morning})

	today := time.Now().UTC().Format("2006-01-02")
	maxScore, lastScore, ok := s.beaconHistoryRowSnapshot(morning.BeaconHistoryKey(), today)
	if !ok {
		t.Fatalf("morning row missing")
	}
	if maxScore != 60 || lastScore != 60 {
		t.Errorf("after morning write: max=%d last=%d, want max=60 last=60", maxScore, lastScore)
	}

	// Noon write at higher score → both max and last update.
	noon := morning
	noon.Score = 88
	noon.Severity = model.SevCritical
	s.SetFindings([]model.Finding{noon})
	maxScore, lastScore, _ = s.beaconHistoryRowSnapshot(morning.BeaconHistoryKey(), today)
	if maxScore != 88 || lastScore != 88 {
		t.Errorf("after noon spike: max=%d last=%d, want max=88 last=88", maxScore, lastScore)
	}

	// Evening write at lower score → max holds at 88, last falls to 50.
	// This is the critical assertion: pre-NEW-76 the noon spike (88)
	// would not have been recorded at all, so the chart would render
	// the morning's 60 instead of the trajectory-meaningful 88.
	evening := morning
	evening.Score = 50
	evening.Severity = model.SevMedium
	s.SetFindings([]model.Finding{evening})
	maxScore, lastScore, _ = s.beaconHistoryRowSnapshot(morning.BeaconHistoryKey(), today)
	if maxScore != 88 {
		t.Errorf("after evening fallback: max=%d, want 88 (spike must be preserved across the day)", maxScore)
	}
	if lastScore != 50 {
		t.Errorf("after evening fallback: last=%d, want 50 (most-recent reading)", lastScore)
	}
}

// TestPurgeBeaconHistory deletes rows older than the retention window
// while leaving in-window rows alone. Uses direct SQL inserts with
// crafted day_utc values to avoid time-of-day dependence — the real
// retention window is 30 days but the test asserts the cutoff
// behavior at day 30 / day 31 explicitly.
func TestPurgeBeaconHistory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	now := time.Now().UTC()
	insideWindow := now.AddDate(0, 0, -(BeaconHistoryRetentionDays - 1)).Format("2006-01-02")
	atBoundary := now.AddDate(0, 0, -BeaconHistoryRetentionDays).Format("2006-01-02")
	outsideWindow := now.AddDate(0, 0, -(BeaconHistoryRetentionDays + 1)).Format("2006-01-02")

	for _, day := range []string{insideWindow, atBoundary, outsideWindow} {
		_, err := db.Exec(`INSERT INTO beacon_history
            (fingerprint, day_utc, finding_type, src_ip, dst_ip, dst_port, host, uri,
             max_score, max_score_at, last_score, last_score_at,
             severity, ts_score, ds_score, hist_score, dur_score, created_at)
            VALUES (?, ?, 'Beaconing', '10.0.0.1', '1.1.1.1', '443', '', '',
                    80, ?, 80, ?, 'HIGH', 1, 1, 0, 1, ?)`,
			"fp-"+day, day, now.Unix(), now.Unix(), now.Unix())
		if err != nil {
			t.Fatalf("seed beacon_history row for %s: %v", day, err)
		}
	}

	deleted := s.PurgeBeaconHistory()
	if deleted != 1 {
		t.Errorf("purged rows = %d, want 1 (only outsideWindow)", deleted)
	}

	// insideWindow + atBoundary still present, outsideWindow gone.
	if _, _, ok := s.beaconHistoryRowSnapshot("fp-"+insideWindow, insideWindow); !ok {
		t.Errorf("in-window row removed by purge")
	}
	if _, _, ok := s.beaconHistoryRowSnapshot("fp-"+atBoundary, atBoundary); !ok {
		t.Errorf("at-boundary row (day == retention) removed by purge")
	}
	if _, _, ok := s.beaconHistoryRowSnapshot("fp-"+outsideWindow, outsideWindow); ok {
		t.Errorf("out-of-window row survived purge")
	}
}

// current run isn't authoritative (the source logs may have been
// archived but the historical observation is still valid). Same
// guarantee as before the rollup-purge change.
func TestSetFindings_PreservesNonRollupHistorical(t *testing.T) {
	s := New(config.Default())

	s.SetFindings([]model.Finding{
		{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-10 12:00:00"},
		{Type: "DNS Tunneling", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 60, Severity: model.SevMedium, Timestamp: "2026-05-10 12:00:00"},
	})

	// Second run only emits Beaconing; DNS Tunneling must be
	// preserved as a historical detection.
	s.SetFindings([]model.Finding{
		{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Score: 80, Severity: model.SevHigh, Timestamp: "2026-05-11 09:00:00"},
	})

	gotTypes := map[string]int{}
	for _, f := range s.findings {
		gotTypes[f.Type]++
	}
	if gotTypes["Beaconing"] != 1 {
		t.Errorf("Beaconing count = %d, want 1", gotTypes["Beaconing"])
	}
	if gotTypes["DNS Tunneling"] != 1 {
		t.Errorf("DNS Tunneling not preserved; got %d row(s)", gotTypes["DNS Tunneling"])
	}
}

// TestBeaconHistory_CapsAtRetentionWindow codifies NEW-88. The read
// path must clip rows older than the retention window even when
// they're physically present in the table — defense against PurgeBeaconHistory
// failing to run (e.g. boot before the first prune-loop tick), future
// retention bumps, or malformed manual inserts at extreme dates.
func TestBeaconHistory_CapsAtRetentionWindow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(config.Default())
	s.InitDB(db)

	key := "fp-beaconhistory-cap-test"
	now := time.Now().UTC()
	inside := now.AddDate(0, 0, -10).Format("2006-01-02")
	stale := now.AddDate(0, 0, -(BeaconHistoryRetentionDays + 30)).Format("2006-01-02")

	for _, day := range []string{inside, stale} {
		_, err := db.Exec(`INSERT INTO beacon_history
            (fingerprint, day_utc, finding_type, src_ip, dst_ip, dst_port, host, uri,
             max_score, max_score_at, last_score, last_score_at,
             severity, ts_score, ds_score, hist_score, dur_score, created_at)
            VALUES (?, ?, 'Beaconing', '10.0.0.1', '1.1.1.1', '443', '', '',
                    80, ?, 80, ?, 'HIGH', 1, 1, 0, 1, ?)`,
			key, day, now.Unix(), now.Unix(), now.Unix())
		if err != nil {
			t.Fatalf("seed beacon_history row for %s: %v", day, err)
		}
	}

	got := s.BeaconHistory(key)
	if len(got) != 1 {
		t.Fatalf("BeaconHistory returned %d rows, want 1 (stale day must be clipped)", len(got))
	}
	if got[0].DayUTC != inside {
		t.Errorf("returned row has day_utc=%q, want %q (the in-window day)", got[0].DayUTC, inside)
	}
}

// TestNotifications_PersistAcrossReload codifies NEW-98 (twenty-third
// audit round). The invariant: every notification surfaced through
// the bell (finding alarms via SetFindings, sensor/feed alarms via
// AddAlarm) survives a store close + reopen, including its dismissed
// state. Pre-fix s.notifications and s.notifCounter were in-memory
// only; a restart wiped every active alarm, and the operator's last
// surface for "what alerted today" disappeared on any redeploy.
//
// The test covers all three notification origin paths:
//   - SetFindings bell emission (Kind=finding via score >= 99)
//   - AddAlarm with Kind=sensor
//   - AddAlarm with Kind=feed
//
// plus a dismissed-then-reloaded shape to assert the dismissed flag
// round-trips. notifCounter is asserted to re-seed from MAX(id) so
// the next emission can't collide with a persisted ID.
func TestNotifications_PersistAcrossReload(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Run 1: emit one finding alarm (score 99) + one sensor alarm +
	// one feed alarm. Dismiss the feed alarm so we can verify the
	// dismissed bit round-trips.
	s := New(config.Default())
	s.InitDB(db)
	s.SetFindings([]model.Finding{
		{Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 99, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
	})
	s.AddAlarm(model.Notification{
		Kind: "sensor", Target: "lab-1",
		Severity: string(model.SevHigh), Type: "Sensor offline",
		Detail: "Sensor lab-1 hasn't checked in for 2h 15m",
	})
	feedNotif := s.AddAlarm(model.Notification{
		Kind: "feed", Target: "misp-prod",
		Severity: string(model.SevHigh), Type: "Feed unhealthy",
		Detail: "Feed misp-prod: 3 consecutive refresh failures",
	})
	s.DismissNotification(feedNotif.ID)

	before := s.GetNotifications()
	if len(before) != 3 {
		t.Fatalf("run 1 has %d notifications, want 3", len(before))
	}

	// Close + reopen the DB to simulate a server restart. The
	// migration runner is idempotent so a re-run is a no-op.
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	db2.SetMaxOpenConns(1)
	defer db2.Close()
	if err := RunMigrations(db2); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	s2 := New(config.Default())
	s2.InitDB(db2)
	after := s2.GetNotifications()

	if len(after) != 3 {
		t.Fatalf("after reload: %d notifications, want 3 (lost on restart pre-fix)", len(after))
	}

	// Build name maps by ID for shape-comparison.
	byID := map[int]model.Notification{}
	for _, n := range after {
		byID[n.ID] = n
	}
	for _, b := range before {
		a, ok := byID[b.ID]
		if !ok {
			t.Errorf("notification id=%d (kind=%s target=%s) not present after reload", b.ID, b.Kind, b.Target)
			continue
		}
		if a.Kind != b.Kind || a.Target != b.Target || a.Type != b.Type {
			t.Errorf("notification id=%d shape drift: before=%+v after=%+v", b.ID, b, a)
		}
		if a.Dismissed != b.Dismissed {
			t.Errorf("notification id=%d dismissed bit lost: before=%v after=%v", b.ID, b.Dismissed, a.Dismissed)
		}
		if a.Detail != b.Detail {
			t.Errorf("notification id=%d Detail lost: before=%q after=%q", b.ID, b.Detail, a.Detail)
		}
	}

	// notifCounter must seed above the highest persisted id so a new
	// emission can't collide. Add a fresh alarm and confirm its id
	// lands above feedNotif.ID (the highest pre-reload id).
	newAlarm := s2.AddAlarm(model.Notification{
		Kind: "sensor", Target: "lab-2",
		Severity: string(model.SevHigh), Type: "Sensor offline",
	})
	if newAlarm.ID <= feedNotif.ID {
		t.Errorf("post-reload AddAlarm assigned id=%d, want strictly > %d (notifCounter not seeded from MAX(id))", newAlarm.ID, feedNotif.ID)
	}
}

// TestSetFindings_BellGate_AtLeast95Notifies codifies the bell
// threshold contract enumerated in CHANGELOG v0.17.1 (NEW-99). The
// invariant: a finding emits a bell notification iff it is new AND
// score >= 95. The threshold was 99 in v0.17.0 and over-corrected
// — discrete-tier detectors top out below 99 by design, so
// externally-validated high-confidence indicators (URLhaus 96,
// Malicious JA3 95, FeodoTracker 97) stayed silent. 95 captures
// the top of both populations.
//
// Articulating the invariant rather than the failure case: the
// score axis has two semantics in this codebase (continuous-
// composite for Beaconing-class detectors, discrete-tier for the
// hard-coded hit detectors); this test asserts the gate behaves
// consistently across both populations at the chosen boundary.
//
// The tier enumeration this test pins down (matches CHANGELOG):
//
//	Rings the bell:  URLhaus/FeodoTracker (96-97), Malicious JA3 (95),
//	                 DGA-bumped Beaconing (up to 99), Correlated
//	                 Activity stacks (up to 99), score-100 catch-all.
//	Does NOT ring:   Cobalt Strike URI (93), Zeek attack notice (92),
//	                 C2 URI Pattern (91), MISP/OpenCTI broad (90),
//	                 Host Risk Score at any score (roll-up exclusion).
func TestSetFindings_BellGate_AtLeast95Notifies(t *testing.T) {
	s := New(config.Default())
	findings := []model.Finding{
		// Below threshold: representative discrete-tier scores from
		// detectors that do NOT ring at the v0.17.1 threshold.
		{Type: "MISP Match", SrcIP: "10.0.0.1", DstIP: "1.1.1.1",
			Score: 90, Severity: model.SevHigh, Timestamp: "2026-05-12 09:00:00"},
		{Type: "C2 URI Pattern", SrcIP: "10.0.0.2", DstIP: "1.1.1.2",
			Score: 91, Severity: model.SevHigh, Timestamp: "2026-05-12 09:00:00"},
		{Type: "Zeek Notice", SrcIP: "10.0.0.3", DstIP: "1.1.1.3",
			Score: 92, Severity: model.SevHigh, Timestamp: "2026-05-12 09:00:00"},
		{Type: "Cobalt Strike URI", SrcIP: "10.0.0.4", DstIP: "1.1.1.4",
			Score: 93, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Below threshold by score; CRITICAL severity is no longer
		// enough on its own (this was the old gate).
		{Type: "Beaconing", SrcIP: "10.0.0.5", DstIP: "1.1.1.5", DstPort: "443",
			Score: 88, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},

		// Boundary: exactly 95 — rings (Malicious JA3 lives here).
		{Type: "Malicious JA3", SrcIP: "10.0.0.6", DstIP: "1.1.1.6",
			Score: 95, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// URLhaus tier (96): rings.
		{Type: "Suspicious URL", SrcIP: "10.0.0.7", DstIP: "1.1.1.7",
			Score: 96, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// FeodoTracker tier (97): rings.
		{Type: "TI Hit (IP)", SrcIP: "10.0.0.8", DstIP: "1.1.1.8",
			Score: 97, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Score-100 catch-all: rings.
		{Type: "Beaconing", SrcIP: "10.0.0.9", DstIP: "1.1.1.9", DstPort: "443",
			Score: 100, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},

		// Excluded by type even at max score — Host Risk Score is a roll-up.
		{Type: "Host Risk Score", SrcIP: "10.0.0.10", DstIP: "(host)",
			Score: 100, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
	}
	notifs := s.SetFindings(findings)

	// Expected: Malicious JA3 (95), Suspicious URL (96), TI Hit (IP) (97),
	// Beaconing (100). Four rings, in any order.
	if len(notifs) != 4 {
		t.Fatalf("got %d notifications, want 4 (the score>=95 non-rollup findings); notifs=%+v", len(notifs), notifs)
	}
	ringingByType := map[string]bool{}
	for _, n := range notifs {
		ringingByType[n.Type] = true
		if n.Kind != "finding" {
			t.Errorf("notification for %s has Kind=%q, want \"finding\"", n.Type, n.Kind)
		}
	}
	wantRinging := []string{"Malicious JA3", "Suspicious URL", "TI Hit (IP)", "Beaconing"}
	for _, want := range wantRinging {
		if !ringingByType[want] {
			t.Errorf("expected %q to ring (>=95), missing from %+v", want, notifs)
		}
	}
	mustNotRing := []string{"MISP Match", "C2 URI Pattern", "Zeek Notice", "Cobalt Strike URI", "Host Risk Score"}
	for _, sub := range mustNotRing {
		if ringingByType[sub] {
			t.Errorf("type %q is below threshold (or excluded) and must not ring", sub)
		}
	}
}

// TestSetFindings_BellGate_HiddenByAllowlistOrSuppression codifies
// NEW-111. The invariant: a notification is never emitted for a
// finding whose row would be filtered out of the table by the
// allowlist or suppression — same exclusion check that
// findings_filter.go applies at read time. Pre-fix the bell rang for
// allowlisted/suppressed findings: single-finding GET bypasses the
// filter (Detail pane renders), but every list endpoint hides the
// row, so Jump scrolled nowhere and the click was a silent no-op.
//
// Test articulates the invariant ("notification iff the row would
// appear in the listing") and exercises both gating paths and both
// IP roles (src vs dst), so a future refactor that only checks one
// of the four shapes fails this test instead of slipping through.
func TestSetFindings_BellGate_HiddenByAllowlistOrSuppression(t *testing.T) {
	s := New(config.Default())

	// Allowlist covers everything in 10.0.99.0/24 plus the specific
	// mDNS multicast IPv6. Suppress 192.168.50.50 for an hour.
	s.SetAllowlist([]string{"10.0.99.0/24", "ff02::fb"})
	s.AddSuppression("192.168.50.50", time.Now().Add(time.Hour), "noisy mDNS responder")

	findings := []model.Finding{
		// Should ring: visible finding above threshold.
		{Type: "Malicious JA3", SrcIP: "10.0.0.1", DstIP: "1.1.1.1",
			Score: 95, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Hidden by allowlist CIDR match on src.
		{Type: "Beaconing", SrcIP: "10.0.99.5", DstIP: "1.1.1.2", DstPort: "443",
			Score: 96, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Hidden by allowlist CIDR match on dst.
		{Type: "Beaconing", SrcIP: "10.0.0.2", DstIP: "10.0.99.6", DstPort: "443",
			Score: 97, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Hidden by allowlist exact-match on dst (IPv6 multicast).
		{Type: "Correlated Activity", SrcIP: "fe80::fafc:e1ff:fe70:4334", DstIP: "ff02::fb",
			Score: 99, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Hidden by suppression on src.
		{Type: "TI Hit (IP)", SrcIP: "192.168.50.50", DstIP: "1.1.1.3",
			Score: 97, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Hidden by suppression on dst.
		{Type: "TI Hit (IP)", SrcIP: "1.1.1.4", DstIP: "192.168.50.50",
			Score: 97, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		// Should ring: dst is on neither list.
		{Type: "Suspicious URL", SrcIP: "10.0.0.3", DstIP: "8.8.8.8",
			Score: 96, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
	}
	notifs := s.SetFindings(findings)
	if len(notifs) != 2 {
		t.Fatalf("got %d notifications, want 2 (only the unhidden findings); notifs=%+v", len(notifs), notifs)
	}
	rang := map[string]bool{}
	for _, n := range notifs {
		rang[n.SrcIP+"→"+n.DstIP] = true
	}
	if !rang["10.0.0.1→1.1.1.1"] {
		t.Errorf("expected the visible Malicious JA3 finding to ring, got %+v", notifs)
	}
	if !rang["10.0.0.3→8.8.8.8"] {
		t.Errorf("expected the visible Suspicious URL finding to ring, got %+v", notifs)
	}
}

// TestSetAllowlist_DismissesHiddenFindingNotifications codifies the
// cleanup path of NEW-111. Notifications emitted before the operator
// adds an IP to the allowlist persist into the bell with no row to
// jump to; SetAllowlist must walk active finding notifications and
// dismiss those whose Src or Dst is now covered.
func TestSetAllowlist_DismissesHiddenFindingNotifications(t *testing.T) {
	s := New(config.Default())

	// Ring three bells with the allowlist empty.
	s.SetFindings([]model.Finding{
		{Type: "Malicious JA3", SrcIP: "10.0.0.1", DstIP: "1.1.1.1",
			Score: 95, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		{Type: "Beaconing", SrcIP: "10.0.99.5", DstIP: "8.8.8.8", DstPort: "443",
			Score: 96, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		{Type: "Correlated Activity", SrcIP: "fe80::fafc:e1ff:fe70:4334", DstIP: "ff02::fb",
			Score: 99, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
	})
	if got := len(activeFindingNotifs(s)); got != 3 {
		t.Fatalf("baseline: got %d active finding notifs, want 3", got)
	}

	// Now allowlist a CIDR covering one finding's src and an exact IP
	// covering another's dst. Third stays visible.
	s.SetAllowlist([]string{"10.0.99.0/24", "ff02::fb"})

	active := activeFindingNotifs(s)
	if len(active) != 1 {
		t.Fatalf("after allowlist update: got %d active finding notifs, want 1 (only the visible one); active=%+v", len(active), active)
	}
	if active[0].SrcIP != "10.0.0.1" {
		t.Errorf("surviving notification should be the unhidden one (10.0.0.1→1.1.1.1), got %+v", active[0])
	}
}

// TestAddSuppression_DismissesHiddenFindingNotifications codifies
// the cleanup path of NEW-111 for the suppression side.
func TestAddSuppression_DismissesHiddenFindingNotifications(t *testing.T) {
	s := New(config.Default())

	s.SetFindings([]model.Finding{
		{Type: "Malicious JA3", SrcIP: "10.0.0.1", DstIP: "1.1.1.1",
			Score: 95, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
		{Type: "TI Hit (IP)", SrcIP: "192.168.50.50", DstIP: "8.8.8.8",
			Score: 97, Severity: model.SevCritical, Timestamp: "2026-05-12 09:00:00"},
	})
	if got := len(activeFindingNotifs(s)); got != 2 {
		t.Fatalf("baseline: got %d active finding notifs, want 2", got)
	}

	s.AddSuppression("192.168.50.50", time.Now().Add(time.Hour), "test")

	active := activeFindingNotifs(s)
	if len(active) != 1 {
		t.Fatalf("after suppression: got %d active finding notifs, want 1; active=%+v", len(active), active)
	}
	if active[0].SrcIP != "10.0.0.1" {
		t.Errorf("surviving notification should be the unhidden one, got %+v", active[0])
	}
}

// activeFindingNotifs returns the subset of s.GetNotifications() that
// are (a) Kind="finding" (or unset, the pre-v0.17.0 default) and (b)
// not yet dismissed. Helper for the cleanup-on-list-update tests.
func activeFindingNotifs(s *Store) []model.Notification {
	all := s.GetNotifications()
	out := make([]model.Notification, 0, len(all))
	for _, n := range all {
		if n.Dismissed {
			continue
		}
		if n.Kind != "" && n.Kind != "finding" {
			continue
		}
		out = append(out, n)
	}
	return out
}
