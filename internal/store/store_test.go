package store

import (
	"sync"
	"testing"
	"time"

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

// TestSetFindings_PreservesNonRollupHistorical confirms the purge is
// scoped to roll-up types only. A Beaconing finding from a prior run
// that doesn't re-fire must still be preserved — its absence from the
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
