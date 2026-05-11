package store

import (
	"database/sql"
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
	insideWindow := now.AddDate(0, 0, -(beaconHistoryRetentionDays - 1)).Format("2006-01-02")
	atBoundary := now.AddDate(0, 0, -beaconHistoryRetentionDays).Format("2006-01-02")
	outsideWindow := now.AddDate(0, 0, -(beaconHistoryRetentionDays + 1)).Format("2006-01-02")

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
