package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// TestWatchFingerprint_PreRunSnapshotDetectsMidRunAppend is the LG-6
// regression. The dataset fingerprint persisted after a full pass must
// reflect the fileset as it was when the run STARTED reading, not when it
// finished. A file appended mid-run, if captured in a post-run fingerprint,
// makes the next non-forced pass's skip-check (datasetFingerprint == stored)
// see "no change" and skip — so the appended tail never receives statistical
// analysis. Persisting the pre-run fingerprint means a mid-run (or any later)
// change differs from the stored value and forces a re-read next pass.
//
// The mid-run timing can't be synchronized through the real analysis
// goroutine (the analyzer is constructed internally and would hit the
// network via prefetchFeeds), so this locks the invariant at the automatable
// layer: datasetFingerprint's sensitivity to appends and the skip-check's
// stored-vs-current comparison. watch.go persisting startedFP (the pre-run
// value) is verified by reading and by the full suite passing.
func TestWatchFingerprint_PreRunSnapshotDetectsMidRunAppend(t *testing.T) {
	dir := t.TempDir()
	s := &Server{store: store.New(config.Default()), broker: NewBroker(), logsDir: dir}

	path := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(path, []byte("line1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	files := []string{path}

	// Fingerprint captured at run start — the value the fix persists.
	preRunFP := s.datasetFingerprint(files)

	// A file is appended while the analysis is still running.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err := f.WriteString("line2-appended-mid-run\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	postRunFP := s.datasetFingerprint(files)
	if preRunFP == postRunFP {
		t.Fatal("datasetFingerprint did not change after an append — cannot detect mid-run writes")
	}

	// Fix: persist the pre-run fingerprint. The next non-forced pass computes
	// the current (post-append) fingerprint, which must NOT match the stored
	// one, so it does not skip and the appended data is re-analyzed.
	s.store.SetLastAnalysisFingerprint(preRunFP)
	if s.datasetFingerprint(files) == s.store.GetLastAnalysisFingerprint() {
		t.Error("next pass would skip: current fingerprint matches the stored pre-run one despite an append")
	}

	// Failure mode being prevented: had the post-run fingerprint been stored,
	// the next pass would see a match and wrongly skip the appended tail.
	s.store.SetLastAnalysisFingerprint(postRunFP)
	if s.datasetFingerprint(files) != s.store.GetLastAnalysisFingerprint() {
		t.Error("test premise broken: post-run fingerprint should match the unchanged current state")
	}
}
