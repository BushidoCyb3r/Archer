package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
)

// TestParallelEach_RecoversPanic is F-REL-1: a panic in a detector running
// inside a parallelEach worker must NOT terminate the process (HTTP, SSE,
// sensor endpoints all share it). It degrades to a per-file skip recorded
// in ParseErrors, the pass completes, and every other file still runs —
// the same skip-and-continue contract recordParseError gives the parser.
// Both the serial (1 file) and goroutine (many files) dispatch paths are
// covered.
func TestParallelEach_RecoversPanic(t *testing.T) {
	for _, n := range []int{1, 6} {
		t.Run(fmt.Sprintf("%d_files", n), func(t *testing.T) {
			a := New(config.Default(), "", nil, nil)
			dir := t.TempDir()
			var files []string
			for i := 0; i < n; i++ {
				p := filepath.Join(dir, fmt.Sprintf("f%d.log", i))
				if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				files = append(files, p)
			}
			poison := files[0]

			var ran int64
			// A bare panic here without recovery would crash the test binary.
			a.parallelEach(files, func(path string) {
				if path == poison {
					panic("boom: poison record")
				}
				atomic.AddInt64(&ran, 1)
			})

			found := false
			for _, e := range a.ParseErrors() {
				if e.Path == poison {
					found = true
				}
			}
			if !found {
				t.Errorf("poison file not recorded in ParseErrors: %+v", a.ParseErrors())
			}
			if int(ran) != n-1 {
				t.Errorf("ran=%d, want %d — non-poison files must still complete", ran, n-1)
			}
		})
	}
}
