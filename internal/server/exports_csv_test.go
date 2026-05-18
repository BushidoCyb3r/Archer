package server

import (
	"encoding/csv"
	"net/http/httptest"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestExportCSV_BeaconScopedColumns codifies the v1.5 export invariant
// as a pair of contracts, not a single case:
//
//  1. Default export (no type filter) keeps the historical 13-column
//     header byte-for-byte — a downstream consumer parsing by column
//     index must not break. This is the non-breaking guarantee.
//  2. Beacon-scoped export (type=beacons) filters to the beacon family
//     AND APPENDS the triage columns after the base 13 (never inserts),
//     so the same index-based consumer still reads columns 0..12
//     unchanged while an IR tool can read the wide tail.
//
// Asserting both arms together means a regression in either the scope
// (non-beacons leaking into a beacon export) or the column layout
// (triage columns inserted mid-row, shifting the base schema) fails
// here rather than silently corrupting a downstream pipeline.
func TestExportCSV_BeaconScopedColumns(t *testing.T) {
	s := newAuditTestServer(t)
	s.store.SetFindings([]model.Finding{
		{ID: 1, Type: "Beaconing", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", DstPort: "443",
			Score: 88, Severity: model.SevCritical, Status: model.StatusOpen,
			Timestamp: "2026-05-18 09:00:00",
			TSScore:   0.92, DSScore: 0.81, HistScore: 0.75, DurScore: 0.88,
			MeanInterval: 47, MedianInterval: 46, Jitter: 0.064, SampleSize: 312,
			JA3: "771,4865", JA4: "t13d1516h2_x_y"},
		{ID: 2, Type: "Suspicious URL", SrcIP: "10.0.0.2", DstIP: "2.2.2.2", DstPort: "80",
			Score: 70, Severity: model.SevMedium, Status: model.StatusOpen,
			Timestamp: "2026-05-18 09:01:00"},
	})

	baseHeader := []string{"score", "severity", "type", "src_ip", "dst_ip", "dst_port", "timestamp", "detail", "source_file", "sensor", "status", "analyst", "analyst_note"}

	read := func(url string) [][]string {
		t.Helper()
		rec := httptest.NewRecorder()
		s.handleExportCSV(rec, httptest.NewRequest("GET", url, nil))
		rows, err := csv.NewReader(rec.Body).ReadAll()
		if err != nil {
			t.Fatalf("parse CSV from %s: %v", url, err)
		}
		return rows
	}

	// (1) Default export — unchanged 13-col header, every finding.
	def := read("/api/export/csv")
	if len(def) != 3 { // header + 2 findings
		t.Fatalf("default export: %d rows, want 3 (header+2)", len(def))
	}
	if !equalRow(def[0], baseHeader) {
		t.Errorf("default header = %v; want the historical 13-col base %v", def[0], baseHeader)
	}

	// (2) Beacon-scoped — wide header, only the beacon row, triage tail.
	b := read("/api/export/csv?type=beacons")
	if len(b) != 2 { // header + 1 beacon (Suspicious URL excluded)
		t.Fatalf("beacon export: %d rows, want 2 (header+1 beacon)", len(b))
	}
	wantHeader := append(append([]string{}, baseHeader...),
		"ts_score", "ds_score", "hist_score", "dur_score",
		"mean_interval", "median_interval", "jitter", "sample_size", "ja3", "ja4")
	if !equalRow(b[0], wantHeader) {
		t.Fatalf("beacon header = %v; want base+triage %v", b[0], wantHeader)
	}
	// Base columns 0..12 must still align with the default schema.
	if b[1][2] != "Beaconing" {
		t.Errorf("beacon row type col = %q; want Beaconing", b[1][2])
	}
	// Triage tail begins at index len(baseHeader).
	tail := b[1][len(baseHeader):]
	wantTail := []string{"0.92", "0.81", "0.75", "0.88", "47", "46", "0.064", "312", "771,4865", "t13d1516h2_x_y"}
	if !equalRow(tail, wantTail) {
		t.Errorf("triage tail = %v; want %v", tail, wantTail)
	}
}

func equalRow(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
