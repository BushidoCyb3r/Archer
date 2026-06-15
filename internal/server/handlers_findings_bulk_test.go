package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestHandleFindingsBulk pins the bulk ack/escalate/dismiss/open endpoint:
// explicit-id and filter-scoped target resolution, action→status mapping, the
// per-finding prior-status payload the undo toast relies on, escalate forwarding
// to the SIEM without running vendor enrichment, and the undo round-trip that
// replays prior statuses through the same endpoint.
func TestHandleFindingsBulk(t *testing.T) {
	seed := func(s *Server) {
		s.store.SetFindings([]model.Finding{
			{ID: 1, Type: "Beacon", SrcIP: "10.0.0.1", DstIP: "203.0.113.5", DstPort: "443", Severity: model.SevHigh},
			{ID: 2, Type: "Beacon", SrcIP: "10.0.0.2", DstIP: "203.0.113.5", DstPort: "443", Severity: model.SevCritical},
			// Different destination, and already escalated — must be untouched by
			// a dst_ip-filtered or id-targeted action that doesn't include it.
			{ID: 3, Type: "Data Exfiltration", SrcIP: "10.0.0.3", DstIP: "198.51.100.7", DstPort: "8080", Severity: model.SevMedium, Status: model.StatusEscalated},
		})
	}
	post := func(s *Server, url, body string) *httptest.ResponseRecorder {
		req := withUser(httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(body)), model.RoleAnalyst)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.handleFindingsBulk(rec, req)
		return rec
	}
	statuses := func(s *Server) map[int]model.Status {
		m := map[int]model.Status{}
		for _, f := range s.store.GetFindings() {
			m[f.ID] = f.Status
		}
		return m
	}

	t.Run("ids mode acknowledges and returns prior", func(t *testing.T) {
		s := newAuditTestServer(t)
		seed(s)
		rec := post(s, "/api/findings/bulk", `{"action":"ack","ids":[1,2],"note":"triaged"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Affected int `json:"affected"`
			Prior    []struct {
				ID     int    `json:"id"`
				Status string `json:"status"`
			} `json:"prior"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if resp.Affected != 2 {
			t.Errorf("affected = %d, want 2", resp.Affected)
		}
		st := statuses(s)
		if st[1] != model.StatusAcknowledged || st[2] != model.StatusAcknowledged {
			t.Errorf("ids 1,2 not acknowledged: %v", st)
		}
		if st[3] != model.StatusEscalated {
			t.Errorf("id 3 must be untouched, got %q", st[3])
		}
		if len(resp.Prior) != 2 {
			t.Fatalf("prior len = %d, want 2", len(resp.Prior))
		}
		for _, p := range resp.Prior {
			if model.Status(p.Status) != model.StatusOpen {
				t.Errorf("prior status for id %d = %q, want open", p.ID, p.Status)
			}
		}
	})

	t.Run("filter mode dismisses the matching set", func(t *testing.T) {
		s := newAuditTestServer(t)
		seed(s)
		// No ids → resolve from the filter query. dst_ip matches ids 1,2 only.
		rec := post(s, "/api/findings/bulk?dst_ip=203.0.113.5", `{"action":"dismiss"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code %d: %s", rec.Code, rec.Body.String())
		}
		st := statuses(s)
		if st[1] != model.StatusDismissed || st[2] != model.StatusDismissed {
			t.Errorf("filter-scoped dismiss did not apply: %v", st)
		}
		if st[3] == model.StatusDismissed {
			t.Error("id 3 (different destination) must not be dismissed")
		}
	})

	t.Run("invalid action is rejected", func(t *testing.T) {
		s := newAuditTestServer(t)
		seed(s)
		if rec := post(s, "/api/findings/bulk", `{"action":"archive","ids":[1]}`); rec.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", rec.Code)
		}
	})

	t.Run("escalate forwards to SIEM without enrichment", func(t *testing.T) {
		s := newAuditTestServer(t)
		seed(s)
		cfg := s.store.GetConfig()
		cfg.SIEMEnabled = true
		cfg.SIEMHost = "siem.example"
		s.store.SetConfig(cfg)
		fwd := make(chan string, 8)
		s.siemSend = func(addr, line string) error { fwd <- line; return nil }

		rec := post(s, "/api/findings/bulk", `{"action":"esc","ids":[1,2]}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code %d: %s", rec.Code, rec.Body.String())
		}
		st := statuses(s)
		if st[1] != model.StatusEscalated || st[2] != model.StatusEscalated {
			t.Errorf("ids 1,2 not escalated: %v", st)
		}
		// Both newly-escalated findings forward to the SIEM (best-effort
		// goroutines). No vendor enrichment is run — the handler never calls
		// runTIEscalation on this path.
		for i := 0; i < 2; i++ {
			select {
			case <-fwd:
			case <-time.After(2 * time.Second):
				t.Fatal("bulk escalate did not forward to the SIEM")
			}
		}
	})

	t.Run("undo restores each finding's prior status", func(t *testing.T) {
		s := newAuditTestServer(t)
		seed(s)
		// Acknowledge 1,2 (prior status open), then replay open as undo would.
		if rec := post(s, "/api/findings/bulk", `{"action":"ack","ids":[1,2]}`); rec.Code != http.StatusOK {
			t.Fatalf("setup ack: %s", rec.Body.String())
		}
		if st := statuses(s); st[1] != model.StatusAcknowledged {
			t.Fatalf("setup ack did not apply: %v", st)
		}
		rec := post(s, "/api/findings/bulk", `{"action":"open","ids":[1,2]}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("undo code %d: %s", rec.Code, rec.Body.String())
		}
		st := statuses(s)
		if st[1] != model.StatusOpen || st[2] != model.StatusOpen {
			t.Errorf("undo did not reopen ids 1,2: %v", st)
		}
	})
}
