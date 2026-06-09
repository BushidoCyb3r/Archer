package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
)

func TestForwardEscalationToSIEM(t *testing.T) {
	var sent []string
	s := &Server{siemSend: func(addr, line string) error { sent = append(sent, line); return nil }}
	f := model.Finding{ID: 42, Type: "Beacon", Score: 98, SrcIP: "10.0.0.5",
		DstIP: "8.8.8.8", DstPort: "443", Status: model.StatusOpen}

	// enabled + transition into escalated -> exactly one send
	s.forwardEscalationToSIEM(config.Config{SIEMEnabled: true, SIEMHost: "10.0.0.9", SIEMPort: 9003},
		f, "alice", "https://archer/?finding=42")
	if len(sent) != 1 {
		t.Fatalf("want 1 send, got %d", len(sent))
	}
	if !strings.Contains(sent[0], "externalId=42") {
		t.Errorf("missing externalId: %s", sent[0])
	}
	if !strings.Contains(sent[0], "cs4Label=ArcherAnalyst cs4=alice") {
		t.Errorf("missing analyst: %s", sent[0])
	}

	// disabled -> no send
	sent = nil
	s.forwardEscalationToSIEM(config.Config{SIEMEnabled: false, SIEMHost: "10.0.0.9"}, f, "alice", "u")
	if len(sent) != 0 {
		t.Fatalf("disabled must not send, got %d", len(sent))
	}

	// host empty -> no send
	s.forwardEscalationToSIEM(config.Config{SIEMEnabled: true, SIEMHost: ""}, f, "alice", "u")
	if len(sent) != 0 {
		t.Fatalf("empty host must not send, got %d", len(sent))
	}

	// already escalated -> no re-send
	already := f
	already.Status = model.StatusEscalated
	s.forwardEscalationToSIEM(config.Config{SIEMEnabled: true, SIEMHost: "10.0.0.9"}, already, "alice", "u")
	if len(sent) != 0 {
		t.Fatalf("already-escalated must not re-send, got %d", len(sent))
	}

	// send error -> swallowed (no panic; function returns normally)
	s.siemSend = func(addr, line string) error { return errors.New("boom") }
	s.forwardEscalationToSIEM(config.Config{SIEMEnabled: true, SIEMHost: "10.0.0.9"}, f, "alice", "u")
}
