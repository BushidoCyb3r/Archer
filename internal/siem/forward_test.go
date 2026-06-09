package siem

import (
	"net"
	"testing"
	"time"
)

func TestSend_DeliversDatagram(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if err := Send(pc.LocalAddr().String(), "hello-cef"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 1024)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "hello-cef" {
		t.Errorf("got %q, want %q", got, "hello-cef")
	}
}
