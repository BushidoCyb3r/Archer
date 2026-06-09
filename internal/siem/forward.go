package siem

import (
	"net"
	"time"
)

// Send writes one CEF datagram to a UDP SIEM endpoint (addr is "host:port").
// Best-effort and fire-and-forget — UDP carries no delivery confirmation.
// A 2s dial timeout bounds the rare hostname-resolution case; an IP target
// (the expected config) dials instantly.
func Send(addr, line string) error {
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write([]byte(line))
	return err
}
