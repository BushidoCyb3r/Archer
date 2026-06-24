package llm

import "net"

// HostClass returns a short, non-identifying structural description of an IP
// address — internal vs external plus any special role (broadcast, multicast,
// network, loopback, link-local). It never echoes the address itself, so it is
// safe to add to the evidence alongside the redacted hosts: it restores the
// discriminating signal the redactor strips (e.g. "this destination is a subnet
// broadcast address" — the tell that a beacon is benign discovery traffic, not
// C2) without revealing the real topology.
//
// Returns "" for an unparseable string so callers can skip the line.
func (r *Redactor) HostClass(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.Equal(net.IPv4bcast) {
		return "IPv4 limited-broadcast address (255.255.255.255)"
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] >= 224 && ip4[0] <= 239:
			return "IPv4 multicast address"
		case ip4[0] == 127:
			return "IPv4 loopback address"
		case ip4[0] == 169 && ip4[1] == 254:
			return "IPv4 link-local address"
		case ip4[3] == 255:
			return "IPv4 broadcast-style address (host octet .255 — typically a /24 directed broadcast)"
		case ip4[3] == 0:
			return "IPv4 network/subnet address (host octet .0)"
		}
	} else {
		switch {
		case ip[0] == 0xff:
			return "IPv6 multicast address"
		case ip[0] == 0xfe && ip[1]&0xc0 == 0x80:
			return "IPv6 link-local address"
		}
	}
	if r.isInternal(ip) {
		return "internal host"
	}
	return "external host"
}
