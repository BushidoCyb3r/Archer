package llm

import (
	"strings"
	"testing"
)

func TestHostClass(t *testing.T) {
	r := NewRedactor([]string{"203.0.113.0/24"})
	cases := []struct {
		ip   string
		want string
	}{
		{"172.16.10.255", "broadcast"},           // the case that defeated the first prompt
		{"192.168.1.255", "broadcast"},           // /24 directed broadcast
		{"255.255.255.255", "limited-broadcast"}, // limited broadcast
		{"224.0.0.251", "multicast"},             // mDNS group
		{"239.255.255.250", "multicast"},         // SSDP group
		{"127.0.0.1", "loopback"},                // loopback
		{"169.254.1.1", "link-local"},            // IPv4 link-local
		{"10.4.4.4", "internal host"},            // RFC1918 host
		{"203.0.113.9", "internal host"},         // org CIDR → internal
		{"8.8.8.8", "external host"},             // public host
		{"10.4.4.0", "network/subnet"},           // network address
		{"ff02::fb", "IPv6 multicast"},           // IPv6 multicast
		{"fe80::1", "IPv6 link-local"},           // IPv6 link-local
		{"not-an-ip", ""},                        // unparseable → empty
	}
	for _, c := range cases {
		got := r.HostClass(c.ip)
		if c.want == "" {
			if got != "" {
				t.Errorf("HostClass(%q) = %q, want empty", c.ip, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("HostClass(%q) = %q, want it to mention %q", c.ip, got, c.want)
		}
	}
}
