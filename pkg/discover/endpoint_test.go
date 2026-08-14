package discover

import (
	"net"
	"strings"
	"testing"
)

func TestFormatEndpoint(t *testing.T) {
	cases := []struct {
		host     string
		port     int
		expected string
	}{
		{"192.168.1.100", 27014, "192.168.1.100:27014"},
		{"240e:390:1234::1", 27014, "[240e:390:1234::1]:27014"},
		{"[240e:390:1234::1]:27014", 27014, "[240e:390:1234::1]:27014"},
		{"example.com", 27014, "example.com:27014"},
	}

	for _, c := range cases {
		got := FormatEndpoint(c.host, c.port)
		if got != c.expected {
			t.Errorf("FormatEndpoint(%q, %d) = %q, want %q", c.host, c.port, got, c.expected)
		}
	}
}

func TestIsGlobalUnicastIPv6(t *testing.T) {
	cases := []struct {
		ip       string
		expected bool
	}{
		{"240e:390:1234::1", true},
		{"2001:da8::1", true},
		{"fe80::1", false},        // Link-local
		{"fc00::1", false},        // Unique local ULA
		{"fd12:3456:789a::1", false}, // ULA
		{"::1", false},            // Loopback
		{"::", false},             // Unspecified
		{"2001:db8::1", false},    // Doc
		{"192.168.1.1", false},    // IPv4
	}

	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		got := isGlobalUnicastIPv6(ip)
		if got != c.expected {
			t.Errorf("isGlobalUnicastIPv6(%s) = %v, want %v", c.ip, got, c.expected)
		}
	}
}

func TestGatherHostCandidatesDoesNotPanic(t *testing.T) {
	lan4, g6 := GatherHostCandidates(27014)
	for _, l := range lan4 {
		if !strings.Contains(l, ":27014") {
			t.Errorf("LAN candidate %q should end with :27014", l)
		}
	}
	for _, g := range g6 {
		if !strings.Contains(g, ":27014") {
			t.Errorf("IPv6 candidate %q should end with :27014", g)
		}
	}
	all := GatherAllLocalCandidates(27014)
	if len(all) != len(lan4)+len(g6) {
		t.Errorf("all candidates count %d != lan4 count %d + g6 count %d", len(all), len(lan4), len(g6))
	}
}
