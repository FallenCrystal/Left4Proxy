package discover

import (
	"net"
	"reflect"
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
		{"example.com:27015", 27014, "example.com:27015"},
		{"[240e:390:1234::1]", 27014, "[240e:390:1234::1]:27014"},
	}

	for _, c := range cases {
		got := FormatEndpoint(c.host, c.port)
		if got != c.expected {
			t.Errorf("FormatEndpoint(%q, %d) = %q, want %q", c.host, c.port, got, c.expected)
		}
	}
}

func TestNormalizeEndpointRejectsAmbiguousOrInvalidValues(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "bare ipv4", value: "192.0.2.10", want: "192.0.2.10:27014"},
		{name: "bare ipv6", value: "2001:db8::10", want: "[2001:db8::10]:27014"},
		{name: "dns with port", value: "game.example:28000", want: "game.example:28000"},
		{name: "bracketed ipv6", value: "[2001:db8::10]", want: "[2001:db8::10]:27014"},
		{name: "empty host", value: ":27014", wantErr: true},
		{name: "empty port", value: "game.example:", wantErr: true},
		{name: "named port", value: "game.example:http", wantErr: true},
		{name: "out of range", value: "game.example:70000", wantErr: true},
		{name: "invalid ipv4", value: "192.0.2.999", wantErr: true},
		{name: "ipv4 with zone", value: "192.0.2.10%eth0", wantErr: true},
		{name: "bracketed ipv4 with zone", value: "[192.0.2.10%eth0]", wantErr: true},
		{name: "url", value: "https://game.example:27014", wantErr: true},
		{name: "userinfo", value: "user@game.example:27014", wantErr: true},
		{name: "path in host", value: "game/example:27014", wantErr: true},
		{name: "ambiguous host port", value: "game.example:27014:1", wantErr: true},
		{name: "metadata pipe delimiter", value: "game.example|relay:27014", wantErr: true},
		{name: "metadata comma delimiter", value: "game.example,other:27014", wantErr: true},
		{name: "oversized host", value: strings.Repeat("a", maxEndpointHostLength+1), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeEndpoint(tc.value, 27014)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeEndpoint(%q) = %q, want an error", tc.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeEndpoint(%q) failed: %v", tc.value, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeEndpoint(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestNormalizeEndpointsDeduplicatesAndReportsIndex(t *testing.T) {
	got, err := NormalizeEndpoints([]string{"example.com", "example.com:27014", "", "[2001:db8::1]"}, 27014)
	if err != nil {
		t.Fatalf("NormalizeEndpoints failed: %v", err)
	}
	if want := []string{"example.com:27014", "[2001:db8::1]:27014"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized endpoints = %#v, want %#v", got, want)
	}
	_, err = NormalizeEndpoints([]string{"ok.example", "bad.example:0"}, 27014)
	if err == nil || !strings.Contains(err.Error(), "public endpoint 1") {
		t.Fatalf("invalid endpoint error = %v, want indexed error", err)
	}
}

func TestIsGlobalUnicastIPv6(t *testing.T) {
	cases := []struct {
		ip       string
		expected bool
	}{
		{"240e:390:1234::1", true},
		{"2001:da8::1", true},
		{"fe80::1", false},           // Link-local
		{"fc00::1", false},           // Unique local ULA
		{"fd12:3456:789a::1", false}, // ULA
		{"::1", false},               // Loopback
		{"::", false},                // Unspecified
		{"2001:db8::1", false},       // Doc
		{"192.168.1.1", false},       // IPv4
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
