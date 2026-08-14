package discover

import (
	"fmt"
	"net"
	"strings"
)

// EndpointType classifies candidate endpoints.
type EndpointType string

const (
	EndpointIPv4LAN    EndpointType = "IPv4_LAN"
	EndpointIPv6Global EndpointType = "IPv6_Global"
)

// CandidateEndpoint represents a discovered local network endpoint.
type CandidateEndpoint struct {
	Addr string
	Type EndpointType
}

// GatherHostCandidates inspects local network interfaces and collects:
// 1. IPv4 LAN / Private addresses
// 2. IPv6 Global Unicast addresses
func GatherHostCandidates(port int) (ipv4LAN []string, ipv6Global []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}

	seen4 := make(map[string]bool)
	seen6 := make(map[string]bool)

	for _, iface := range ifaces {
		// Ignore interfaces that are down or loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				// IPv4 LAN candidate
				if ip4.IsPrivate() {
					cand := fmt.Sprintf("%s:%d", ip4.String(), port)
					if !seen4[cand] {
						seen4[cand] = true
						ipv4LAN = append(ipv4LAN, cand)
					}
				}
			} else {
				// IPv6 Global candidate
				if isGlobalUnicastIPv6(ip) {
					cand := fmt.Sprintf("[%s]:%d", ip.String(), port)
					if !seen6[cand] {
						seen6[cand] = true
						ipv6Global = append(ipv6Global, cand)
					}
				}
			}
		}
	}

	return ipv4LAN, ipv6Global
}

// GatherAllLocalCandidates returns a merged list of local IPv4 LAN and IPv6 Global candidates.
func GatherAllLocalCandidates(port int) []string {
	lan4, g6 := GatherHostCandidates(port)
	res := make([]string, 0, len(lan4)+len(g6))
	res = append(res, lan4...)
	res = append(res, g6...)
	return res
}

// isGlobalUnicastIPv6 checks whether an IP is a true globally routable IPv6 unicast address
// (excluding link-local fe80::/10, unique local fc00::/7, documentation 2001:db8::/32, etc.)
func isGlobalUnicastIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	// Check for unique local (ULA fc00::/7)
	if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
		return false
	}
	// Check for link-local (fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// Check for documentation prefix 2001:db8::/32
	if len(ip) == 16 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	return true
}

// FormatEndpoint safely formats host and port for both IPv4 and IPv6.
func FormatEndpoint(host string, port int) string {
	host = strings.TrimSpace(host)
	// If already in [host]:port format, return as is
	if strings.Contains(host, ":") && strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
		return host
	}
	// If host contains colons (IPv6 without brackets), enclose in brackets
	if strings.Contains(host, ":") && !strings.Contains(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
