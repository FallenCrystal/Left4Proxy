package discover

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const maxEndpointHostLength = 253

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
	if endpoint, err := NormalizeEndpoint(host, port); err == nil {
		return endpoint
	}
	// Keep this helper's historical no-error API for callers that use it only
	// for display.  Runtime configuration paths should use NormalizeEndpoint so
	// malformed values are reported instead of being silently advertised.
	host = strings.TrimSpace(host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// NormalizeEndpoint converts an endpoint that may omit its port into the
// canonical host:port form accepted by net.ResolveUDPAddr.  Public endpoint
// configuration historically documented bare IPs and host names, while the
// wire protocol always carries host:port values.  Keeping the normalization in
// one place prevents a bare IPv6 address from being mistaken for a malformed
// host:port pair and makes invalid ports fail loudly.
func NormalizeEndpoint(raw string, defaultPort int) (string, error) {
	if defaultPort < 1 || defaultPort > 65535 {
		return "", fmt.Errorf("default port %d is outside 1..65535", defaultPort)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("endpoint is empty")
	}
	if strings.ContainsAny(raw, "\r\n\t") {
		return "", fmt.Errorf("endpoint contains control whitespace")
	}

	// A complete host:port value is parsed first.  SplitHostPort handles both
	// DNS/IPv4 values and bracketed IPv6 values without treating an IPv6 colon as
	// a port separator.
	if host, portText, err := net.SplitHostPort(raw); err == nil {
		if host == "" {
			return "", fmt.Errorf("endpoint %q has no host", raw)
		}
		if err := validateEndpointHost(host); err != nil {
			return "", fmt.Errorf("endpoint %q: %w", raw, err)
		}
		if strings.HasPrefix(raw, "[") && net.ParseIP(host) == nil && !validIPv6ZoneLiteral(host) {
			return "", fmt.Errorf("endpoint %q uses brackets around a non-IPv6 host", raw)
		}
		port, err := parseEndpointPort(portText)
		if err != nil {
			return "", fmt.Errorf("endpoint %q: %w", raw, err)
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}

	// Brackets without a port are a useful spelling for an IPv6 literal.  Strip
	// them before adding the configured port; a bracketed DNS name is rejected by
	// net.ParseIP below and should not be silently accepted.
	host := raw
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") || len(host) < 3 {
			return "", fmt.Errorf("endpoint %q has malformed IPv6 brackets", raw)
		}
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return "", fmt.Errorf("endpoint %q has no host", raw)
	}
	if err := validateEndpointHost(host); err != nil {
		return "", fmt.Errorf("endpoint %q: %w", raw, err)
	}
	if strings.Contains(host, ":") {
		// An unbracketed value containing a colon is only valid as an IPv6
		// literal (optionally with a zone).  A value such as "host:port" gets a
		// clear error instead of being advertised in an unparsable form.
		if net.ParseIP(host) == nil && !validIPv6ZoneLiteral(host) {
			return "", fmt.Errorf("endpoint %q has an unbracketed host:port or invalid IPv6 address", raw)
		}
	}
	if strings.HasPrefix(raw, "[") && net.ParseIP(host) == nil && !validIPv6ZoneLiteral(host) {
		return "", fmt.Errorf("endpoint %q uses brackets around a non-IPv6 host", raw)
	}
	return net.JoinHostPort(host, strconv.Itoa(defaultPort)), nil
}

// NormalizeEndpoints normalizes, deduplicates, and validates a list of
// advertised endpoints.  The first invalid value is returned with its index so
// startup can identify the exact configuration entry that needs correction.
func NormalizeEndpoints(raw []string, defaultPort int) ([]string, error) {
	result := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for i, value := range raw {
		if strings.TrimSpace(value) == "" {
			continue
		}
		normalized, err := NormalizeEndpoint(value, defaultPort)
		if err != nil {
			return nil, fmt.Errorf("public endpoint %d (%q): %w", i, value, err)
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func parseEndpointPort(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("port is empty")
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %q is outside 1..65535", value)
	}
	return port, nil
}

// validIPv6ZoneLiteral accepts the scoped-link-local spelling that
// net.ParseIP intentionally does not parse.  It is still passed through
// net.JoinHostPort, which preserves the zone in the canonical endpoint.
func validIPv6ZoneLiteral(host string) bool {
	parts := strings.SplitN(host, "%", 2)
	if len(parts) != 2 || parts[1] == "" {
		return false
	}
	ip := net.ParseIP(parts[0])
	return ip != nil && ip.To4() == nil
}

func validateEndpointHost(host string) error {
	if host == "" {
		return fmt.Errorf("endpoint has no host")
	}
	if len(host) > maxEndpointHostLength {
		return fmt.Errorf("endpoint host exceeds %d bytes", maxEndpointHostLength)
	}
	// Endpoint values are also serialized in the authenticated handshake's
	// comma/pipe-separated metadata fields. Reject those delimiters here so a
	// configured hostname cannot inject a second candidate or a fake metadata
	// field even if a downstream resolver happens to accept it.
	if strings.ContainsAny(host, "[]/@\\?#|,\r\n\t \f\v") {
		return fmt.Errorf("endpoint host contains invalid characters")
	}
	if strings.Contains(host, "%") && !validIPv6ZoneLiteral(host) {
		return fmt.Errorf("endpoint host contains an invalid IPv6 zone")
	}
	if looksLikeIPv4Literal(host) && net.ParseIP(host) == nil {
		return fmt.Errorf("endpoint host contains an invalid IPv4 literal")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil && !validIPv6ZoneLiteral(host) {
		return fmt.Errorf("endpoint host contains an invalid IPv6 literal")
	}
	return nil
}

func looksLikeIPv4Literal(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	for _, ch := range host {
		if (ch < '0' || ch > '9') && ch != '.' {
			return false
		}
	}
	return true
}
