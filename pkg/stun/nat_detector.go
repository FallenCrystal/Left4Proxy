package stun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// NATMappingBehavior describes how the NAT device maps internal endpoints to external ones.
type NATMappingBehavior string

const (
	// MappingEndpointIndependent (Cone NAT): The NAT uses the same external endpoint for all destinations.
	MappingEndpointIndependent NATMappingBehavior = "Endpoint-Independent (Cone)"
	// MappingAddressOrPortDependent (Symmetric NAT): The NAT assigns a different external endpoint for different destinations.
	MappingAddressOrPortDependent NATMappingBehavior = "Address/Port-Dependent (Symmetric)"
	// MappingUnknown: Unable to determine NAT mapping behavior (e.g. timeout or single STUN response).
	MappingUnknown NATMappingBehavior = "Unknown"
)

// NATMappingInfo contains the detected NAT behavior and port delta.
type NATMappingInfo struct {
	Behavior      NATMappingBehavior
	PrimaryAddr   *net.UDPAddr
	SecondaryAddr *net.UDPAddr
	PortDelta     int
}

// DetectNATMapping queries two distinct STUN servers from the same UDP socket to determine
// whether the NAT employs Endpoint-Independent Mapping (Cone) or Symmetric Mapping.
func DetectNATMapping(ctx context.Context, conn *net.UDPConn, server1, server2 *net.UDPAddr, timeout time.Duration) (*NATMappingInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return nil, errors.New("udp connection is nil")
	}
	if server1 == nil || server2 == nil {
		return nil, errors.New("two distinct STUN server addresses are required")
	}
	if sameUDPAddr(server1, server2) {
		return nil, errors.New("two distinct STUN server addresses are required")
	}
	if timeout <= 0 {
		return nil, errors.New("STUN detection timeout must be positive")
	}

	info := &NATMappingInfo{
		Behavior: MappingUnknown,
	}

	validator := NewValidator()
	// Send independently identified requests to both STUN servers.
	if err := validator.SendBindingRequest(conn, server1); err != nil {
		return nil, fmt.Errorf("failed to send STUN request to server 1: %w", err)
	}
	if err := validator.SendBindingRequest(conn, server2); err != nil {
		return nil, fmt.Errorf("failed to send STUN request to server 2: %w", err)
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return info, ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		validated, err := validator.Accept(buf[:n], src)
		if err != nil {
			continue
		}

		if sameUDPAddr(src, server1) {
			info.PrimaryAddr = validated.Reflected
		} else if sameUDPAddr(src, server2) {
			info.SecondaryAddr = validated.Reflected
		}

		if info.PrimaryAddr != nil && info.SecondaryAddr != nil {
			break
		}
	}

	if info.PrimaryAddr == nil && info.SecondaryAddr == nil {
		return info, errors.New("no STUN response received from either server")
	}

	// If only one responded, record the endpoint and return Unknown behavior
	if info.PrimaryAddr == nil || info.SecondaryAddr == nil {
		return info, nil
	}

	// Compare the two reflected endpoints
	if info.PrimaryAddr.IP.Equal(info.SecondaryAddr.IP) && info.PrimaryAddr.Port == info.SecondaryAddr.Port {
		info.Behavior = MappingEndpointIndependent
		info.PortDelta = 0
	} else {
		info.Behavior = MappingAddressOrPortDependent
		info.PortDelta = info.SecondaryAddr.Port - info.PrimaryAddr.Port
	}

	return info, nil
}

// DetectClientNAT opens an ephemeral UDP socket and queries multiple public STUN servers
// to detect the local network's NAT mapping behavior (Cone NAT vs Symmetric NAT).
func DetectClientNAT(ctx context.Context, customStunServer string, timeout time.Duration) (*NATMappingInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return nil, errors.New("STUN detection timeout must be positive")
	}
	stunCandidates := []string{}
	if customStunServer != "" {
		stunCandidates = append(stunCandidates, customStunServer)
	}
	stunCandidates = append(stunCandidates, DefaultStunServers...)
	addrs := ResolveStunServers(stunCandidates)
	if len(addrs) == 0 {
		return nil, errors.New("no STUN servers could be resolved")
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create probe socket: %w", err)
	}
	defer conn.Close()

	if len(addrs) == 1 {
		// With one reachable STUN server we can still report a validated single
		// reflection, but mapping behavior is necessarily unknown. Do not send
		// two transactions to the same destination and pretend they are distinct
		// observations.
		validator := NewValidator()
		if err := validator.SendBindingRequest(conn, addrs[0]); err != nil {
			return nil, fmt.Errorf("failed to send STUN request: %w", err)
		}
		deadline := time.Now().Add(timeout)
		buf := make([]byte, 2048)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return &NATMappingInfo{Behavior: MappingUnknown}, ctx.Err()
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			validated, err := validator.Accept(buf[:n], src)
			if err != nil {
				continue
			}
			return &NATMappingInfo{Behavior: MappingUnknown, PrimaryAddr: validated.Reflected}, nil
		}
		return &NATMappingInfo{Behavior: MappingUnknown}, errors.New("no STUN response received from server")
	}

	validator := NewValidator()
	if err := validator.SendMultiBindingRequests(conn, addrs); err != nil {
		return nil, fmt.Errorf("failed to send STUN requests: %w", err)
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	reflections := make(map[string]*net.UDPAddr)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		validated, err := validator.Accept(buf[:n], src)
		if err != nil {
			continue
		}

		reflections[validated.Server.String()] = validated.Reflected
		if len(reflections) >= 2 {
			break
		}
	}

	if len(reflections) == 0 {
		return nil, errors.New("no STUN response received from servers")
	}

	info := &NATMappingInfo{
		Behavior: MappingUnknown,
	}

	// Preserve the configured destination order instead of ranging over the map;
	// stable Primary/Secondary assignment makes PortDelta and diagnostics
	// reproducible across runs.
	var endpoints []*net.UDPAddr
	for _, server := range addrs {
		if ep, ok := reflections[server.String()]; ok {
			endpoints = append(endpoints, ep)
		}
	}

	info.PrimaryAddr = endpoints[0]
	if len(endpoints) == 1 {
		return info, nil
	}

	info.SecondaryAddr = endpoints[1]

	if info.PrimaryAddr.IP.Equal(info.SecondaryAddr.IP) && info.PrimaryAddr.Port == info.SecondaryAddr.Port {
		info.Behavior = MappingEndpointIndependent
		info.PortDelta = 0
	} else {
		info.Behavior = MappingAddressOrPortDependent
		info.PortDelta = info.SecondaryAddr.Port - info.PrimaryAddr.Port
	}

	return info, nil
}

// FormatNATSummary returns a concise, human-friendly summary string of the NAT mapping behavior.
func FormatNATSummary(info *NATMappingInfo) string {
	if info == nil {
		return "Detecting / Not tested"
	}
	switch info.Behavior {
	case MappingEndpointIndependent:
		if info.PrimaryAddr != nil {
			return fmt.Sprintf("Cone NAT (NAT 1-3, Endpoint-Independent) [Public IP: %s]", info.PrimaryAddr.IP.String())
		}
		return "Cone NAT (NAT 1-3, Endpoint-Independent) [Direct/Punch Supported]"
	case MappingAddressOrPortDependent:
		deltaStr := ""
		if info.PortDelta != 0 {
			deltaStr = fmt.Sprintf(", Delta: %+d", info.PortDelta)
		}
		return fmt.Sprintf("Symmetric NAT (NAT 4, Address/Port-Dependent%s) [Relay Recommended]", deltaStr)
	default:
		if info.PrimaryAddr != nil {
			return fmt.Sprintf("Single Reflection (%s) [Behavior Unknown]", info.PrimaryAddr.String())
		}
		return "Unknown / STUN unreachable"
	}
}
