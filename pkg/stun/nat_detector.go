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
	if conn == nil {
		return nil, errors.New("udp connection is nil")
	}
	if server1 == nil || server2 == nil {
		return nil, errors.New("two distinct STUN server addresses are required")
	}

	info := &NATMappingInfo{
		Behavior: MappingUnknown,
	}

	req1 := BuildBindingRequest()
	req2 := BuildBindingRequest()

	// Send requests to both STUN servers
	if _, err := conn.WriteToUDP(req1, server1); err != nil {
		return nil, fmt.Errorf("failed to send STUN request to server 1: %w", err)
	}
	if _, err := conn.WriteToUDP(req2, server2); err != nil {
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

		if !IsStunResponse(buf[:n]) {
			continue
		}

		reflected, err := ParseBindingResponse(buf[:n])
		if err != nil {
			continue
		}

		// Match source with server1 or server2
		if src.IP.Equal(server1.IP) && src.Port == server1.Port {
			info.PrimaryAddr = reflected
		} else if src.IP.Equal(server2.IP) && src.Port == server2.Port {
			info.SecondaryAddr = reflected
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
