package stun

import (
	"context"
	"net"
	"testing"
	"time"
)

func startMockStunServer(t *testing.T, mappedIP net.IP, mappedPort int) (*net.UDPConn, *net.UDPAddr) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve mock stun addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen mock stun: %v", err)
	}

	go func() {
		buf := make([]byte, 1024)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if IsStunResponse(buf[:n]) || (len(buf[:n]) >= stunHeaderLen) {
				resp := buildResponse(mappedIP, mappedPort)
				// Copy transaction ID from request
				if n >= 20 {
					copy(resp[8:20], buf[8:20])
				}
				_, _ = conn.WriteToUDP(resp, clientAddr)
			}
		}
	}()

	return conn, conn.LocalAddr().(*net.UDPAddr)
}

func TestDetectNATMappingCone(t *testing.T) {
	mock1, addr1 := startMockStunServer(t, net.IPv4(203, 0, 113, 10), 40000)
	defer mock1.Close()
	mock2, addr2 := startMockStunServer(t, net.IPv4(203, 0, 113, 10), 40000)
	defer mock2.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen client udp: %v", err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info, err := DetectNATMapping(ctx, clientConn, addr1, addr2, 1*time.Second)
	if err != nil {
		t.Fatalf("DetectNATMapping failed: %v", err)
	}

	if info.Behavior != MappingEndpointIndependent {
		t.Fatalf("expected Cone NAT, got %v", info.Behavior)
	}
	if info.PortDelta != 0 {
		t.Fatalf("expected PortDelta 0, got %d", info.PortDelta)
	}
}

func TestDetectNATMappingSymmetric(t *testing.T) {
	mock1, addr1 := startMockStunServer(t, net.IPv4(203, 0, 113, 10), 40000)
	defer mock1.Close()
	mock2, addr2 := startMockStunServer(t, net.IPv4(203, 0, 113, 10), 40002)
	defer mock2.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen client udp: %v", err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info, err := DetectNATMapping(ctx, clientConn, addr1, addr2, 1*time.Second)
	if err != nil {
		t.Fatalf("DetectNATMapping failed: %v", err)
	}

	if info.Behavior != MappingAddressOrPortDependent {
		t.Fatalf("expected Symmetric NAT, got %v", info.Behavior)
	}
	if info.PortDelta != 2 {
		t.Fatalf("expected PortDelta 2, got %d", info.PortDelta)
	}
}
