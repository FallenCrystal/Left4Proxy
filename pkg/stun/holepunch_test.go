package stun

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"left4proxy/pkg/protocol"
)

func TestHolePuncherSendBurstAndStop(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen server udp: %v", err)
	}
	defer serverConn.Close()

	var receivedCount atomic.Int32
	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt, err := protocol.Unmarshal(buf[:n])
			if err == nil && pkt.Cmd == protocol.CmdStunProbe {
				receivedCount.Add(1)
			}
		}
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen client udp: %v", err)
	}
	defer clientConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	hp := NewHolePuncher(12345, clientConn, serverAddr)
	hp.SendBurst(5, 10*time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	if count := receivedCount.Load(); count < 5 {
		t.Fatalf("expected at least 5 burst probes, got %d", count)
	}

	hp.Stop()
}

func TestSendBurstProbesStandalone(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen server udp: %v", err)
	}
	defer serverConn.Close()

	var receivedCount atomic.Int32
	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt, err := protocol.Unmarshal(buf[:n])
			if err == nil && pkt.Cmd == protocol.CmdStunProbe {
				receivedCount.Add(1)
			}
		}
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen client udp: %v", err)
	}
	defer clientConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	SendBurstProbes(clientConn, serverAddr, 9999, 4, 10*time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	if count := receivedCount.Load(); count < 4 {
		t.Fatalf("expected at least 4 burst probes, got %d", count)
	}
}
