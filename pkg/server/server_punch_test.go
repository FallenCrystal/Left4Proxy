package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/stun"
)

func TestServerAutoGatherHostCandidates(t *testing.T) {
	cfg := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:27015",
		NAT:        "false",
		PublicIPs:  []string{"game.example.com:27014"},
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// Client sends handshake
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to create client socket: %v", err)
	}
	defer clientConn.Close()

	srvAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	hsReq := protocol.NewPacket(protocol.CmdHandshakeReq, 0, 1, []byte("HANDSHAKE"))
	if _, err := clientConn.WriteToUDP(hsReq.Marshal(), srvAddr); err != nil {
		t.Fatalf("failed to send handshake: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to read handshake response: %v", err)
	}

	resp, err := protocol.Unmarshal(buf[:n])
	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Cmd != protocol.CmdHandshakeResp {
		t.Fatalf("expected CmdHandshakeResp, got %d", resp.Cmd)
	}

	payload := string(resp.Payload)
	parts := strings.Split(payload, "|")
	if len(parts) < 3 {
		t.Fatalf("invalid payload format: %s", payload)
	}

	// Advertised IPs should include game.example.com:27014
	if !strings.Contains(parts[1], "game.example.com:27014") {
		t.Errorf("expected payload to contain configured public IP, got: %s", parts[1])
	}
}

func TestServerPunchInitBurstAndProbe(t *testing.T) {
	cfg := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:27015",
		NAT:        "true",
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// 1. Client creates relay connection and handshakes
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen relay conn: %v", err)
	}
	defer relayConn.Close()

	srvAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	hsReq := protocol.NewPacket(protocol.CmdHandshakeReq, 0, 1, []byte("HANDSHAKE"))
	_, _ = relayConn.WriteToUDP(hsReq.Marshal(), srvAddr)

	_ = relayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := relayConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to read handshake: %v", err)
	}
	hsResp, _ := protocol.Unmarshal(buf[:n])
	sessionID := hsResp.SessionID

	// 2. Client creates punch socket
	punchConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen punch socket: %v", err)
	}
	defer punchConn.Close()

	var probeCount atomic.Int32
	go func() {
		pBuf := make([]byte, 1024)
		for {
			pn, _, pErr := punchConn.ReadFromUDP(pBuf)
			if pErr != nil {
				return
			}
			pkt, err := protocol.Unmarshal(pBuf[:pn])
			if err == nil && pkt.Cmd == protocol.CmdStunProbe {
				probeCount.Add(1)
			}
		}
	}()

	// 3. Client sends CmdPunchInit over relay
	punchLocal := punchConn.LocalAddr().String()
	punchInit := protocol.NewPacket(protocol.CmdPunchInit, sessionID, 2, []byte(punchLocal))
	_, _ = relayConn.WriteToUDP(punchInit.Marshal(), srvAddr)

	// Wait for Ack on relayConn
	_ = relayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = relayConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to read punch ack: %v", err)
	}
	ackPkt, _ := protocol.Unmarshal(buf[:n])
	if ackPkt.Cmd != protocol.CmdPunchAck {
		t.Fatalf("expected CmdPunchAck, got %d", ackPkt.Cmd)
	}

	// 4. Punch socket should receive burst probes from server
	time.Sleep(200 * time.Millisecond)
	if count := probeCount.Load(); count < 2 {
		t.Fatalf("expected at least 2 burst probes received on punch socket, got %d", count)
	}
}

func TestServerMultiStunDiscovery(t *testing.T) {
	// Start mock STUN server
	mockStun, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen mock stun: %v", err)
	}
	defer mockStun.Close()

	mockAddr := mockStun.LocalAddr().(*net.UDPAddr)

	go func() {
		sBuf := make([]byte, 1024)
		for {
			sn, clientAddr, err := mockStun.ReadFromUDP(sBuf)
			if err != nil {
				return
			}
			if stun.IsStunResponse(sBuf[:sn]) || sn >= 20 {
				resp := make([]byte, 20)
				copy(resp, sBuf[:20])
				binary.BigEndian.PutUint16(resp[0:2], 0x0101) // STUN Binding Response
				binary.BigEndian.PutUint32(resp[4:8], 0x2112A442) // Magic Cookie
				// Append XOR-MAPPED-ADDRESS
				addr := net.IPv4(198, 51, 100, 1)
				attr := make([]byte, 12)
				binary.BigEndian.PutUint16(attr[0:2], 0x0020) // XOR-MAPPED-ADDRESS
				binary.BigEndian.PutUint16(attr[2:4], 8)      // length
				attr[4] = 0
				attr[5] = 0x01 // IPv4
				binary.BigEndian.PutUint16(attr[6:8], uint16(27014)^(0x2112A442>>16))
				ipBytes := addr.To4()
				binary.BigEndian.PutUint32(attr[8:12], binary.BigEndian.Uint32(ipBytes)^0x2112A442)
				resp = append(resp, attr...)
				binary.BigEndian.PutUint16(resp[2:4], 12)
				_, _ = mockStun.WriteToUDP(resp, clientAddr)
			}
		}
	}()

	cfg := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:27015",
		StunServer: fmt.Sprintf("127.0.0.1:%d", mockAddr.Port),
		NAT:        "true",
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// Wait for STUN reflection
	deadline := time.Now().Add(2 * time.Second)
	var pub string
	for time.Now().Before(deadline) {
		pub = srv.publicEndpointString()
		if pub != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if pub == "" {
		t.Fatalf("server failed to discover public endpoint from mock STUN")
	}
}
