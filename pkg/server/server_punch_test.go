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
	"left4proxy/pkg/security"
	"left4proxy/pkg/stun"
)

func serverTestKey() []byte {
	key := make([]byte, security.KeySize)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}
	return key
}

func serverHandshake(t *testing.T, conn *net.UDPConn, serverAddr *net.UDPAddr, key []byte) (uint64, *security.Session) {
	t.Helper()
	req, pending, err := security.NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatalf("create handshake: %v", err)
	}
	if _, err := conn.WriteToUDP(req.Marshal(), serverAddr); err != nil {
		t.Fatalf("send handshake: %v", err)
	}
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read handshake: %v", err)
		}
		pkt, err := protocol.Unmarshal(buf[:n])
		if err != nil || pkt.Cmd != protocol.CmdHandshakeResp {
			continue
		}
		resp, session, err := security.VerifyHandshakeResponse(key, pkt, pending, time.Now().UnixNano())
		if err != nil {
			continue
		}
		return resp.SessionID, session
	}
}

func TestServerRejectsWrongKeyHandshakeAndPlaintextData(t *testing.T) {
	key := serverTestKey()
	cfg := &config.ServerConfig{ListenAddr: "127.0.0.1:0", TargetAddr: "127.0.0.1:27015", AuthKey: key}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 0xff
	req, _, err := security.NewHandshakeRequest(wrongKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	if _, err := conn.WriteToUDP(req.Marshal(), serverAddr); err != nil {
		t.Fatal(err)
	}
	plain := protocol.NewPacket(protocol.CmdData, 123, 1, []byte{0xff, 0xff, 0xff, 0xff, 'T', 'E', 'S', 'T'})
	_, _ = conn.WriteToUDP(plain.Marshal(), serverAddr)
	time.Sleep(50 * time.Millisecond)
	srv.sessionMu.RLock()
	count := len(srv.sessions)
	srv.sessionMu.RUnlock()
	if count != 0 {
		t.Fatalf("unauthenticated traffic allocated %d sessions", count)
	}
}

func TestServerPongEchoesAuthenticatedPingTimestamp(t *testing.T) {
	key := serverTestKey()
	cfg := &config.ServerConfig{ListenAddr: "127.0.0.1:0", TargetAddr: "127.0.0.1:27015", AuthKey: key}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	sessionID, session := serverHandshake(t, conn, serverAddr, key)
	defer session.Close()
	seq, err := session.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	wantTimestamp := time.Now().Add(-25 * time.Millisecond).UnixNano()
	ping := protocol.NewPacket(protocol.CmdPing, sessionID, seq, []byte("PING"))
	ping.Timestamp = wantTimestamp
	wire, err := session.Seal(ping, security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP(wire, serverAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	pong, err := session.Open(buf[:n], security.ServerToClient)
	if err != nil {
		t.Fatalf("authenticate pong: %v", err)
	}
	if pong.Cmd != protocol.CmdPong {
		t.Fatalf("command = %d, want CmdPong", pong.Cmd)
	}
	if pong.Timestamp != wantTimestamp {
		t.Fatalf("pong timestamp = %d, want echoed %d", pong.Timestamp, wantTimestamp)
	}
}

func TestAuthenticatedPingBindsCandidateWithoutChangingSession(t *testing.T) {
	key := serverTestKey()
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	cfg := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: upstream.LocalAddr().String(),
		NAT:        "false",
		PunchAddr:  "127.0.0.1:1", // avoid external STUN traffic in this test
		AuthKey:    key,
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	connA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()

	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	sessionID, session := serverHandshake(t, connA, serverAddr, key)
	defer session.Close()

	// A fresh candidate source can join the existing session only with a valid
	// AEAD Ping. The server must not require a new handshake/session ID.
	seq, err := session.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	ping := protocol.NewPacket(protocol.CmdPing, sessionID, seq, []byte("PING"))
	wire, err := session.Seal(ping, security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connB.WriteToUDP(wire, serverAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	_ = connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pong *protocol.Packet
	for pong == nil {
		n, _, rerr := connB.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatal(rerr)
		}
		candidate, oerr := session.Open(buf[:n], security.ServerToClient)
		if oerr == nil && candidate.Cmd == protocol.CmdPong {
			pong = candidate
		}
	}
	if hint, ok := protocol.DecodePathHint(pong.Payload); !ok || hint != protocol.PathHintLAN {
		t.Fatalf("unexpected authenticated path hint: %q (ok=%v)", pong.Payload, ok)
	}

	dataPayload := []byte{0xff, 0xff, 0xff, 0xff, 'T', 'E', 'S', 'T'}
	seq, err = session.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	data, err := session.Seal(protocol.NewPacket(protocol.CmdData, sessionID, seq, dataPayload), security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connB.WriteToUDP(data, serverAddr); err != nil {
		t.Fatal(err)
	}
	_ = upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, upstreamSource, err := upstream.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("upstream did not receive candidate data: %v", err)
	}
	if string(buf[:n]) != string(dataPayload) {
		t.Fatalf("upstream payload = %x, want %x", buf[:n], dataPayload)
	}
	if _, err := upstream.WriteToUDP([]byte("reply"), upstreamSource); err != nil {
		t.Fatal(err)
	}

	_ = connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, rerr := connB.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatal(rerr)
		}
		response, oerr := session.Open(buf[:n], security.ServerToClient)
		if oerr == nil && response.Cmd == protocol.CmdData {
			if string(response.Payload) != "reply" {
				t.Fatalf("reply payload = %q", response.Payload)
			}
			break
		}
	}
}

func TestServerAutoGatherHostCandidates(t *testing.T) {
	key := serverTestKey()
	cfg := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:27015",
		NAT:        "false",
		PublicIPs:  []string{"game.example.com:27014"},
		AuthKey:    key,
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
	_, session := serverHandshake(t, clientConn, srvAddr, key)
	_ = session
	buf := make([]byte, 2048)
	// The helper already verified the authenticated response; inspect metadata
	// through a second direct request only where the test's advertisement check
	// needs the response payload.
	// (The server emits the same cached response for this nonce, so use a fresh
	// request to avoid exposing unauthenticated fixture logic.)
	req, pending, err := security.NewHandshakeRequest(key, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.WriteToUDP(req.Marshal(), srvAddr); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp *protocol.Packet
	var metadata []byte
	for resp == nil {
		n, _, rerr := clientConn.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatal(rerr)
		}
		candidate, uerr := protocol.Unmarshal(buf[:n])
		if uerr == nil && candidate.Cmd == protocol.CmdHandshakeResp {
			if verified, _, verr := security.VerifyHandshakeResponse(key, candidate, pending, time.Now().UnixNano()); verr == nil {
				resp = candidate
				metadata = verified.Metadata
			}
		}
	}
	if resp.Cmd != protocol.CmdHandshakeResp {
		t.Fatalf("expected CmdHandshakeResp, got %d", resp.Cmd)
	}

	payload := string(metadata)
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
	key := serverTestKey()
	cfg := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:27015",
		NAT:        "true",
		AuthKey:    key,
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
	sessionID, session := serverHandshake(t, relayConn, srvAddr, key)
	buf := make([]byte, 2048)

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
			pkt, err := session.Open(pBuf[:pn], security.ServerToClient)
			if err == nil && pkt.Cmd == protocol.CmdStunProbe {
				probeCount.Add(1)
			}
		}
	}()

	// 3. Client sends CmdPunchInit over relay
	punchLocal := punchConn.LocalAddr().String()
	seq, err := session.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	punchInit, err := session.Seal(protocol.NewPacket(protocol.CmdPunchInit, sessionID, seq, []byte(punchLocal)), security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = relayConn.WriteToUDP(punchInit, srvAddr)

	// Wait for Ack on relayConn
	_ = relayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := relayConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to read punch ack: %v", err)
	}
	ackPkt, err := session.Open(buf[:n], security.ServerToClient)
	if err != nil {
		t.Fatalf("failed to authenticate punch ack: %v", err)
	}
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
	key := serverTestKey()
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
			if stun.IsStunMessage(sBuf[:sn]) && binary.BigEndian.Uint16(sBuf[0:2]) == 0x0001 {
				resp := make([]byte, 20)
				copy(resp, sBuf[:20])
				binary.BigEndian.PutUint16(resp[0:2], 0x0101)     // STUN Binding Response
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
		AuthKey:    key,
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
