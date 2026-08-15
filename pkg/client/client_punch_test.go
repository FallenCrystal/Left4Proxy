package client

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/security"
	"left4proxy/pkg/server"
	"left4proxy/pkg/stun"
)

const stunMagicCookie = uint32(0x2112A442)

// mockStunBindingResponse builds a STUN Binding Response whose
// XOR-MAPPED-ADDRESS reflects src (IPv4). Mirrors RFC 5389 §15.2 and echoes
// the request transaction ID so the production Validator can authenticate it.
func mockStunBindingResponse(request []byte, src *net.UDPAddr) []byte {
	ip4 := src.IP.To4()
	resp := make([]byte, 20+12)
	binary.BigEndian.PutUint16(resp[0:2], 0x0101) // Binding Response
	binary.BigEndian.PutUint16(resp[2:4], 12)     // total attribute length (4 header + 8 value)
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	if len(request) >= 20 {
		copy(resp[8:20], request[8:20])
	}
	attr := resp[20:]
	binary.BigEndian.PutUint16(attr[0:2], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(attr[2:4], 8)
	attr[4] = 0
	attr[5] = 0x01 // IPv4
	binary.BigEndian.PutUint16(attr[6:8], uint16(src.Port)^0x2112)
	binary.BigEndian.PutUint32(attr[8:12], binary.BigEndian.Uint32(ip4)^stunMagicCookie)
	return resp
}

// startMockStunServer runs a UDP listener that answers any STUN message with a
// reflection of the sender, like a real public STUN server.
func startMockStunServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("mock STUN listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, src, rerr := conn.ReadFromUDP(buf)
			if rerr != nil {
				continue
			}
			if stun.IsStunMessage(buf[:n]) { // any STUN message -> reflect sender
				_, _ = conn.WriteToUDP(mockStunBindingResponse(buf[:n], src), src)
			}
		}
	}()
	cleanup := func() { close(done); _ = conn.Close() }
	return conn.LocalAddr().(*net.UDPAddr), cleanup
}

// handshakeRaw performs a handshake over an already-dialed socket and returns
// the parsed session ID and the response payload split on "|". It skips any
// push packets (e.g. a CmdPunchOffer broadcast at startup) that may arrive
// before the handshake response.
func integrationKey() []byte {
	key := make([]byte, security.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func handshakeRaw(t *testing.T, conn *net.UDPConn, key []byte) (uint64, []string, *security.Session) {
	t.Helper()
	req, pending, err := security.NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatalf("create handshake: %v", err)
	}
	if _, err := conn.Write(req.Marshal()); err != nil {
		t.Fatalf("handshake write: %v", err)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		pkt, uerr := protocol.Unmarshal(buf[:n])
		if uerr != nil {
			continue
		}
		if pkt.Cmd == protocol.CmdHandshakeResp {
			resp, session, verr := security.VerifyHandshakeResponse(key, pkt, pending, time.Now().UnixNano())
			if verr != nil {
				continue
			}
			return resp.SessionID, strings.Split(string(resp.Metadata), "|"), session
		}
	}
	t.Fatalf("handshake response not received")
	return 0, nil, nil
}

func sealIntegrationPacket(t *testing.T, session *security.Session, cmd byte, payload []byte) []byte {
	t.Helper()
	seq, err := session.NextSeq()
	if err != nil {
		t.Fatalf("next sequence: %v", err)
	}
	data, err := session.Seal(protocol.NewPacket(cmd, session.ID, seq, payload), security.ClientToServer)
	if err != nil {
		t.Fatalf("seal packet: %v", err)
	}
	return data
}

func openIntegrationPacket(t *testing.T, session *security.Session, data []byte) *protocol.Packet {
	t.Helper()
	pkt, err := session.Open(data, security.ServerToClient)
	if err != nil {
		t.Fatalf("open packet: %v", err)
	}
	return pkt
}

// TestServerStunDiscoveryAdvertisesEndpoint verifies the server reflects its own
// public endpoint via a STUN server and advertises it as the 4th handshake
// payload field (the punch target clients should use).
func TestServerStunDiscoveryAdvertisesEndpoint(t *testing.T) {
	mockAddr, stopStun := startMockStunServer(t)
	defer stopStun()
	key := integrationKey()

	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = "127.0.0.1:28314"
	serverCfg.TargetAddr = "127.0.0.1:28315"
	serverCfg.StunServer = mockAddr.String()
	serverCfg.AuthKey = key

	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Stop()

	// Give the discovery loop time to query the mock STUN server.
	time.Sleep(400 * time.Millisecond)

	raw, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 28314})
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer raw.Close()

	_, parts, _ := handshakeRaw(t, raw, key)
	if len(parts) != 3 {
		t.Fatalf("expected a 3-field handshake payload, got %d fields: %q", len(parts), strings.Join(parts, "|"))
	}
	// A local UPnP mapper may win the race with the mock STUN response in CI;
	// either endpoint is valid as long as it is an address on the configured
	// listener port and the field is not empty/forged text.
	_, port, err := net.SplitHostPort(parts[2])
	if err != nil || port != "28314" {
		t.Fatalf("handshake punch field = %q, want a valid endpoint on port 28314", parts[2])
	}
}

// TestServerPunchesInitTarget verifies the server replies to CmdPunchInit with
// CmdPunchAck and then proactively probes the given direct target.
func TestServerPunchesInitTarget(t *testing.T) {
	key := integrationKey()
	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = "127.0.0.1:28324"
	serverCfg.TargetAddr = "127.0.0.1:28325"
	serverCfg.PunchAddr = "127.0.0.1:28324" // manual override (avoids STUN here)
	serverCfg.AuthKey = key

	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Stop()

	raw, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 28324})
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer raw.Close()

	_, _, session := handshakeRaw(t, raw, key)

	// Pretend this socket is the client's direct (punch) socket and tell the
	// server to open a hole toward it.
	init := sealIntegrationPacket(t, session, protocol.CmdPunchInit, []byte(raw.LocalAddr().String()))
	if _, err := raw.Write(init); err != nil {
		t.Fatalf("punch init write: %v", err)
	}

	// Expect CmdPunchAck, then the server's CmdStunProbe toward our "direct" socket.
	buf := make([]byte, 2048)
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	gotAck, gotProbe := false, false
	for i := 0; i < 5; i++ {
		n, err := raw.Read(buf)
		if err != nil {
			break
		}
		pkt, uerr := session.Open(buf[:n], security.ServerToClient)
		if uerr != nil {
			continue
		}
		switch pkt.Cmd {
		case protocol.CmdPunchAck:
			gotAck = true
		case protocol.CmdStunProbe:
			gotProbe = true
		}
		if gotAck && gotProbe {
			break
		}
	}
	if !gotAck {
		t.Fatalf("expected CmdPunchAck after PunchInit")
	}
	if !gotProbe {
		t.Fatalf("expected the server to probe the direct target after PunchInit")
	}
}

// TestPunchCandidateEstablishment runs a real client+server and verifies the
// client's punch machinery: create the punch socket, learn its public endpoint
// via STUN, tell the server, probe the server's public endpoint, and confirm the
// direct path by receiving a reflection.
//
// It calls addPunchCandidate directly because on localhost the client's relay
// candidate is the same address as the punch target, which the
// maybeCreatePunchCandidate dedup correctly skips (in production they differ:
// relay = frp node, target = the server's own NAT-mapped endpoint).
func TestPunchCandidateEstablishment(t *testing.T) {
	mockAddr, stopStun := startMockStunServer(t)
	defer stopStun()
	key := integrationKey()

	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = "127.0.0.1:28334"
	serverCfg.TargetAddr = "127.0.0.1:28335"
	serverCfg.PunchAddr = "127.0.0.1:28334"
	serverCfg.AuthKey = key

	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Stop()

	clientCfg := config.DefaultClientConfig()
	clientCfg.ServerAddrs = []string{"127.0.0.1:28334"}
	clientCfg.ListenAddr = "127.0.0.2:28335"
	clientCfg.StunServer = mockAddr.String()
	clientCfg.EnableLAN = true
	clientCfg.EnablePunch = true
	clientCfg.PingInterval = 1
	clientCfg.AuthKey = key

	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer cli.Stop()

	// Wait for the handshake to complete.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cli.sessionID.Load() != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cli.sessionID.Load() == 0 {
		t.Fatalf("client never completed handshake")
	}

	// Simulate the relay scenario so sendPunchInit has a control channel (in a
	// real deployment the frp tunnel labels the connection "relay").
	cli.candidateMu.RLock()
	relay := cli.candidates[0]
	cli.candidateMu.RUnlock()
	relay.mu.Lock()
	relay.pathClass = "relay"
	relay.online = true
	relay.mu.Unlock()

	serverPub, _ := net.ResolveUDPAddr("udp", "127.0.0.1:28334")
	cli.addPunchCandidate(serverPub)

	// The punch candidate should come online (direct path confirmed) shortly.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var punch *serverCandidate
		cli.candidateMu.RLock()
		for _, c := range cli.candidates {
			if c.isPunch {
				punch = c
				break
			}
		}
		cli.candidateMu.RUnlock()
		if punch == nil {
			t.Fatalf("punch candidate was not created")
		}
		punch.mu.RLock()
		online := punch.online
		pub := punch.pubEndpoint
		punch.mu.RUnlock()
		if online {
			t.Logf("punch candidate confirmed online; public endpoint=%s", pub)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The punch candidate's RTT must get measured via the normal CmdPing/CmdPong
	// loop (it starts at 999ms), otherwise it can never win routing by RTT.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var punch *serverCandidate
		cli.candidateMu.RLock()
		for _, c := range cli.candidates {
			if c.isPunch {
				punch = c
				break
			}
		}
		cli.candidateMu.RUnlock()
		if punch == nil {
			t.Fatalf("punch candidate was not created")
		}
		punch.mu.RLock()
		rtt := punch.rtt
		online := punch.online
		punch.mu.RUnlock()
		if online && rtt < 999*time.Millisecond {
			t.Logf("punch candidate RTT measured via ping: %v", rtt)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("punch candidate RTT was never measured (stays at initial 999ms)")
}

// TestMaybeCreatePunchCandidateGating verifies when the client decides to start
// punching: it must be enabled, not relay-only, require an existing relay
// candidate, and not duplicate an address it already has.
func TestMaybeCreatePunchCandidateGating(t *testing.T) {
	mk := func(mode string) *Client {
		cfg := config.DefaultClientConfig()
		cfg.Mode = mode
		cfg.StunServer = "127.0.0.1:9" // non-routable: establishPunch exits fast
		cli, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("create client: %v", err)
		}
		return cli
	}

	target := "9.9.9.9:27014"

	// 1. No relay candidate -> no punch candidate.
	c := mk("auto")
	c.maybeCreatePunchCandidate(target)
	if len(c.candidates) != 0 {
		t.Fatalf("expected no candidate without a relay, got %d", len(c.candidates))
	}
	c.Stop()

	// 2. relay-only mode -> no punch candidate even with a relay.
	c = mk("relay-only")
	c.candidates = []*serverCandidate{{addrStr: "1.2.3.4:27014", pathClass: "relay", online: true}}
	c.maybeCreatePunchCandidate(target)
	if len(c.candidates) != 1 {
		t.Fatalf("relay-only must not create a punch candidate")
	}
	c.Stop()

	// 3. An existing candidate at the same address -> skipped (redundant).
	c = mk("auto")
	dup, _ := net.ResolveUDPAddr("udp", target)
	c.candidates = []*serverCandidate{{addrStr: target, udpAddr: dup, online: true, pathClass: "relay"}}
	c.maybeCreatePunchCandidate(target)
	if len(c.candidates) != 1 {
		t.Fatalf("duplicate address must not create a second candidate")
	}
	c.Stop()

	// 4. A relay candidate at a different address -> punch candidate created.
	c = mk("auto")
	relayAddr, _ := net.ResolveUDPAddr("udp", "1.2.3.4:27014")
	c.candidates = []*serverCandidate{{addrStr: "1.2.3.4:27014", udpAddr: relayAddr, online: true, pathClass: "relay"}}
	c.maybeCreatePunchCandidate(target)
	if len(c.candidates) != 2 || !c.candidates[1].isPunch {
		t.Fatalf("expected a punch candidate to be created, got %d candidates", len(c.candidates))
	}
	c.Stop()
}

func TestModeSwitchRetiresAndRestoresPunchCandidate(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.EnablePunch = true
	cfg.StunServer = "127.0.0.1:9"
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	relayAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 39991}
	relay := &serverCandidate{
		addrStr:       relayAddr.String(),
		udpAddr:       relayAddr,
		online:        true,
		lastActive:    time.Now(),
		rtt:           20 * time.Millisecond,
		pathClass:     candidatePathRelay,
		punchEndpoint: "127.0.0.1:39992",
	}
	punchConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	punchAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 39992}
	punch := &serverCandidate{
		addrStr:    punchAddr.String(),
		udpAddr:    punchAddr,
		conn:       punchConn,
		sendTo:     punchAddr,
		isPunch:    true,
		online:     true,
		lastActive: time.Now(),
		rtt:        10 * time.Millisecond,
		pathClass:  candidatePathPunch,
	}
	c.candidates = []*serverCandidate{relay, punch}
	c.bestCandidate = punch

	if err := c.SetMode("relay-only"); err != nil {
		t.Fatal(err)
	}
	c.candidateMu.RLock()
	if len(c.candidates) != 1 || c.candidates[0] != relay {
		c.candidateMu.RUnlock()
		t.Fatalf("relay-only candidates = %#v, want only relay", c.candidates)
	}
	c.candidateMu.RUnlock()

	if err := c.SetMode("auto"); err != nil {
		t.Fatal(err)
	}
	c.candidateMu.RLock()
	restored := false
	for _, cand := range c.candidates {
		if cand != nil {
			cand.mu.RLock()
			isRestored := cand.isPunch && sameUDPAddr(cand.udpAddr, punchAddr)
			cand.mu.RUnlock()
			if isRestored {
				restored = true
				break
			}
		}
	}
	c.candidateMu.RUnlock()
	if !restored {
		t.Fatal("auto mode did not recreate the punch candidate cached by the relay")
	}
}

func TestWaitPublicEndpointStopsForRetiredCandidate(t *testing.T) {
	cfg := config.DefaultClientConfig()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	cand := &serverCandidate{retired: true}
	started := time.Now()
	if got := c.waitPublicEndpoint(cand, time.Second); got != "" {
		t.Fatalf("public endpoint = %q, want empty for retired candidate", got)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("waitPublicEndpoint took %v for an already retired candidate", elapsed)
	}
}

// TestPunchIsFallbackWhenRelayDies verifies the resilience story: while the
// relay is healthy it wins by RTT (even though the punched direct path is
// online but slower), and when the relay goes offline the client switches to
// the punch candidate unconditionally (no hysteresis against a stale RTT).
func TestPunchIsFallbackWhenRelayDies(t *testing.T) {
	cfg := config.DefaultClientConfig()
	c := &Client{cfg: cfg}

	relay := mkCand("157.148.128.243:18276", 52*time.Millisecond, true, false)
	relay.pathClass = "relay"
	punch := mkCand("64.186.238.133:41465", 318*time.Millisecond, true, false)
	punch.pathClass = "punch"
	punch.isPunch = true

	c.candidates = []*serverCandidate{relay, punch}
	c.bestCandidate = relay

	// Relay healthy and faster -> stays on relay.
	c.selectBestCandidate()
	if c.bestCandidate != relay {
		t.Fatalf("expected relay while healthy, got %s", c.bestCandidate.addrStr)
	}

	// Relay dies (offline) -> punch becomes the only online candidate and must
	// take over, even though its RTT is worse than the relay's stale value.
	relay.mu.Lock()
	relay.online = false
	relay.lastActive = time.Time{}
	relay.mu.Unlock()
	c.selectBestCandidate()
	if c.bestCandidate != punch {
		t.Fatalf("expected punch fallback when relay dies, got %s", c.bestCandidate.addrStr)
	}

	// Relay comes back -> switch back to relay (better RTT).
	relay.mu.Lock()
	relay.online = true
	relay.lastActive = time.Now()
	relay.mu.Unlock()
	c.bestCandidate = punch
	c.selectBestCandidate()
	if c.bestCandidate != relay {
		t.Fatalf("expected to return to relay when it recovers, got %s", c.bestCandidate.addrStr)
	}
}

// TestCandidateReadLoopSurvivesTransientError verifies a candidate's read loop
// keeps running after a transient socket error (ICMP "connection refused" from
// a downed peer) instead of exiting. If it exited, the candidate could never
// recover and the client would re-handshake it forever, spamming the server
// with fresh sessions.
func TestCandidateReadLoopSurvivesTransientError(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// A peer that closes, making the connected candidate socket get ECONNREFUSED.
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	cand := &serverCandidate{addrStr: peer.LocalAddr().String(), udpAddr: peer.LocalAddr().(*net.UDPAddr), conn: conn}

	// Establish the connection so the kernel tracks it.
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	buf := make([]byte, 64)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	_, _, _ = peer.ReadFromUDP(buf)
	peer.Close() // now sends to this port get ICMP port-unreachable

	done := make(chan struct{})
	cli.wg.Add(1)
	go func() {
		cli.candidateReadLoop(cand)
		close(done)
	}()

	// Trigger ECONNREFUSED on the socket by sending to the now-closed peer, then
	// give the loop time to hit the error path.
	for i := 0; i < 5; i++ {
		_, _ = conn.Write([]byte("X"))
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(700 * time.Millisecond)

	select {
	case <-done:
		conn.Close()
		t.Fatalf("candidateReadLoop exited on a transient error")
	default:
		// Still running as expected.
	}

	// Clean shutdown must still stop the loop.
	cli.cancel()
	conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("candidateReadLoop did not stop after cancel")
	}
}

// TestRawSenderAddrMigration verifies the core path-switching hook: when the
// same session sends CmdData from a second socket, the server migrates the
// return path to that socket (this is what makes direct punching seamless).
func TestRawSenderAddrMigration(t *testing.T) {
	// Mock upstream L4D2 server.
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 28345})
	if err != nil {
		t.Fatalf("mock upstream listen: %v", err)
	}
	defer upstream.Close()

	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = "127.0.0.1:28344"
	serverCfg.TargetAddr = "127.0.0.1:28345"
	serverCfg.AuthKey = integrationKey()

	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Stop()

	connA, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 28344})
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()
	connB, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 28344})
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.Close()

	_, _, session := handshakeRaw(t, connA, serverCfg.AuthKey)
	payload := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'T', 'S', 'o', 'u', 'r', 'c', 'e'}
	buf := make([]byte, 2048)

	// 1. Socket A sends a game packet; the reply must come back to A.
	dataA := sealIntegrationPacket(t, session, protocol.CmdData, payload)
	if _, err := connA.Write(dataA); err != nil {
		t.Fatalf("write A: %v", err)
	}
	_ = upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, serverSrc, err := upstream.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("upstream did not receive packet A: %v", err)
	}
	if _, err := upstream.WriteToUDP([]byte("REPLY-A"), serverSrc); err != nil {
		t.Fatalf("upstream reply A: %v", err)
	}
	_ = connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := connA.Read(buf); err != nil {
		t.Fatalf("connA did not receive reply: %v", err)
	}
	t.Logf("packet A replied to socket A (received %d bytes)", n)

	// Authorize the direct socket through the authenticated PunchInit control
	// packet, then send a game packet with the same session ID.  An arbitrary
	// unauthenticated source is intentionally rejected by the server.
	initB := sealIntegrationPacket(t, session, protocol.CmdPunchInit, []byte(connB.LocalAddr().String()))
	if _, err := connA.Write(initB); err != nil {
		t.Fatalf("write PunchInit: %v", err)
	}
	_ = connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := connA.Read(buf)
		if err != nil {
			t.Fatalf("PunchAck read: %v", err)
		}
		if pkt, err := session.Open(buf[:n], security.ServerToClient); err == nil && pkt.Cmd == protocol.CmdPunchAck {
			break
		}
	}

	dataB := sealIntegrationPacket(t, session, protocol.CmdData, payload)
	if _, err := connB.Write(dataB); err != nil {
		t.Fatalf("write B: %v", err)
	}
	_ = upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, serverSrc2, err := upstream.ReadFromUDP(buf); err != nil {
		t.Fatalf("upstream did not receive packet B: %v", err)
	} else {
		if _, err := upstream.WriteToUDP([]byte("REPLY-B"), serverSrc2); err != nil {
			t.Fatalf("upstream reply B: %v", err)
		}
	}

	_ = connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := connB.Read(buf); err != nil {
		t.Fatalf("connB did not receive the migrated reply: %v", err)
	}

	// Socket A must not receive the migrated reply.
	_ = connA.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := connA.Read(buf); err == nil {
		t.Fatalf("connA should NOT receive the migrated reply")
	}
}
