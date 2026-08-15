package client

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/router"
	"left4proxy/pkg/security"
)

func TestDualSendingDuringRouteMigration(t *testing.T) {
	// Start two mock candidate servers (Relay and Punch)
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen relay mock: %v", err)
	}
	defer relayConn.Close()

	punchConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen punch mock: %v", err)
	}
	defer punchConn.Close()

	var relayPacketCount atomic.Int32
	var punchPacketCount atomic.Int32

	readPackets := func(conn *net.UDPConn, counter *atomic.Int32) {
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt, err := protocol.Unmarshal(buf[:n])
			if err == nil && pkt.Cmd == protocol.CmdData {
				counter.Add(1)
			}
		}
	}

	go readPackets(relayConn, &relayPacketCount)
	go readPackets(punchConn, &punchPacketCount)

	clientCfg := config.DefaultClientConfig()
	clientCfg.ListenAddr = "127.0.0.1:0"
	clientCfg.ServerAddrs = []string{relayConn.LocalAddr().String()}
	clientCfg.EnablePunch = false // manual candidate setup
	clientCfg.AuthKey = integrationKey()

	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer cli.Stop()
	// The mock endpoints below do not implement the handshake themselves;
	// install a real derived session so the local forwarding path is exercised
	// with the same AEAD framing as production.
	key := clientCfg.AuthKey
	reqPkt, pending, err := security.NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	req, err := security.VerifyHandshakeRequest(key, reqPkt, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	respPkt, _, err := security.NewHandshakeResponse(key, req, 1234, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, clientSession, err := security.VerifyHandshakeResponse(key, respPkt, pending, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	cli.secureSession.Store(clientSession)
	cli.sessionID.Store(clientSession.ID)

	// Add punch candidate
	punchCand, _ := cli.addCandidate(punchConn.LocalAddr().String())
	punchCand.mu.Lock()
	punchCand.online = true
	punchCand.pathHint = "punch"
	punchCand.lastActive = time.Now()
	punchCand.rtt = 10 * time.Millisecond
	punchCand.mu.Unlock()

	relayCand := cli.candidates[0]
	relayCand.mu.Lock()
	relayCand.online = true
	relayCand.pathHint = "relay"
	relayCand.lastActive = time.Now()
	relayCand.rtt = 50 * time.Millisecond
	relayCand.mu.Unlock()

	// Initial route is Relay
	cli.bestCandidate = relayCand

	// Trigger route switch to Punch (which enables dual-sending for 400ms)
	cli.candidateMu.Lock()
	cli.prevCandidate = relayCand
	cli.bestCandidate = punchCand
	cli.dualSendUntil = time.Now().Add(400 * time.Millisecond)
	cli.candidateMu.Unlock()

	// Send a game packet to client localConn
	gameData := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x00, 0x01, 0x02}
	localAddr := cli.localConn.LocalAddr().(*net.UDPAddr)

	senderConn, err := net.DialUDP("udp", nil, localAddr)
	if err != nil {
		t.Fatalf("failed to dial localConn: %v", err)
	}
	defer senderConn.Close()

	_, _ = senderConn.Write(gameData)

	time.Sleep(100 * time.Millisecond)

	// Both relay and punch should have received the packet due to dual sending!
	if punchCount := punchPacketCount.Load(); punchCount < 1 {
		t.Errorf("expected punch candidate to receive at least 1 packet, got %d", punchCount)
	}
	if relayCount := relayPacketCount.Load(); relayCount < 1 {
		t.Errorf("expected relay candidate to receive duplicate packet during dual-sending window, got %d", relayCount)
	}

	// Switching to relay-only must clear the dual-send path and send the next
	// game datagram exclusively to the explicitly classified relay candidate.
	relayCand.mu.Lock()
	relayCand.isLAN = false // loopback fixture represents an external relay.
	relayCand.mu.Unlock()
	punchCand.mu.Lock()
	punchCand.isLAN = false
	punchCand.mu.Unlock()
	if err := cli.SetMode("relay-only"); err != nil {
		t.Fatal(err)
	}
	beforeRelay := relayPacketCount.Load()
	beforePunch := punchPacketCount.Load()
	_, _ = senderConn.Write(gameData)
	time.Sleep(100 * time.Millisecond)
	if relayPacketCount.Load() <= beforeRelay {
		t.Fatal("relay-only did not forward the game packet to the relay")
	}
	if got := punchPacketCount.Load(); got != beforePunch {
		t.Fatalf("relay-only leaked game traffic to punch candidate: before=%d after=%d", beforePunch, got)
	}
}

func TestFastFailoverDuringActiveGameplay(t *testing.T) {
	clientCfg := config.DefaultClientConfig()
	clientCfg.ListenAddr = "127.0.0.1:0"
	clientCfg.ServerAddrs = []string{"127.0.0.1:39991"}
	clientCfg.PingInterval = 1
	clientCfg.AuthKey = integrationKey()

	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	punchAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:39992")
	punchCand := &serverCandidate{
		addrStr:    "127.0.0.1:39992",
		udpAddr:    punchAddr,
		isPunch:    true,
		pathHint:   "punch",
		online:     true,
		lastActive: time.Now().Add(-3 * time.Second), // 3s silent
		rtt:        15 * time.Millisecond,
	}

	relayAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:39991")
	relayCand := &serverCandidate{
		addrStr:    "127.0.0.1:39991",
		udpAddr:    relayAddr,
		isPunch:    false,
		pathHint:   "relay",
		online:     true,
		lastActive: time.Now(), // active
		rtt:        40 * time.Millisecond,
	}

	cli.candidates = []*serverCandidate{relayCand, punchCand}
	cli.bestCandidate = punchCand
	cli.router.UpdateMetrics(router.PathPunch, 15*time.Millisecond, 0.0)
	cli.router.UpdateMetrics(router.PathRelay, 40*time.Millisecond, 0.0)

	// Simulate active game connection
	gameSocket, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51234")
	cli.gameConnAddr.Store(gameSocket)
	cli.gameConnLastSeen.Store(time.Now().UnixNano())

	// Run selectBestCandidate with punch unresponsive > 2.5s
	// The fast failover logic in pingProbeLoop sets online = false when silent > 2.5s
	// Let's verify selectBestCandidate picks relay when punch is marked dead or degraded
	punchCand.online = false
	cli.selectBestCandidate()

	if cli.bestCandidate != relayCand {
		t.Errorf("expected bestCandidate to revert to relayCand on punch failure, got %v", cli.bestCandidate)
	}
}
