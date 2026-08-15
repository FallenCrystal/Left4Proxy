package client

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/router"
	"left4proxy/pkg/server"
	"left4proxy/pkg/stun"
)

func TestClientConcurrentStartStopDoesNotLeakOrHang(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	for i := 0; i < 20; i++ {
		cfg := config.DefaultClientConfig()
		cfg.ServerAddrs = []string{peer.LocalAddr().String()}
		cfg.ListenAddr = "127.0.0.1:0"
		cfg.Mode = "relay-only"
		cfg.EnablePunch = false
		cfg.AuthKey = integrationKey()
		cli, err := NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}

		var callers sync.WaitGroup
		callers.Add(2)
		go func() {
			defer callers.Done()
			_ = cli.Start()
		}()
		go func() {
			defer callers.Done()
			cli.Stop()
		}()
		done := make(chan struct{})
		go func() { callers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent client Start/Stop hung")
		}
		cli.Stop()
	}
}

// TestA2SResponseRouting verifies the A2S helpers distinguish the server
// browser's query/response packets from the game's netchannel connect
// challenge, so responses are routed to the query socket instead of the
// netchannel socket (which would otherwise see a spurious 0x41 challenge and
// drop the player with "Invalid challenge packet").
func TestA2SResponseRouting(t *testing.T) {
	// A2S challenge request from the server browser: ff ff ff ff 54 "Source Engine Query".
	query := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54}
	query = append(query, []byte("Source Engine Query")...)
	if !isA2SQuery(query) {
		t.Fatalf("isA2SQuery(%x) = false, want true", query)
	}
	// The game's netchannel connect packet must NOT be treated as an A2S query.
	connect := append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x71}, []byte("connect0x0BB1626F")...)
	if isA2SQuery(connect) {
		t.Fatalf("isA2SQuery(connect) = true, want false")
	}

	// A2S challenge response is exactly 10 bytes: ff ff ff ff 41 <challenge>.
	a2sChallenge := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0x00, 0x11, 0x22, 0x33}
	if !isA2SResponse(a2sChallenge) {
		t.Fatalf("isA2SResponse(A2S challenge) = false, want true")
	}
	// A2S info response (0x49) is also a query response.
	a2sInfo := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x49, 'h', 'e', 'l', 'l', 'o'}
	if !isA2SResponse(a2sInfo) {
		t.Fatalf("isA2SResponse(A2S info) = false, want true")
	}
	// The netchannel connect challenge response (type 0x41, but much longer
	// than 10 bytes) must NOT be treated as an A2S response — it is delivered
	// to the game's netchannel socket normally.
	connectChallenge := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0x6f, 0x62, 0xb1, 0x0b, 0x03, 0x00, 0x00, 0x00}
	if isA2SResponse(connectChallenge) {
		t.Fatalf("isA2SResponse(connect challenge) = true, want false")
	}
}

func TestPathForCandidate(t *testing.T) {
	c := &Client{}

	lan := mkCand("192.168.1.5:27014", 0, false, true)
	relay := mkCand("1.2.3.4:27014", 0, false, false)
	relay.pathClass = "relay"
	direct := mkCand("5.6.7.8:27014", 0, false, false)
	direct.pathClass = "direct"
	punch := mkCand("9.9.9.9:27014", 0, false, false)
	punch.pathClass = "punch"
	unknown := mkCand("8.8.8.8:27014", 0, false, false) // no hint yet (old server / pre-handshake)

	got := func(cand *serverCandidate) router.PathType { return c.pathForCandidate(cand) }

	if got(lan) != router.PathLAN {
		t.Errorf("expected LAN for lan candidate, got %s", got(lan))
	}
	if got(relay) != router.PathRelay {
		t.Errorf("expected Relay for relay candidate, got %s", got(relay))
	}
	if got(direct) != router.PathDirect {
		t.Errorf("expected Direct for direct candidate, got %s", got(direct))
	}
	if got(punch) != router.PathPunch {
		t.Errorf("expected Punch for punch candidate, got %s", got(punch))
	}
	if got(unknown) != router.PathRelay {
		t.Errorf("expected Relay default for unknown hint, got %s", got(unknown))
	}
}

func TestAdvertisedAddressPromotesConfiguredEntry(t *testing.T) {
	c := &Client{}
	local := mkCand("127.0.0.1:27014", 0, false, true)
	local.pathClass = candidatePathRelay
	c.setCandidatePath(local, candidatePathDirect)
	if local.pathClass != candidatePathLAN {
		t.Fatalf("advertised local entry path = %q, want LAN", local.pathClass)
	}

	public := mkCand("198.51.100.20:27014", 0, false, false)
	public.pathClass = candidatePathRelay
	c.setCandidatePath(public, candidatePathDirect)
	if public.pathClass != candidatePathDirect {
		t.Fatalf("advertised public entry path = %q, want Direct", public.pathClass)
	}
	c.setCandidatePath(public, candidatePathRelay)
	if public.pathClass != candidatePathDirect {
		t.Fatal("configured relay role downgraded authenticated direct provenance")
	}
}

// mkCand builds a serverCandidate with the given characteristics for routing tests.
func mkCand(addr string, rtt time.Duration, online, lan bool) *serverCandidate {
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	hint := ""
	if lan {
		hint = candidatePathLAN
	}
	return &serverCandidate{
		addrStr:    addr,
		udpAddr:    udpAddr,
		online:     online,
		rtt:        rtt,
		isLAN:      lan,
		pathClass:  hint,
		lastActive: time.Now(),
	}
}

func TestClientModeRouting(t *testing.T) {
	cfg := config.DefaultClientConfig()

	lan := mkCand("192.168.1.5:27014", 1*time.Millisecond, true, true)
	wanSlow := mkCand("203.0.113.1:27014", 50*time.Millisecond, true, false)
	wanFast := mkCand("198.51.100.1:27014", 20*time.Millisecond, true, false)
	wanSlow.pathClass = "relay"
	wanFast.pathClass = "direct"

	c := &Client{cfg: cfg}

	// relay-only: LAN candidates must be excluded.
	cfg.Mode = "relay-only"
	c.candidates = []*serverCandidate{lan, wanSlow}
	c.bestCandidate = wanSlow
	c.selectBestCandidate()
	if c.bestCandidate != wanSlow {
		t.Fatalf("relay-only: expected WAN candidate, got %s", c.bestCandidate.addrStr)
	}

	// direct-only: non-LAN candidates must be excluded.
	cfg.Mode = "direct-only"
	c.bestCandidate = lan
	c.selectBestCandidate()
	if c.bestCandidate != lan {
		t.Fatalf("direct-only: expected LAN candidate, got %s", c.bestCandidate.addrStr)
	}

	// enable_lan=false: LAN excluded even in auto mode.
	cfg.Mode = "auto"
	cfg.EnableLAN = false
	c.candidates = []*serverCandidate{lan, wanSlow}
	c.bestCandidate = wanSlow
	c.selectBestCandidate()
	if c.bestCandidate != wanSlow {
		t.Fatalf("enable_lan=false: expected WAN candidate, got %s", c.bestCandidate.addrStr)
	}

	// auto with LAN enabled: LAN candidate wins over lower effective RTT.
	cfg.EnableLAN = true
	c.bestCandidate = wanSlow
	c.selectBestCandidate()
	if c.bestCandidate != lan {
		t.Fatalf("auto: expected LAN candidate, got %s", c.bestCandidate.addrStr)
	}

	// WAN -> WAN switch with meaningful RTT improvement must be honored.
	c.candidates = []*serverCandidate{wanSlow, wanFast}
	c.bestCandidate = wanSlow
	c.selectBestCandidate()
	if c.bestCandidate != wanFast {
		t.Fatalf("auto: expected faster WAN candidate, got %s", c.bestCandidate.addrStr)
	}

	// relay-only must fail closed when no candidate is explicitly classified as
	// relay; a direct or punched endpoint must never become the destination.
	directOnly := mkCand("198.51.100.20:27014", 5*time.Millisecond, true, false)
	directOnly.pathClass = "direct"
	punchOnly := mkCand("198.51.100.21:27014", 4*time.Millisecond, true, false)
	punchOnly.pathClass = "punch"
	punchOnly.isPunch = true
	cfg.Mode = "relay-only"
	c.candidates = []*serverCandidate{directOnly, punchOnly}
	c.bestCandidate = directOnly
	c.selectBestCandidate()
	if c.bestCandidate != nil {
		t.Fatalf("relay-only selected non-relay candidate %s", c.bestCandidate.addrStr)
	}
	if c.candidateAllowed(directOnly) || c.candidateAllowed(punchOnly) {
		t.Fatal("relay-only marked a direct/punch candidate as allowed")
	}

	// Auto/direct-only must also clear a stale route when every candidate is
	// unavailable; retaining the old pointer would keep the data plane sending
	// after the selector has found no legal path.
	c.cfg.Mode = "auto"
	c.candidates = []*serverCandidate{directOnly}
	directOnly.mu.Lock()
	directOnly.online = false
	directOnly.lastActive = time.Time{}
	directOnly.mu.Unlock()
	c.bestCandidate = directOnly
	c.selectBestCandidate()
	if c.bestCandidate != nil {
		t.Fatalf("auto retained unavailable candidate %s", c.bestCandidate.addrStr)
	}
}

func TestRelayOnlyUsesCandidateProvenance(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.Mode = "relay-only"
	c := &Client{cfg: cfg}

	// A configured relay endpoint may resolve to loopback/private space. Its
	// configured provenance still takes priority over address shape.
	localRelay := mkCand("127.0.0.1:27014", 5*time.Millisecond, true, true)
	localRelay.pathClass = candidatePathRelay
	if !c.candidateAllowed(localRelay) {
		t.Fatal("relay-only rejected a configured relay on a local address")
	}

	localRelay.pathClass = candidatePathDirect
	if c.candidateAllowed(localRelay) {
		t.Fatal("relay-only admitted a direct candidate with a local address")
	}
	localRelay.pathClass = ""
	if c.candidateAllowed(localRelay) {
		t.Fatal("relay-only admitted an unclassified candidate")
	}
}

func TestConfiguredRelayDoesNotReceiveLANPreference(t *testing.T) {
	cfg := config.DefaultClientConfig()
	c := &Client{cfg: cfg}

	// Local tunnel processes commonly expose the relay on loopback. Its
	// configured Relay classification must override the address-based LAN
	// hint, otherwise the 10x LAN preference prevents a faster punched path
	// from ever being selected.
	localRelay := mkCand("127.0.0.1:27014", 50*time.Millisecond, true, true)
	localRelay.pathClass = candidatePathRelay
	punch := mkCand("198.51.100.20:27014", 20*time.Millisecond, true, false)
	punch.pathClass = candidatePathPunch
	punch.isPunch = true

	c.candidates = []*serverCandidate{localRelay, punch}
	c.bestCandidate = localRelay
	c.selectBestCandidate()
	if c.bestCandidate != punch {
		t.Fatalf("configured loopback relay retained LAN preference; selected %v", c.bestCandidate)
	}
}

func TestClientServerIntegration(t *testing.T) {
	// 1. Setup mock upstream L4D2 server
	upstreamConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 27015})
	if err != nil {
		t.Fatalf("failed to listen on mock upstream 127.0.0.1:27015: %v", err)
	}
	defer upstreamConn.Close()

	// 2. Start Left4Proxy Server on :27014 with advertised public_ips
	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = "127.0.0.1:27014"
	serverCfg.TargetAddr = "127.0.0.1:27015"
	serverCfg.PublicIPs = []string{"127.0.0.1:27014"}
	serverCfg.AuthKey = integrationKey()

	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// 3. Start Left4Proxy Client on 127.0.0.2:27015 -> 127.0.0.1:27014
	clientCfg := config.DefaultClientConfig()
	clientCfg.ServerAddrs = []string{"127.0.0.1:27014"}
	clientCfg.ListenAddr = "127.0.0.2:27015"
	clientCfg.EnableLAN = true
	clientCfg.AuthKey = serverCfg.AuthKey

	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer cli.Stop()

	time.Sleep(500 * time.Millisecond)

	// 4. Send Source Engine A2S_INFO query UDP packet from mock game client to 127.0.0.2:27015
	mockGameConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 27015})
	if err != nil {
		t.Fatalf("failed to dial local client 127.0.0.2:27015: %v", err)
	}
	defer mockGameConn.Close()

	a2sQuery := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'T', 'S', 'o', 'u', 'r', 'c', 'e', ' ', 'E', 'n', 'g', 'i', 'n', 'e', ' ', 'Q', 'u', 'e', 'r', 'y', 0x00}
	_, err = mockGameConn.Write(a2sQuery)
	if err != nil {
		t.Fatalf("failed to write A2S_INFO packet to client listener: %v", err)
	}

	// 5. Verify upstream server receives packet
	buf := make([]byte, 1024)
	_ = upstreamConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, srcAddr, err := upstreamConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("upstream server failed to receive proxied L4D2 packet: %v", err)
	}

	if n < len(a2sQuery) {
		t.Fatalf("expected packet size >= %d, got %d", len(a2sQuery), n)
	}
	t.Logf("Successfully proxied L4D2 packet through Left4Proxy! Received %d bytes from %s", n, srcAddr.String())
}

func TestClientStatusReporting(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.ListenAddr = "127.0.0.2:27015"
	cfg.Mode = "auto"
	cfg.EnablePunch = true

	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	candPunch := mkCand("1.2.3.4:27015", 25*time.Millisecond, true, false)
	candPunch.isPunch = true
	candPunch.pathClass = "punch"
	candPunch.pubEndpoint = "114.240.1.2:58210"
	candPunch.lastReflected = "114.240.1.2:58210"

	candRelay := mkCand("5.6.7.8:27014", 60*time.Millisecond, false, false)
	candRelay.pathClass = "relay"

	cli.candidates = []*serverCandidate{candPunch, candRelay}
	cli.bestCandidate = candPunch
	cli.sessionID.Store(987654321)

	// Status snapshot
	st := cli.Status()
	if st.SessionID != 987654321 {
		t.Errorf("expected session ID 987654321, got %d", st.SessionID)
	}
	if st.ListenAddr != "127.0.0.2:27015" {
		t.Errorf("expected listen addr 127.0.0.2:27015, got %s", st.ListenAddr)
	}
	if len(st.Candidates) != 2 {
		t.Errorf("expected 2 candidates, got %d", len(st.Candidates))
	}
	if !st.Candidates[0].IsActive {
		t.Errorf("expected candidate 0 to be active")
	}
	if st.ActivePath != router.PathPunch {
		t.Errorf("active path = %q, want actual candidate path %q", st.ActivePath, router.PathPunch)
	}

	// Test game connection tracking
	gameAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51234")
	cli.trackGameConnection(gameAddr)

	stActiveGame := cli.Status()
	if !stActiveGame.GameConnected || stActiveGame.GameAddr != "127.0.0.1:51234" {
		t.Errorf("expected game connection to 127.0.0.1:51234, got %v (%s)", stActiveGame.GameConnected, stActiveGame.GameAddr)
	}

	// Set mock NAT info
	mockNAT := &stun.NATMappingInfo{
		Behavior:    stun.MappingEndpointIndependent,
		PrimaryAddr: &net.UDPAddr{IP: net.ParseIP("114.240.1.2"), Port: 58210},
	}
	cli.natInfo.Store(mockNAT)

	// Verify formatted status output
	formatted := cli.FormatStatus()
	if !strings.Contains(formatted, "987654321") {
		t.Errorf("formatted status missing session ID: %s", formatted)
	}
	if !strings.Contains(formatted, "114.240.1.2:58210") {
		t.Errorf("formatted status missing STUN endpoint: %s", formatted)
	}
	if !strings.Contains(formatted, "127.0.0.1:51234") {
		t.Errorf("formatted status missing game addr: %s", formatted)
	}
	if !strings.Contains(formatted, "NAT Mapping Type") || !strings.Contains(formatted, "Cone NAT") {
		t.Errorf("formatted status missing NAT info: %s", formatted)
	}

	// Test SetMode / GetMode
	if err := cli.SetMode("relay-only"); err != nil {
		t.Fatalf("SetMode error: %v", err)
	}
	if cli.GetMode() != "relay-only" {
		t.Errorf("expected mode relay-only, got %s", cli.GetMode())
	}
}
