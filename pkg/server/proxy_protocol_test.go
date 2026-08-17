package server

import (
	"bytes"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/proxyproto"
	"left4proxy/pkg/security"
)

type logRecorder struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes chan struct{}
}

func newLogRecorder() *logRecorder {
	return &logRecorder{writes: make(chan struct{}, 1)}
}

func (r *logRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	n, err := r.buf.Write(p)
	r.mu.Unlock()
	select {
	case r.writes <- struct{}{}:
	default:
	}
	return n, err
}

func (r *logRecorder) Reset() {
	r.mu.Lock()
	r.buf.Reset()
	r.mu.Unlock()
}

func (r *logRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func (r *logRecorder) waitFor(t *testing.T, text string, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		if strings.Contains(r.String(), text) {
			return
		}
		select {
		case <-r.writes:
		case <-timer.C:
			t.Fatalf("timed out waiting for log %q; got %q", text, r.String())
		}
	}
}

func sendProxyV2Packet(t *testing.T, conn *net.UDPConn, serverAddr, realClientAddr *net.UDPAddr, wire []byte) {
	t.Helper()
	header, err := proxyproto.BuildV2Header(realClientAddr, serverAddr)
	if err != nil {
		t.Fatalf("build PROXY v2 header: %v", err)
	}
	datagram := append(header, wire...)
	if _, err := conn.WriteToUDP(datagram, serverAddr); err != nil {
		t.Fatalf("send proxied datagram: %v", err)
	}
}

func proxiedServerHandshake(t *testing.T, conn *net.UDPConn, serverAddr, realClientAddr *net.UDPAddr, key []byte) (uint64, *security.Session, *security.HandshakeResponse) {
	t.Helper()
	req, pending, err := security.NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatalf("create handshake: %v", err)
	}
	sendProxyV2Packet(t, conn, serverAddr, realClientAddr, req.Marshal())

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read proxied handshake: %v", err)
		}
		pkt, err := protocol.Unmarshal(buf[:n])
		if err != nil || pkt.Cmd != protocol.CmdHandshakeResp {
			continue
		}
		response, session, err := security.VerifyHandshakeResponse(key, pkt, pending, time.Now().UnixNano())
		if err != nil {
			continue
		}
		return response.SessionID, session, response
	}
}

func serverHandshakeWithResponse(t *testing.T, conn *net.UDPConn, serverAddr *net.UDPAddr, key []byte) (*security.HandshakeResponse, *security.Session) {
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
		response, session, err := security.VerifyHandshakeResponse(key, pkt, pending, time.Now().UnixNano())
		if err == nil {
			return response, session
		}
	}
}

func waitForProxySenderAddress(t *testing.T, srv *Server, source, want *net.UDPAddr) time.Time {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.proxySenderMu.Lock()
		state := srv.proxySenderStates[source.String()]
		got := (*net.UDPAddr)(nil)
		var lastSeen time.Time
		if state != nil {
			got = cloneUDPAddr(state.realClientAddr)
			lastSeen = state.lastSeen
		}
		srv.proxySenderMu.Unlock()
		if sameUDPAddr(got, want) {
			return lastSeen
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for PROXY sender state %s -> %s", source, want)
	return time.Time{}
}

func waitForProxySenderActivityAfter(t *testing.T, srv *Server, source *net.UDPAddr, after time.Time) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.proxySenderMu.Lock()
		state := srv.proxySenderStates[source.String()]
		var lastSeen time.Time
		if state != nil {
			lastSeen = state.lastSeen
		}
		srv.proxySenderMu.Unlock()
		if lastSeen.After(after) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a subsequent datagram from %s", source)
}

func authenticatedPathHint(t *testing.T, conn *net.UDPConn, serverAddr *net.UDPAddr, session *security.Session) string {
	t.Helper()
	seq, err := session.NextSeq()
	if err != nil {
		t.Fatalf("next ping sequence: %v", err)
	}
	ping := protocol.NewPacket(protocol.CmdPing, session.ID, seq, []byte("PING"))
	wire, err := session.Seal(ping, security.ClientToServer)
	if err != nil {
		t.Fatalf("seal ping: %v", err)
	}
	if _, err := conn.WriteToUDP(wire, serverAddr); err != nil {
		t.Fatalf("send ping: %v", err)
	}

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var path string
	pongSeen := false
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read ping response: %v", err)
		}
		pkt, err := session.Open(buf[:n], security.ServerToClient)
		if err != nil {
			continue
		}
		switch pkt.Cmd {
		case protocol.CmdPong:
			if string(pkt.Payload) != "PONG" {
				t.Fatalf("pong payload = %q, want PONG", pkt.Payload)
			}
			pongSeen = true
		case protocol.CmdPathHint:
			decoded, ok := protocol.DecodePathHint(pkt.Payload)
			if !ok {
				t.Fatalf("invalid authenticated path hint: %q", pkt.Payload)
			}
			path = decoded
		}
		if pongSeen && path != "" {
			return path
		}
	}
}

func TestPathClassificationFollowsProxyEnvelopeNotPublicIPs(t *testing.T) {
	key := serverTestKey()
	srv, err := NewServer(&config.ServerConfig{
		ListenAddr:        "127.0.0.1:0",
		TargetAddr:        "127.0.0.1:27015",
		PublicIPs:         []string{"127.0.0.1"},
		PunchAddr:         "127.0.0.1:1",
		ProxyProtocolV2:   true,
		ProxyTrustedAddrs: []string{"127.0.0.1"},
		AuthKey:           key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)

	directConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer directConn.Close()
	_, directSession := serverHandshakeWithResponse(t, directConn, serverAddr, key)
	defer directSession.Close()
	if got := authenticatedPathHint(t, directConn, serverAddr, directSession); got != protocol.PathHintDirect {
		t.Fatalf("headerless candidate path = %q, want direct", got)
	}

	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	// A second candidate may reuse the session established by the first
	// handshake. Its classification must still follow this candidate's own
	// PROXY prelude, not the cached response's original source.
	sendProxyV2Packet(t, relayConn, serverAddr, &net.UDPAddr{IP: net.ParseIP("198.51.100.55"), Port: 42000}, nil)
	if got := authenticatedPathHint(t, relayConn, serverAddr, directSession); got != protocol.PathHintRelay {
		t.Fatalf("PROXY candidate path = %q, want relay", got)
	}
}

func TestTrustedProxyProtocolV2HandshakeAndPunch(t *testing.T) {
	key := serverTestKey()
	srv, err := NewServer(&config.ServerConfig{
		ListenAddr:        "127.0.0.1:0",
		TargetAddr:        "127.0.0.1:27015",
		PunchAddr:         "127.0.0.1:1",
		ProxyProtocolV2:   true,
		ProxyTrustedAddrs: []string{"127.0.0.1"},
		AuthKey:           key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()

	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	realClientAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.25"), Port: 41000}
	sessionID, session, response := proxiedServerHandshake(t, relayConn, serverAddr, realClientAddr, key)
	defer session.Close()
	if got := strings.SplitN(string(response.Metadata), "|", 2)[0]; got != realClientAddr.String() {
		t.Fatalf("handshake reflected endpoint = %q, want %q", got, realClientAddr)
	}

	punchConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer punchConn.Close()

	seq, err := session.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	punchInit, err := session.Seal(protocol.NewPacket(protocol.CmdPunchInit, sessionID, seq, []byte(punchConn.LocalAddr().String())), security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relayConn.WriteToUDP(punchInit, serverAddr); err != nil {
		t.Fatalf("send post-handshake PunchInit: %v", err)
	}

	buf := make([]byte, 4096)
	_ = relayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := relayConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read punch acknowledgement: %v", err)
		}
		pkt, err := session.Open(buf[:n], security.ServerToClient)
		if err == nil && pkt.Cmd == protocol.CmdPunchAck {
			break
		}
	}

	_ = punchConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := punchConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read server punch probe: %v", err)
		}
		pkt, err := session.Open(buf[:n], security.ServerToClient)
		if err == nil && pkt.Cmd == protocol.CmdStunProbe {
			return
		}
	}
}

func TestOnlyFirstDatagramMaySupplyProxyHeader(t *testing.T) {
	key := serverTestKey()
	srv, err := NewServer(&config.ServerConfig{
		ListenAddr:        "127.0.0.1:0",
		TargetAddr:        "127.0.0.1:27015",
		PunchAddr:         "127.0.0.1:1",
		ProxyProtocolV2:   true,
		ProxyTrustedAddrs: []string{"127.0.0.1"},
		AuthKey:           key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	firstRealAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.27"), Port: 41002}
	secondRealAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.28"), Port: 41003}

	// frp may emit the first trusted PROXY header in a datagram of its own.
	sendProxyV2Packet(t, relayConn, serverAddr, firstRealAddr, nil)
	firstSeen := waitForProxySenderAddress(t, srv, relayConn.LocalAddr().(*net.UDPAddr), firstRealAddr)

	// A later header is ordinary invalid L4DP input, not a replacement source.
	sendProxyV2Packet(t, relayConn, serverAddr, secondRealAddr, nil)
	waitForProxySenderActivityAfter(t, srv, relayConn.LocalAddr().(*net.UDPAddr), firstSeen)

	response, session := serverHandshakeWithResponse(t, relayConn, serverAddr, key)
	defer session.Close()
	if got := strings.SplitN(string(response.Metadata), "|", 2)[0]; got != firstRealAddr.String() {
		t.Fatalf("handshake reflected endpoint = %q, want first PROXY address %q", got, firstRealAddr)
	}
	if got := authenticatedPathHint(t, relayConn, serverAddr, session); got != protocol.PathHintRelay {
		t.Fatalf("first PROXY prelude path = %q, want relay", got)
	}
}

func TestTrustedProxyLocalPreludeClassifiesRelay(t *testing.T) {
	key := serverTestKey()
	srv, err := NewServer(&config.ServerConfig{
		ListenAddr:        "127.0.0.1:0",
		TargetAddr:        "127.0.0.1:27015",
		PunchAddr:         "127.0.0.1:1",
		ProxyProtocolV2:   true,
		ProxyTrustedAddrs: []string{"127.0.0.1"},
		AuthKey:           key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)

	// PROXY v2 LOCAL has no usable real-client endpoint, but it still proves
	// this datagram arrived through a trusted relay.
	header := append([]byte(nil), proxyproto.V2Signature...)
	header = append(header, 0x20, 0x00, 0x00, 0x00)
	if _, err := relayConn.WriteToUDP(header, serverAddr); err != nil {
		t.Fatalf("send LOCAL prelude: %v", err)
	}
	_, session := serverHandshakeWithResponse(t, relayConn, serverAddr, key)
	defer session.Close()
	if got := authenticatedPathHint(t, relayConn, serverAddr, session); got != protocol.PathHintRelay {
		t.Fatalf("LOCAL PROXY candidate path = %q, want relay", got)
	}
}

func TestUntrustedProxyHeaderIsLoggedAndDoesNotBlockNormalL4DP(t *testing.T) {
	recorder := newLogRecorder()
	oldOutput := log.Writer()
	log.SetOutput(recorder)
	defer log.SetOutput(oldOutput)

	key := serverTestKey()
	srv, err := NewServer(&config.ServerConfig{
		ListenAddr:        "127.0.0.1:0",
		TargetAddr:        "127.0.0.1:27015",
		PunchAddr:         "127.0.0.1:1",
		ProxyProtocolV2:   true,
		ProxyTrustedAddrs: []string{"127.0.0.1"},
		AuthKey:           key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	recorder.Reset()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	request, _, err := security.NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	sendProxyV2Packet(t, conn, serverAddr, &net.UDPAddr{IP: net.ParseIP("203.0.113.26"), Port: 41001}, request.Marshal())
	recorder.waitFor(t, "Dropped PROXY header from 127.0.0.2:", 2*time.Second)
	recorder.waitFor(t, "because this address is not in proxy_protocol_trusted_addrs", time.Second)

	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := conn.ReadFromUDP(make([]byte, 4096)); err == nil {
		t.Fatal("untrusted PROXY header unexpectedly received a handshake response")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read after untrusted PROXY header: %v", err)
	}

	// The source whitelist applies only to PROXY envelopes. A normal L4DP
	// handshake from the same untrusted address must remain valid.
	_, session := serverHandshake(t, conn, serverAddr, key)
	defer session.Close()
}

func TestTrustedProxyAddressParsingAndRequiredWhitelist(t *testing.T) {
	networks, err := parseTrustedProxyAddrs([]string{"127.0.0.1", "10.20.0.0/16", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("parse trusted addresses: %v", err)
	}
	if len(networks) != 3 || !networks[1].Contains(net.ParseIP("10.20.99.1")) || !networks[2].Contains(net.ParseIP("2001:db8:1::1")) {
		t.Fatalf("trusted networks = %#v", networks)
	}
	if _, err := parseTrustedProxyAddrs([]string{"not-an-address"}); err == nil {
		t.Fatal("invalid trusted address was accepted")
	}

	srv, err := NewServer(&config.ServerConfig{
		ListenAddr:        "127.0.0.1:0",
		TargetAddr:        "127.0.0.1:27015",
		ProxyProtocolV2:   true,
		ProxyTrustedAddrs: []string{},
		AuthKey:           serverTestKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err == nil {
		srv.Stop()
		t.Fatal("enabled PROXY parser accepted an empty trusted-source whitelist")
	}
}
