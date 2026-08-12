package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/router"
	"left4proxy/pkg/stun"
)

type serverCandidate struct {
	mu            sync.RWMutex
	addrStr       string
	udpAddr       *net.UDPAddr
	conn          *net.UDPConn
	sendTo        *net.UDPAddr // Non-nil only for the punch candidate: an unconnected socket that must use WriteToUDP.
	isPunch       bool         // Punch (STUN hole-punched) candidate.
	pubEndpoint   string       // Punch candidate's own public endpoint (C_direct), learned via STUN reflection.
	lastActive    time.Time
	lastHandshake time.Time // Last handshake attempt to an offline candidate (reconnect backoff).
	rtt           time.Duration
	isLAN         bool
	online        bool
	lastReflected string // Last STUN-reflected public endpoint, for deduped logging.
	pathHint      string // Server's classification: "relay" | "direct" | "punch" | "lan".
}

// send writes data through the candidate's socket. Connected candidate sockets
// use conn.Write; the unconnected punch socket uses WriteToUDP to sendTo.
func (cand *serverCandidate) send(data []byte) error {
	cand.mu.RLock()
	conn := cand.conn
	sendTo := cand.sendTo
	cand.mu.RUnlock()
	if conn == nil {
		return fmt.Errorf("candidate connection is nil")
	}
	if sendTo != nil {
		_, err := conn.WriteToUDP(data, sendTo)
		return err
	}
	_, err := conn.Write(data)
	return err
}

// Client is the Left4Proxy client daemon.
type Client struct {
	cfg              *config.ClientConfig
	sessionID        atomic.Uint64 // Written by handshake responses, read by senders — must be atomic.
	seq              uint32
	localConn        *net.UDPConn
	candidates       []*serverCandidate
	bestCandidate    *serverCandidate
	candidateMu      sync.RWMutex
	lastClientAddr   atomic.Pointer[net.UDPAddr] // Written by localReadLoop, read by handleServerPacket.
	router           *router.Router
	holePuncher      *stun.HolePuncher
	lastReportedPath router.PathType
	lastReportedCand string
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

// NewClient creates a new Client instance.
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:              cfg,
		router:           router.NewRouter(cfg.Mode),
		lastReportedPath: "",
		lastReportedCand: "",
		ctx:              ctx,
		cancel:           cancel,
	}, nil
}

// Start initializes local socket, connects to server candidates, and starts background loops.
func (s *Client) Start() error {
	// 1. Bind local listener (default: 127.0.0.2:27015 - L4D2 loopback requirement)
	localAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve local listen addr %s: %w", s.cfg.ListenAddr, err)
	}

	lConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on local UDP %s: %w", s.cfg.ListenAddr, err)
	}
	s.localConn = lConn

	// 2. Resolve remote server external addresses/domains
	addrs := s.cfg.GetServerAddrs()
	for _, addrStr := range addrs {
		s.addCandidate(addrStr)
	}

	if len(s.candidates) == 0 {
		return fmt.Errorf("no valid server candidates reachable from configured addrs: %v", addrs)
	}

	s.bestCandidate = s.candidates[0]

	// 3. Send initial Handshake across candidates
	s.candidateMu.RLock()
	cands := make([]*serverCandidate, len(s.candidates))
	copy(cands, s.candidates)
	s.candidateMu.RUnlock()

	for _, cand := range cands {
		s.sendHandshake(cand)
	}

	log.Printf("[Client] Left4Proxy Client active on %s | Primary Candidate: %s",
		s.cfg.ListenAddr, s.bestCandidate.addrStr)

	// 4. Start Hole Puncher & Background Loops
	if s.cfg.EnablePunch && s.bestCandidate != nil {
		interval := time.Duration(s.cfg.PingInterval) * time.Second
		if interval <= 0 {
			interval = 3 * time.Second
		}
		s.holePuncher = stun.NewHolePuncher(s.sessionID.Load(), s.bestCandidate.conn, nil)
		s.holePuncher.StartPunching(interval)
		log.Printf("[Client] STUN hole-punching enabled -> candidate [%s] (interval %v)", s.bestCandidate.addrStr, interval)
	} else {
		log.Printf("[Client] STUN hole-punching disabled (enable_punch=%v)", s.cfg.EnablePunch)
	}

	s.wg.Add(2)
	go s.localReadLoop()
	go s.pingProbeLoop()

	return nil
}

// addCandidate resolves endpoint and adds a new candidate if not already tracked by IP:Port.
func (s *Client) addCandidate(addrStr string) (*serverCandidate, bool) {
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, false
	}

	s.candidateMu.Lock()
	defer s.candidateMu.Unlock()

	// Deduplicate by resolved IP:Port rather than input domain string!
	for _, c := range s.candidates {
		if c.udpAddr.String() == udpAddr.String() {
			return c, false
		}
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, false
	}

	// Static LAN check: Private IP space or Loopback
	isLAN := udpAddr.IP.IsPrivate() || udpAddr.IP.IsLoopback()

	cand := &serverCandidate{
		addrStr: addrStr,
		udpAddr: udpAddr,
		conn:    conn,
		online:  false,
		rtt:     999 * time.Millisecond,
		isLAN:   isLAN,
	}
	s.candidates = append(s.candidates, cand)

	s.wg.Add(1)
	go s.candidateReadLoop(cand)

	log.Printf("[Client] Discovered Candidate Endpoint: [%s] (IP: %s, LAN: %v)", addrStr, udpAddr.String(), cand.isLAN)
	return cand, true
}

// maybeCreatePunchCandidate establishes a STUN hole-punched direct candidate
// toward the server's public endpoint. It is a no-op unless punching is enabled
// and the server is reachable via a tunnel — that is the case where a direct
// (non-relay) path is actually valuable.
func (s *Client) maybeCreatePunchCandidate(serverPublic string) {
	if !s.cfg.EnablePunch || s.cfg.Mode == "relay-only" {
		return
	}
	addr, err := net.ResolveUDPAddr("udp", serverPublic)
	if err != nil {
		log.Printf("[Client] Ignoring invalid punch endpoint %q: %v", serverPublic, err)
		return
	}

	s.candidateMu.RLock()
	for _, c := range s.candidates {
		if c.udpAddr.IP.Equal(addr.IP) && c.udpAddr.Port == addr.Port {
			s.candidateMu.RUnlock()
			return // already have this endpoint (e.g. a direct / port-forwarded candidate)
		}
	}
	hasRelay := false
	for _, c := range s.candidates {
		c.mu.RLock()
		hint := c.pathHint
		c.mu.RUnlock()
		if hint == "relay" {
			hasRelay = true
			break
		}
	}
	s.candidateMu.RUnlock()

	if !hasRelay {
		return
	}
	s.addPunchCandidate(addr)
}

// addPunchCandidate creates the unconnected punch socket toward the server's
// public endpoint and starts its read loop and establishment goroutine.
func (s *Client) addPunchCandidate(serverPublic *net.UDPAddr) {
	// Unconnected socket: it must talk to BOTH the public STUN server (to learn
	// this socket's NAT-mapped endpoint) and the server's public endpoint
	// (probes and, after migration, data).
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("[Client] Failed to create punch socket: %v", err)
		return
	}
	cand := &serverCandidate{
		addrStr:  serverPublic.String(),
		udpAddr:  serverPublic,
		conn:     conn,
		sendTo:   serverPublic,
		isPunch:  true,
		rtt:      999 * time.Millisecond,
		pathHint: "punch",
	}
	s.candidateMu.Lock()
	s.candidates = append(s.candidates, cand)
	s.candidateMu.Unlock()

	s.wg.Add(1)
	go s.candidateReadLoop(cand)
	s.wg.Add(1)
	go s.establishPunch(cand)

	log.Printf("[Client] Punch candidate created -> direct endpoint [%s] (socket %s)", serverPublic, conn.LocalAddr())
}

// relayCandidate returns an online candidate used as the control channel to the
// server. The punch negotiation must travel over the tunnel so the server maps
// it to our session.
func (s *Client) relayCandidate() *serverCandidate {
	s.candidateMu.RLock()
	defer s.candidateMu.RUnlock()
	for _, c := range s.candidates {
		c.mu.RLock()
		hint := c.pathHint
		online := c.online
		c.mu.RUnlock()
		if hint == "relay" && online {
			return c
		}
	}
	// Fall back to any online non-punch candidate.
	for _, c := range s.candidates {
		c.mu.RLock()
		isPunch := c.isPunch
		online := c.online
		c.mu.RUnlock()
		if !isPunch && online {
			return c
		}
	}
	return nil
}

// sendPunchInit tells the server (over the relay) the public endpoint of our
// punch socket, so it can open a hole toward us.
func (s *Client) sendPunchInit(cand *serverCandidate, cDirect string) {
	relay := s.relayCandidate()
	if relay == nil {
		return
	}
	pkt := protocol.NewPacket(protocol.CmdPunchInit, s.sessionID.Load(), 0, []byte(cDirect))
	if err := relay.send(pkt.Marshal()); err != nil {
		log.Printf("[Client] PunchInit send failed: %v", err)
		return
	}
	log.Printf("[Client] PunchInit sent (my public endpoint %s) via candidate [%s]", cDirect, relay.addrStr)
}

// waitPublicEndpoint blocks until the punch socket learns its public endpoint
// via STUN reflection (or the timeout elapses).
func (s *Client) waitPublicEndpoint(cand *serverCandidate, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-s.ctx.Done():
			return ""
		default:
		}
		cand.mu.RLock()
		pe := cand.pubEndpoint
		cand.mu.RUnlock()
		if pe != "" {
			return pe
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ""
}

// establishPunch drives the hole-punch exchange for a punch candidate: learn our
// public endpoint on this socket via STUN, tell the server so it opens a hole
// toward us, then probe the server's public endpoint until a direct path is
// confirmed or we give up and keep the relay.
func (s *Client) establishPunch(cand *serverCandidate) {
	defer s.wg.Done()

	stunAddr, err := net.ResolveUDPAddr("udp", s.cfg.StunServer)
	if err != nil {
		log.Printf("[Client] Bad stun_server %q: %v", s.cfg.StunServer, err)
		s.punchFailed(cand)
		return
	}

	// PunchInit must carry a real session ID so the server maps it to our
	// session; wait for the handshake to complete if needed.
	for s.sessionID.Load() == 0 {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}

	// 1. Discover C_direct on the punch socket via the public STUN server.
	binding := stun.BuildBindingRequest()
	for i := 0; i < 3; i++ {
		_, _ = cand.conn.WriteToUDP(binding, stunAddr)
		time.Sleep(20 * time.Millisecond)
	}
	cDirect := s.waitPublicEndpoint(cand, 3*time.Second)
	initSent := false
	if cDirect != "" {
		s.sendPunchInit(cand, cDirect)
		initSent = true
	}

	// 2. Probe the server's public endpoint until confirmed or timed out. The
	// server's replies (CmdStunAck) and any server-initiated probes mark the
	// candidate online in candidateReadLoop, which confirms the direct path.
	probePkt := protocol.NewPacket(protocol.CmdStunProbe, s.sessionID.Load(), 0, []byte("PUNCH"))
	probeData := probePkt.Marshal()
	cand.mu.RLock()
	sendTo := cand.sendTo
	cand.mu.RUnlock()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		_, _ = cand.conn.WriteToUDP(probeData, sendTo)

		cand.mu.RLock()
		online := cand.online
		reflected := cand.lastReflected
		cand.mu.RUnlock()

		if online {
			log.Printf("[Client] Punch path confirmed -> direct endpoint [%s] (socket %s)", cand.udpAddr, cand.conn.LocalAddr())
			s.selectBestCandidate()
			// One-shot diagnostic: once the ping loop has measured the punch
			// candidate's RTT, report how it compares to the current best so it's
			// obvious whether the direct path won or why it didn't.
			go s.logPunchRttDiagnostic(cand)
			return
		}
		// The server reflected our probe (its NAT was open enough) — now we know
		// our real endpoint and can send the init that STUN discovery missed.
		if !initSent && reflected != "" {
			s.sendPunchInit(cand, reflected)
			initSent = true
		}
		time.Sleep(time.Second)
	}
	s.punchFailed(cand)
}

// punchFailed marks the punch candidate dead (relay stays the active path).
func (s *Client) punchFailed(cand *serverCandidate) {
	cand.mu.Lock()
	cand.online = false
	cand.mu.Unlock()
	log.Printf("[Client] Punch to [%s] failed (no direct path), staying on relay", cand.addrStr)
}

// logPunchRttDiagnostic waits (up to ~6s) for the punch candidate's RTT to be
// measured by the normal ping loop, then logs how it compares to the current
// best candidate. This makes the routing decision — and the direct path's real
// latency — visible, so a human can tell "direct is genuinely slower" apart
// from "RTT was never measured".
func (s *Client) logPunchRttDiagnostic(cand *serverCandidate) {
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		cand.mu.RLock()
		punchRTT := cand.rtt
		cand.mu.RUnlock()
		if punchRTT < 999*time.Millisecond {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	cand.mu.RLock()
	punchRTT := cand.rtt
	cand.mu.RUnlock()

	s.candidateMu.RLock()
	best := s.bestCandidate
	s.candidateMu.RUnlock()

	bestRTT := 999 * time.Millisecond
	bestAddr, bestPath := "(none)", "-"
	if best != nil {
		best.mu.RLock()
		bestRTT = best.rtt
		best.mu.RUnlock()
		bestAddr = best.addrStr
		bestPath = string(s.pathForCandidate(best))
	}

	decision := "staying on " + bestPath
	if best == cand {
		decision = "SWITCHED to punch"
	}
	log.Printf("[Client] Punch diagnostic: direct [%s] RTT=%v | best [%s] (%s) RTT=%v -> %s",
		cand.addrStr, punchRTT, bestAddr, bestPath, bestRTT, decision)
}

// sendHandshake transmits a handshake request packet over a candidate's socket.
func (s *Client) sendHandshake(cand *serverCandidate) {
	if cand == nil || cand.conn == nil {
		return
	}
	handshakePkt := protocol.NewPacket(protocol.CmdHandshakeReq, 0, 0, []byte("HANDSHAKE"))
	_ = cand.send(handshakePkt.Marshal())
}

// pathForCandidate maps a candidate to the path type its traffic actually takes.
// LAN candidates are a direct same-subnet path. Non-LAN candidates are labeled
// by the server's handshake hint: reached through a tunnel -> Relay, via a NAT
// mapping on a NATed server -> Punch, otherwise a direct connection to a public
// server -> Direct. Unknown hints (old server) default to Relay, the historical
// safe assumption for a non-LAN candidate.
func (s *Client) pathForCandidate(cand *serverCandidate) router.PathType {
	cand.mu.RLock()
	isLAN := cand.isLAN
	hint := cand.pathHint
	cand.mu.RUnlock()

	if isLAN {
		return router.PathLAN
	}
	switch hint {
	case "relay":
		return router.PathRelay
	case "punch":
		return router.PathPunch
	case "direct":
		return router.PathDirect
	default:
		return router.PathRelay
	}
}

// selectBestCandidate evaluates all candidate endpoints with switching hysteresis.
func (s *Client) selectBestCandidate() {
	s.candidateMu.Lock()
	defer s.candidateMu.Unlock()

	var best *serverCandidate
	var bestEffectiveRTT time.Duration = 999 * time.Second

	now := time.Now()

	for _, cand := range s.candidates {
		cand.mu.RLock()
		lastActive := cand.lastActive
		online := cand.online
		rtt := cand.rtt
		isLAN := cand.isLAN
		pathHint := cand.pathHint
		cand.mu.RUnlock()

		// Apply the routing mode and LAN preference from the config, otherwise the
		// configured mode would have no effect on which candidate actually carries data.
		if isLAN {
			if !s.cfg.EnableLAN || s.cfg.Mode == "relay-only" {
				continue
			}
		} else if s.cfg.Mode == "direct-only" {
			// direct-only means "no tunnel": exclude relay candidates, but keep
			// direct/punch ones. Unknown (handshake not yet completed) is treated
			// as relay, so a fresh candidate is only admitted once classified.
			if pathHint == "relay" || pathHint == "" {
				continue
			}
		}

		if online && !lastActive.IsZero() && now.Sub(lastActive) <= 15*time.Second {
			effRTT := rtt
			if isLAN {
				effRTT = effRTT / 10 // Strongly favor LAN candidates
			}
			if best == nil || effRTT < bestEffectiveRTT {
				best = cand
				bestEffectiveRTT = effRTT
			}
		}
	}

	if best != nil && s.bestCandidate != best {
		// Hysteresis threshold: require a meaningful RTT improvement to switch
		// away from the current candidate — UNLESS the current candidate is
		// offline/stale and can no longer carry data, in which case switch
		// unconditionally to the best remaining online candidate (this is what
		// lets the client fall back to the punched direct path if the relay dies).
		if s.bestCandidate != nil {
			s.bestCandidate.mu.RLock()
			currRTT := s.bestCandidate.rtt
			currLAN := s.bestCandidate.isLAN
			currOnline := s.bestCandidate.online
			currLastActive := s.bestCandidate.lastActive
			s.bestCandidate.mu.RUnlock()

			best.mu.RLock()
			bestLAN := best.isLAN
			bestRTT := best.rtt
			best.mu.RUnlock()

			currDead := !currOnline || now.Sub(currLastActive) > 15*time.Second
			if !currDead {
				if !bestLAN && currLAN {
					// Don't switch away from a live LAN to WAN
					return
				}

				if !bestLAN && !currLAN {
					improvement := currRTT - bestRTT
					if improvement < 5*time.Millisecond && improvement < currRTT/7 {
						// Latency improvement too small, avoid flapping
						return
					}
				}
			}
		}

		s.bestCandidate = best
		best.mu.RLock()
		bestRTT := best.rtt
		bestLAN := best.isLAN
		best.mu.RUnlock()

		// Keep the hole puncher following the active candidate, so STUN keepalives
		// keep the NAT mapping of the path that actually carries data alive.
		if s.cfg.EnablePunch && s.holePuncher != nil {
			best.mu.RLock()
			bestSendTo := best.sendTo
			best.mu.RUnlock()
			s.holePuncher.Retarget(best.conn, bestSendTo)
			log.Printf("[Client] STUN hole-puncher retargeted -> candidate [%s]", best.addrStr)
		}

		log.Printf("[Client] Optimal Route Switch -> Active Candidate: [%s] (IP: %s, RTT: %v, LAN: %v)",
			best.addrStr, best.udpAddr.String(), bestRTT, bestLAN)
	}
}

// localReadLoop captures packets from local L4D2 game client (127.0.0.2:27015).
func (s *Client) localReadLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = s.localConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := s.localConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("[Client] Local read error: %v", err)
				continue
			}
		}

		s.lastClientAddr.Store(clientAddr)
		payload := buf[:n]

		if !protocol.IsL4D2Packet(payload) {
			continue
		}

		seq := atomic.AddUint32(&s.seq, 1)
		pkt := protocol.NewPacket(protocol.CmdData, s.sessionID.Load(), seq, payload)

		s.candidateMu.RLock()
		activeCand := s.bestCandidate
		s.candidateMu.RUnlock()

		if activeCand != nil {
			_ = activeCand.send(pkt.Marshal())
		}
	}
}

// candidateReadLoop is the SOLE reader for a candidate UDP socket.
func (s *Client) candidateReadLoop(cand *serverCandidate) {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = cand.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := cand.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// A transient socket error (e.g. ICMP "connection refused" from a
			// momentarily-downed peer) must NOT kill this read loop — otherwise
			// the candidate can never come back online when the peer returns, and
			// the client would re-handshake it forever (spamming the server with
			// fresh sessions). Only a shutdown/close stops the loop.
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		data := buf[:n]

		// STUN Binding Response from the public STUN server (only expected on the
		// punch socket): reveals this socket's NAT-mapped public endpoint.
		if stun.IsStunResponse(data) {
			if addr, perr := stun.ParseBindingResponse(data); perr == nil {
				cand.mu.Lock()
				if cand.pubEndpoint == "" || cand.pubEndpoint != addr.String() {
					cand.pubEndpoint = addr.String()
					log.Printf("[Client] Punch socket public endpoint discovered -> %s (candidate %s)", addr, cand.addrStr)
				}
				cand.mu.Unlock()
			}
			continue
		}

		pkt, err := protocol.Unmarshal(data)
		if err != nil {
			continue
		}

		cand.mu.Lock()
		cand.lastActive = time.Now()
		cand.online = true
		cand.mu.Unlock()

		// A server-initiated STUN probe on the punch socket proves the
		// server→client direction and keeps both NAT mappings open — reply to the
		// exact source so the reply flows back on the direct path.
		if pkt.Cmd == protocol.CmdStunProbe {
			ack := protocol.NewPacket(protocol.CmdStunAck, pkt.SessionID, pkt.Seq, []byte(stun.ReflectAddress(cand.conn.LocalAddr())))
			_, _ = cand.conn.WriteToUDP(ack.Marshal(), src)
		}

		s.handleServerPacket(cand, pkt)
	}
}

// handleServerPacket handles all incoming server packets from a candidate socket.
func (s *Client) handleServerPacket(cand *serverCandidate, pkt *protocol.Packet) {
	cand.mu.Lock()
	cand.lastActive = time.Now()
	cand.online = true
	cand.mu.Unlock()

	// RTT is only meaningful when the server echoed the client's own timestamp
	// (HandshakeResp and Pong). For CmdData etc. the server stamps its own clock,
	// so measuring RTT there would mix clock skew into the result.
	if pkt.Cmd == protocol.CmdHandshakeResp || pkt.Cmd == protocol.CmdPong {
		rtt := time.Duration(time.Now().UnixNano() - pkt.Timestamp)
		if rtt > 0 && rtt < 10*time.Second {
			cand.mu.Lock()
			cand.rtt = rtt
			cand.mu.Unlock()
		}
	}

	switch pkt.Cmd {
	case protocol.CmdHandshakeResp:
		// Adopt the FIRST session ID the server assigns and keep it for the whole
		// session. The server keeps ONE upstream socket per session ID, so changing
		// the ID later would make it re-dial the L4D2 server from a new source port
		// and drop the player mid-game. Leftover IDs from before a server restart are
		// safe because the server seeds its ID counter randomly (server.NewServer),
		// so a fresh client can never collide with a stale pre-restart ID.
		if pkt.SessionID != 0 {
			s.sessionID.CompareAndSwap(0, pkt.SessionID)
		}

		cand.mu.RLock()
		candRTT := cand.rtt
		cand.mu.RUnlock()

		payloadStr := string(pkt.Payload)
		parts := strings.Split(payloadStr, "|")
		reflected := parts[0]

		// Store the server's path classification so pathForCandidate can label
		// this candidate Direct/Punch/Relay instead of guessing.
		if len(parts) > 2 {
			cand.mu.Lock()
			cand.pathHint = parts[2]
			cand.mu.Unlock()
		}

		log.Printf("[Client] Connected & Handshake Verified -> Candidate [%s] (IP: %s, RTT: %v) | SessionID: %d | Apparent Endpoint: %s",
			cand.addrStr, cand.udpAddr.String(), candRTT, pkt.SessionID, reflected)

		s.router.UpdateMetrics(s.pathForCandidate(cand), candRTT, 0.0)

		// Process server's advertised public_ips / LAN IPs
		if len(parts) > 1 && parts[1] != "" {
			advAddrs := strings.Split(parts[1], ",")
			for _, advAddr := range advAddrs {
				advAddr = strings.TrimSpace(advAddr)
				if advAddr != "" {
					newCand, isNew := s.addCandidate(advAddr)
					if isNew && newCand != nil {
						s.sendHandshake(newCand)
					}
				}
			}
		}

		// 4th field: the server's public punch endpoint. When present, attempt to
		// hole-punch a direct path (the server is behind NAT, reachable via relay).
		if len(parts) > 3 && parts[3] != "" {
			s.maybeCreatePunchCandidate(parts[3])
		}
		s.selectBestCandidate()

	case protocol.CmdPong:
		cand.mu.RLock()
		candRTT := cand.rtt
		cand.mu.RUnlock()

		s.router.UpdateMetrics(s.pathForCandidate(cand), candRTT, 0.0)
		s.selectBestCandidate()

	case protocol.CmdLanAck:
		cand.mu.Lock()
		cand.rtt = 1 * time.Millisecond
		cand.isLAN = true
		cand.mu.Unlock()
		s.router.UpdateMetrics(router.PathLAN, 1*time.Millisecond, 0.0)
		s.selectBestCandidate()

	case protocol.CmdStunAck:
		// A STUN ack is the server reflecting a probe back on the candidate's own
		// socket (NAT keepalive/reflection) — it is not a separate direct data
		// path, so record it under the path the candidate actually carries. Feeding
		// it as PathDirect would mislabel a relayed connection as "direct".
		reflected := string(pkt.Payload)
		firstReflection := false
		cand.mu.Lock()
		if reflected != "" && reflected != cand.lastReflected {
			cand.lastReflected = reflected
			firstReflection = true
		}
		cand.mu.Unlock()
		if firstReflection {
			log.Printf("[Client] STUN reflection OK -> public endpoint [%s] via candidate [%s]", reflected, cand.addrStr)
		}
		cand.mu.RLock()
		stunRTT := cand.rtt
		cand.mu.RUnlock()
		if stunRTT > 0 {
			s.router.UpdateMetrics(s.pathForCandidate(cand), stunRTT, 0.0)
		}
		s.selectBestCandidate()

	case protocol.CmdPunchOffer:
		// The server tells us its public punch endpoint (may arrive as a push
		// for sessions that connected before the server discovered its endpoint).
		offer := string(pkt.Payload)
		if offer != "" {
			s.maybeCreatePunchCandidate(offer)
		}

	case protocol.CmdPunchAck:
		// Server confirmed it received our PunchInit and is probing toward us.
		if !cand.isPunch {
			log.Printf("[Client] Server acknowledged punch init (candidate %s)", cand.addrStr)
		}

	case protocol.CmdData:
		if addr := s.lastClientAddr.Load(); addr != nil && len(pkt.Payload) > 0 {
			_, _ = s.localConn.WriteToUDP(pkt.Payload, addr)
		}
	}
}

// pingProbeLoop pings candidates periodically without spamming logs.
func (s *Client) pingProbeLoop() {
	defer s.wg.Done()
	interval := time.Duration(s.cfg.PingInterval) * time.Second
	if interval <= 0 {
		interval = 3 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			seq := atomic.AddUint32(&s.seq, 1)
			pingPkt := protocol.NewPacket(protocol.CmdPing, s.sessionID.Load(), seq, []byte("PING"))
			marshaledPing := pingPkt.Marshal()

			s.candidateMu.RLock()
			cands := make([]*serverCandidate, len(s.candidates))
			copy(cands, s.candidates)
			s.candidateMu.RUnlock()

			anyOnline := false
			now := time.Now()

			for _, cand := range cands {
				cand.mu.RLock()
				isPunch := cand.isPunch
				lastActive := cand.lastActive
				cand.mu.RUnlock()

				if !lastActive.IsZero() && now.Sub(lastActive) <= 15*time.Second {
					cand.mu.Lock()
					cand.online = true
					cand.mu.Unlock()
					anyOnline = true
					_ = cand.send(marshaledPing)
				} else {
					cand.mu.Lock()
					cand.online = false
					canRehandshake := time.Since(cand.lastHandshake) >= 10*time.Second
					if canRehandshake {
						cand.lastHandshake = time.Now()
					}
					cand.mu.Unlock()

					// Tell the router this candidate's path is down so its path
					// reporting reflects reality (e.g. Relay down -> Punch active).
					s.router.SetInactive(s.pathForCandidate(cand))

					// Throttle reconnects so a long-dead relay doesn't spam the
					// server with a fresh handshake (and a fresh session ID) every
					// 3 seconds. Re-handshaking the punch candidate would mint a
					// NEW session ID anyway; its establishment goroutine handles
					// recovery instead.
					if !isPunch && canRehandshake {
						s.sendHandshake(cand)
					}
				}
			}

			s.selectBestCandidate()

			if !anyOnline {
				s.router.SetInactive(router.PathLAN)
				s.router.SetInactive(router.PathRelay)

				if s.lastReportedCand != "OFFLINE" {
					s.lastReportedCand = "OFFLINE"
					s.lastReportedPath = ""
					log.Printf("[Client] Warning: All server candidates offline. Retrying connection...")
				}
				continue
			}

			s.candidateMu.RLock()
			bestCand := s.bestCandidate
			s.candidateMu.RUnlock()

			curPath := s.router.CurrentPath()
			candKey := ""
			if bestCand != nil {
				candKey = bestCand.udpAddr.String()
			}

			// ONLY log when the active candidate IP:Port OR route mode ACTUALLY changes!
			if curPath != s.lastReportedPath || candKey != s.lastReportedCand {
				s.lastReportedPath = curPath
				s.lastReportedCand = candKey
				log.Printf("[Client] Active Route Switched -> Candidate: [%s] | Mode: [%s]", candKey, curPath)
			}
		}
	}
}

// Stop shuts down the client.
func (s *Client) Stop() {
	s.cancel()
	if s.holePuncher != nil {
		s.holePuncher.Stop()
	}
	if s.localConn != nil {
		_ = s.localConn.Close()
	}

	s.candidateMu.Lock()
	for _, cand := range s.candidates {
		if cand.conn != nil {
			_ = cand.conn.Close()
		}
	}
	s.candidateMu.Unlock()

	s.wg.Wait()
	log.Printf("[Client] Client stopped successfully")
}
