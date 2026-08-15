package client

import (
	"bytes"
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

// gameConnIdleTimeout is how long the game netchannel socket can be silent
// before the client logs it as closed (the game returned to the main menu or
// its connection dropped). The game keeps sending heartbeats/timesync while
// connected, so 30s is well beyond normal idle.
const gameConnIdleTimeout = 30 * time.Second

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
	prevCandidate    *serverCandidate // Previous candidate for temporary dual-sending during route transition.
	dualSendUntil    time.Time        // End timestamp for dual-sending window.
	candidateMu      sync.RWMutex
	lastClientAddr   atomic.Pointer[net.UDPAddr] // Game netchannel socket (set by localReadLoop, read by handleServerPacket).
	a2sQueryAddr     atomic.Pointer[net.UDPAddr] // Server-browser A2S query socket (separate from the game netchannel socket).
	gameConnAddr     atomic.Pointer[net.UDPAddr] // Current game netchannel socket, for open/close logging.
	gameConnLastSeen atomic.Int64                // UnixNano of the last packet from the game netchannel socket.
	natInfo          atomic.Pointer[stun.NATMappingInfo]
	router           *router.Router
	holePuncher      *stun.HolePuncher
	lastReportedPath router.PathType
	lastReportedCand string
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

// isA2SQuery reports whether a local payload is a Source Engine server query
// (A2S challenge / info request, "ff ff ff ff 54 Source Engine Query").
//
// The game issues these from its server-browser socket, which is a DIFFERENT
// UDP socket than the one carrying the netchannel. Responses to it must be
// routed back to that socket: if they land on the netchannel socket instead,
// the netchannel sees a spurious 0x41 challenge and disconnects with
// "Invalid challenge packet".
func isA2SQuery(payload []byte) bool {
	return len(payload) > 20 &&
		payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF &&
		payload[4] == 0x54 && bytes.HasPrefix(payload[5:], []byte("Source Engine Query"))
}

// isA2SResponse reports whether a relay payload is an A2S response that belongs
// to the server-browser query socket:
//
//   - the A2S challenge response is exactly 9 bytes: ff ff ff ff 41 + 4-byte
//     challenge. This length distinguishes it from the (much longer) netchannel
//     connect challenge response, which is also type 0x41.
//   - the A2S info response (0x49) is always a query response.
func isA2SResponse(payload []byte) bool {
	if len(payload) < 5 || payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF {
		return false
	}
	if payload[4] == 0x41 {
		return len(payload) == 9 // A2S challenge response only (connect challenge is longer)
	}
	return payload[4] == 0x49 // A2S info response
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

	s.wg.Add(3)
	go s.localReadLoop()
	go s.pingProbeLoop()
	go s.detectNATLoop()

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
// public endpoint on this socket via multi-STUN racing, tell the server so it opens a hole
// toward us, then probe the server's public endpoint until a direct path is
// confirmed or we give up and keep the relay.
func (s *Client) establishPunch(cand *serverCandidate) {
	defer s.wg.Done()

	// Multi-STUN server resolution for racing & redundancy
	stunCandidates := []string{}
	if s.cfg.StunServer != "" {
		stunCandidates = append(stunCandidates, s.cfg.StunServer)
	}
	stunCandidates = append(stunCandidates, stun.DefaultStunServers...)
	stunAddrs := stun.ResolveStunServers(stunCandidates)
	if len(stunAddrs) == 0 {
		log.Printf("[Client] Bad stun_server %q and fallback servers unreachable", s.cfg.StunServer)
		s.punchFailed(cand)
		return
	}
	log.Printf("[Client] Initiating STUN hole punch -> racing %d public STUN servers for endpoint discovery", len(stunAddrs))

	// PunchInit must carry a real session ID so the server maps it to our
	// session; wait for the handshake to complete if needed.
	for s.sessionID.Load() == 0 {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}

	// 1. Discover C_direct on the punch socket via parallel multi-STUN racing.
	for i := 0; i < 2; i++ {
		stun.SendMultiBindingRequests(cand.conn, stunAddrs)
		time.Sleep(20 * time.Millisecond)
	}
	cDirect := s.waitPublicEndpoint(cand, 2*time.Second)
	initSent := false
	if cDirect != "" {
		s.sendPunchInit(cand, cDirect)
		initSent = true
	}

	// 2. Probe the server's public endpoint until confirmed or timed out.
	cand.mu.RLock()
	sendTo := cand.sendTo
	cand.mu.RUnlock()

	// Immediately send an initial burst of 5 probes to establish client NAT mapping within ~100ms
	go stun.SendBurstProbes(cand.conn, sendTo, s.sessionID.Load(), 5, 25*time.Millisecond)

	probePkt := protocol.NewPacket(protocol.CmdStunProbe, s.sessionID.Load(), 0, []byte("PUNCH"))
	probeData := probePkt.Marshal()
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

		oldBest := s.bestCandidate
		s.bestCandidate = best
		if oldBest != nil && oldBest.online && oldBest != best {
			s.prevCandidate = oldBest
			s.dualSendUntil = time.Now().Add(400 * time.Millisecond)
			log.Printf("[Client] Route migration: Dual-sending to [%s] and [%s] for 400ms (0-RTT handoff)", best.addrStr, oldBest.addrStr)
		}

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

		payload := buf[:n]

		if !protocol.IsL4D2Packet(payload) {
			continue
		}

		// The game's server browser queries (A2S) come from a separate UDP
		// socket than the netchannel. Remember it so the query's response is
		// routed back to it instead of being dumped on the netchannel socket,
		// where it looks like a bogus connection challenge and drops the game
		// with "Invalid challenge packet".
		if isA2SQuery(payload) {
			s.a2sQueryAddr.Store(clientAddr)
			// Do NOT let the query socket overwrite lastClientAddr — that is
			// the game netchannel socket, which every game response is routed
			// to. Letting the browser socket clobber it would misroute game
			// responses to the browser. A2S queries are still forwarded below.
		} else {
			s.lastClientAddr.Store(clientAddr)
			s.trackGameConnection(clientAddr)
		}

		seq := atomic.AddUint32(&s.seq, 1)
		pkt := protocol.NewPacket(protocol.CmdData, s.sessionID.Load(), seq, payload)
		marshaled := pkt.Marshal()

		s.candidateMu.RLock()
		activeCand := s.bestCandidate
		prevCand := s.prevCandidate
		dualUntil := s.dualSendUntil
		s.candidateMu.RUnlock()

		if activeCand != nil {
			_ = activeCand.send(marshaled)
			// 0-RTT dual-sending: during route migration, send to both paths to prevent single packet drops
			if prevCand != nil && prevCand != activeCand && time.Now().Before(dualUntil) {
				_ = prevCand.send(marshaled)
			}
		}
	}
}

// trackGameConnection logs when the game's netchannel socket opens or changes,
// and records when it was last seen. The game can restart its connection from a
// new local socket (reconnect after a drop / map change) — knowing when that
// happens makes the client-side connection lifecycle visible in the log.
func (s *Client) trackGameConnection(addr *net.UDPAddr) {
	cur := s.gameConnAddr.Load()
	if cur == nil {
		log.Printf("[Client] Game connection socket opened: %s", addr)
	} else if cur.String() != addr.String() {
		log.Printf("[Client] Game connection socket changed %s -> %s (reconnect)", cur, addr)
	}
	s.gameConnAddr.Store(addr)
	s.gameConnLastSeen.Store(time.Now().UnixNano())
}

// checkGameConnectionClosed logs when the game connection socket goes quiet for
// gameConnIdleTimeout (the game returned to the main menu / disconnected).
// Called from pingProbeLoop.
func (s *Client) checkGameConnectionClosed() {
	addr := s.gameConnAddr.Load()
	if addr == nil {
		return
	}
	last := s.gameConnLastSeen.Load()
	if time.Since(time.Unix(0, last)) > gameConnIdleTimeout {
		log.Printf("[Client] Game connection socket closed (no traffic for %v): %s", gameConnIdleTimeout, addr)
		s.gameConnAddr.Store(nil)
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
		if len(pkt.Payload) == 0 {
			break
		}
		// A2S query responses belong to the server-browser socket, NOT the
		// game's netchannel socket. Sending them to lastClientAddr (the last
		// local sender — often the netchannel ack) makes the netchannel see a
		// spurious 0x41 challenge and abort with "Invalid challenge packet".
		if isA2SResponse(pkt.Payload) {
			if a2s := s.a2sQueryAddr.Load(); a2s != nil {
				_, _ = s.localConn.WriteToUDP(pkt.Payload, a2s)
				break
			}
		}
		if addr := s.lastClientAddr.Load(); addr != nil {
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
			// Log when the game connection socket goes quiet (game left / dropped).
			s.checkGameConnectionClosed()

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

				gameActive := s.gameConnAddr.Load() != nil
				// Normal timeout is 15s. However, during active gameplay on a punched path,
				// if no packet is received for > 2.5s, trigger fast failover to Relay to prevent game disconnect.
				maxStale := 15 * time.Second
				if gameActive && isPunch {
					maxStale = 2500 * time.Millisecond
				}

				if !lastActive.IsZero() && now.Sub(lastActive) <= maxStale {
					cand.mu.Lock()
					cand.online = true
					cand.mu.Unlock()
					anyOnline = true
					_ = cand.send(marshaledPing)
				} else {
					if gameActive && isPunch && cand.online {
						log.Printf("[Client] Fast failover: Punch candidate [%s] unresponsive (>2.5s) during active game -> fallback to Relay", cand.addrStr)
					}
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

// CandidateStatus holds snapshot information about a server candidate.
type CandidateStatus struct {
	Addr          string          `json:"addr"`
	ResolvedIP    string          `json:"resolved_ip"`
	Online        bool            `json:"online"`
	RTT           time.Duration   `json:"rtt"`
	PathType      router.PathType `json:"path_type"`
	PathHint      string          `json:"path_hint"`
	IsLAN         bool            `json:"is_lan"`
	IsPunch       bool            `json:"is_punch"`
	IsActive      bool            `json:"is_active"`
	LastActive    time.Time       `json:"last_active"`
	PubEndpoint   string          `json:"pub_endpoint,omitempty"`
	LastReflected string          `json:"last_reflected,omitempty"`
}

// ClientStatus holds snapshot information about the client state.
type ClientStatus struct {
	SessionID       uint64               `json:"session_id"`
	ListenAddr      string               `json:"listen_addr"`
	Mode            string               `json:"mode"`
	ActivePath      router.PathType      `json:"active_path"`
	ActiveCandidate string               `json:"active_candidate"`
	ActiveRTT       time.Duration        `json:"active_rtt"`
	GameConnected   bool                 `json:"game_connected"`
	GameAddr        string               `json:"game_addr,omitempty"`
	GameLastSeen    time.Time            `json:"game_last_seen,omitempty"`
	PunchEnabled    bool                 `json:"punch_enabled"`
	NATSummary      string               `json:"nat_summary"`
	NATInfo         *stun.NATMappingInfo `json:"nat_info,omitempty"`
	Candidates      []CandidateStatus    `json:"candidates"`
}

// Status returns a point-in-time snapshot of the client state.
func (s *Client) Status() ClientStatus {
	s.candidateMu.RLock()
	activeCand := s.bestCandidate
	cands := make([]*serverCandidate, len(s.candidates))
	copy(cands, s.candidates)
	mode := s.cfg.Mode
	listenAddr := s.cfg.ListenAddr
	enablePunch := s.cfg.EnablePunch
	s.candidateMu.RUnlock()

	activeCandStr := ""
	var activeRTT time.Duration
	if activeCand != nil && activeCand.online {
		activeCandStr = activeCand.addrStr
		activeCand.mu.RLock()
		activeRTT = activeCand.rtt
		if activeCand.udpAddr != nil && activeCand.addrStr != activeCand.udpAddr.String() {
			activeCandStr = fmt.Sprintf("%s (%s)", activeCand.addrStr, activeCand.udpAddr.String())
		}
		activeCand.mu.RUnlock()
	}

	gameAddr := s.gameConnAddr.Load()
	gameLastSeenNano := s.gameConnLastSeen.Load()
	gameConnected := gameAddr != nil
	var gameLastSeen time.Time
	var gameAddrStr string
	if gameLastSeenNano > 0 {
		gameLastSeen = time.Unix(0, gameLastSeenNano)
	}
	if gameAddr != nil {
		gameAddrStr = gameAddr.String()
	}

	natInfo := s.natInfo.Load()
	natSummary := stun.FormatNATSummary(natInfo)

	candStatuses := make([]CandidateStatus, 0, len(cands))
	for _, c := range cands {
		c.mu.RLock()
		resolvedIP := ""
		if c.udpAddr != nil {
			resolvedIP = c.udpAddr.String()
		}
		isActive := (c == activeCand && c.online)
		candStatuses = append(candStatuses, CandidateStatus{
			Addr:          c.addrStr,
			ResolvedIP:    resolvedIP,
			Online:        c.online,
			RTT:           c.rtt,
			PathType:      s.pathForCandidate(c),
			PathHint:      c.pathHint,
			IsLAN:         c.isLAN,
			IsPunch:       c.isPunch,
			IsActive:      isActive,
			LastActive:    c.lastActive,
			PubEndpoint:   c.pubEndpoint,
			LastReflected: c.lastReflected,
		})
		c.mu.RUnlock()
	}

	return ClientStatus{
		SessionID:       s.sessionID.Load(),
		ListenAddr:      listenAddr,
		Mode:            mode,
		ActivePath:      s.router.CurrentPath(),
		ActiveCandidate: activeCandStr,
		ActiveRTT:       activeRTT,
		GameConnected:   gameConnected,
		GameAddr:        gameAddrStr,
		GameLastSeen:    gameLastSeen,
		PunchEnabled:    enablePunch,
		NATSummary:      natSummary,
		NATInfo:         natInfo,
		Candidates:      candStatuses,
	}
}

// FormatStatus returns a human-readable, well-formatted status string.
func (s *Client) FormatStatus() string {
	st := s.Status()
	var b strings.Builder

	b.WriteString("\n============================= Left4Proxy Status =============================\n")
	if st.SessionID != 0 {
		fmt.Fprintf(&b, "  Session ID       : %d\n", st.SessionID)
	} else {
		b.WriteString("  Session ID       : Not established (Waiting for handshake)\n")
	}
	fmt.Fprintf(&b, "  Listen Address   : %s\n", st.ListenAddr)
	fmt.Fprintf(&b, "  Routing Mode     : %s\n", st.Mode)

	if st.ActiveCandidate != "" {
		rttStr := "N/A"
		if st.ActiveRTT > 0 && st.ActiveRTT < 900*time.Millisecond {
			rttStr = fmt.Sprintf("%.1fms", float64(st.ActiveRTT)/float64(time.Millisecond))
		}
		fmt.Fprintf(&b, "  Active Route     : [%s] -> %s (RTT: %s)\n", st.ActivePath, st.ActiveCandidate, rttStr)
	} else {
		b.WriteString("  Active Route     : None (All candidates offline / Handshaking)\n")
	}

	if st.GameConnected {
		ago := time.Since(st.GameLastSeen).Truncate(100 * time.Millisecond)
		fmt.Fprintf(&b, "  Game Connection  : Active (%s, last packet %v ago)\n", st.GameAddr, ago)
	} else if !st.GameLastSeen.IsZero() {
		ago := time.Since(st.GameLastSeen).Truncate(time.Second)
		fmt.Fprintf(&b, "  Game Connection  : Idle (Disconnected %v ago)\n", ago)
	} else {
		b.WriteString("  Game Connection  : Idle (No game connected yet)\n")
	}

	fmt.Fprintf(&b, "  NAT Mapping Type : %s\n", st.NATSummary)

	punchStr := "Disabled"
	if st.PunchEnabled {
		punchStr = "Enabled"
	}
	fmt.Fprintf(&b, "  STUN Hole Punch  : %s\n", punchStr)

	fmt.Fprintf(&b, "\nCandidates (%d):\n", len(st.Candidates))
	for i, c := range st.Candidates {
		marker := "  "
		if c.IsActive {
			marker = "* "
		}

		statusStr := "Offline"
		rttStr := "N/A"
		if c.Online {
			statusStr = "Online"
			if c.RTT > 0 && c.RTT < 900*time.Millisecond {
				rttStr = fmt.Sprintf("%.1fms", float64(c.RTT)/float64(time.Millisecond))
			}
		}

		addrDisplay := c.Addr
		if c.ResolvedIP != "" && c.ResolvedIP != c.Addr {
			addrDisplay = fmt.Sprintf("%s (%s)", c.Addr, c.ResolvedIP)
		}

		lastSeenStr := "Never"
		if !c.LastActive.IsZero() {
			lastSeenStr = fmt.Sprintf("%v ago", time.Since(c.LastActive).Truncate(100*time.Millisecond))
		}

		fmt.Fprintf(&b, "%s[%d] %-8s %s\n", marker, i+1, fmt.Sprintf("[%s]", c.PathType), addrDisplay)
		fmt.Fprintf(&b, "      Status: %-7s | RTT: %-7s | LAN: %-5v | Last Seen: %s\n",
			statusStr, rttStr, c.IsLAN, lastSeenStr)

		if c.PubEndpoint != "" {
			fmt.Fprintf(&b, "      Local NAT Mapped : %s\n", c.PubEndpoint)
		}
		if c.LastReflected != "" && c.LastReflected != c.PubEndpoint {
			fmt.Fprintf(&b, "      Reflected Addr   : %s\n", c.LastReflected)
		}
	}
	b.WriteString("=============================================================================\n")

	return b.String()
}

// detectNATLoop runs NAT detection on start.
func (s *Client) detectNATLoop() {
	defer s.wg.Done()
	s.DetectNAT()
}

// DetectNAT performs STUN-based NAT mapping detection and updates the cached NAT info.
func (s *Client) DetectNAT() *stun.NATMappingInfo {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	stunServer := ""
	if s.cfg != nil {
		stunServer = s.cfg.StunServer
	}
	info, err := stun.DetectClientNAT(ctx, stunServer, 3*time.Second)
	if err != nil {
		log.Printf("[Client] STUN NAT detection: %v", err)
		return nil
	}
	s.natInfo.Store(info)
	log.Printf("[Client] Local NAT Type detected -> %s", stun.FormatNATSummary(info))
	return info
}

// Probe actively sends ping probe packets to all candidates and refreshes route state and NAT type.
func (s *Client) Probe() {
	seq := atomic.AddUint32(&s.seq, 1)
	pingPkt := protocol.NewPacket(protocol.CmdPing, s.sessionID.Load(), seq, []byte("PING"))
	marshaledPing := pingPkt.Marshal()

	s.candidateMu.RLock()
	cands := make([]*serverCandidate, len(s.candidates))
	copy(cands, s.candidates)
	s.candidateMu.RUnlock()

	for _, cand := range cands {
		_ = cand.send(marshaledPing)
		cand.mu.RLock()
		isPunch := cand.isPunch
		online := cand.online
		cand.mu.RUnlock()
		if !isPunch && !online {
			s.sendHandshake(cand)
		}
	}

	// Trigger async NAT re-detection if unknown
	if s.natInfo.Load() == nil {
		go s.DetectNAT()
	}

	time.Sleep(100 * time.Millisecond)
	s.selectBestCandidate()
}

// SetMode changes the routing mode dynamically ("auto", "direct-only", "relay-only").
func (s *Client) SetMode(mode string) error {
	switch strings.ToLower(mode) {
	case "auto":
		mode = "auto"
	case "direct-only", "direct":
		mode = "direct-only"
	case "relay-only", "relay":
		mode = "relay-only"
	default:
		return fmt.Errorf("invalid route mode %q: must be 'auto', 'direct-only' (or 'direct'), or 'relay-only' (or 'relay')", mode)
	}

	s.candidateMu.Lock()
	s.cfg.Mode = mode
	s.candidateMu.Unlock()

	s.router.SetMode(mode)
	s.selectBestCandidate()
	log.Printf("[Client] Route mode switched to: %s", mode)
	return nil
}

// GetMode returns the current routing mode.
func (s *Client) GetMode() string {
	s.candidateMu.RLock()
	defer s.candidateMu.RUnlock()
	return s.cfg.Mode
}
