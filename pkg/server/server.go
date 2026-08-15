package server

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/discover"
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/proxyproto"
	"left4proxy/pkg/security"
	"left4proxy/pkg/stun"
)

// maxSessions bounds the number of concurrent client sessions to protect against
// memory/socket exhaustion from handshakes or data packets with forged IDs.
const maxSessions = 2048

// clientSession tracks one client's state on the server.
type clientSession struct {
	mu             sync.RWMutex // Guards addresses / lastActive / punchTarget.
	sessionID      uint64
	rawSenderAddr  *net.UDPAddr // Socket return path (frpc or direct UDP client)
	realClientAddr *net.UDPAddr // Extracted real client public IP:Port (from PROXY protocol or direct)
	allowedSenders map[string]struct{}
	secure         *security.Session
	lastActive     time.Time
	punchTarget    *net.UDPAddr // Client's punch-socket public endpoint (from CmdPunchInit); probed to open the server-side hole.
	punchExpiry    time.Time    // When to stop probing the punch target.
	upstreamMu     sync.Mutex   // Guards upstream dial/close.
	upstream       *net.UDPConn
}

// proxyAddrEntry records the real client endpoint learned from a PROXY protocol
// header for a given raw tunnel sender, plus when it was learned (for pruning).
type proxyAddrEntry struct {
	addr *net.UDPAddr
	ts   time.Time
}

type handshakeCacheEntry struct {
	response  []byte
	client    *clientSession
	clientPub []byte
	created   time.Time
}

// Server is the Left4Proxy server daemon.
type Server struct {
	cfg               *config.ServerConfig
	udpConn           *net.UDPConn
	sessions          map[uint64]*clientSession
	pendingProxyAddrs map[string]*proxyAddrEntry // Map raw tunnel sender IP:Port -> real client UDPAddr
	stunProbeLogged   map[string]bool            // Dedup so only the first STUN probe per sender is logged.
	proxyAddrMu       sync.RWMutex
	sessionMu         sync.RWMutex
	serverPubMu       sync.RWMutex   // Guards serverPublic and upnpCleanup.
	serverPublic      *net.UDPAddr   // The server's NAT-mapped public endpoint (advertised so clients can punch to it).
	upnpCleanup       func()         // Optional UPnP port mapping release callback.
	stunAddrs         []*net.UDPAddr // Resolved public STUN servers for multi-STUN racing.
	stunValidator     *stun.Validator
	authKey           []byte
	handshakeMu       sync.Mutex
	handshakes        map[string]*handshakeCacheEntry
	nextID            uint64
	behindNAT         bool // Whether the server has no public interface IP (for direct vs punch labeling).
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
}

// NewServer creates a new Server instance.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server configuration is nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:               cfg,
		sessions:          make(map[uint64]*clientSession),
		pendingProxyAddrs: make(map[string]*proxyAddrEntry),
		stunProbeLogged:   make(map[string]bool),
		stunValidator:     stun.NewValidator(),
		authKey:           append([]byte(nil), cfg.AuthKey...),
		handshakes:        make(map[string]*handshakeCacheEntry),
		// Seed the session ID counter randomly. After a server restart the counter
		// must NOT restart from 0, otherwise a freshly-connected client could be
		// assigned an ID that a client from before the restart is still using, and
		// the two sessions would collide on the server.
		nextID:    rand.Uint64(),
		behindNAT: determineBehindNAT(cfg.NAT),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start launches the UDP listener and packet processing routines.
func (s *Server) Start() error {
	if len(s.authKey) != security.KeySize {
		return fmt.Errorf("server authentication key is missing or invalid; load the shared .secret file before starting")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve server UDP listen addr %s: %w", s.cfg.ListenAddr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", s.cfg.ListenAddr, err)
	}
	s.udpConn = conn

	log.Printf("[Server] Left4Proxy Server listening on UDP %s | Target L4D2: %s | PROXY Protocol Parser: %v",
		s.cfg.ListenAddr, s.cfg.TargetAddr, s.cfg.ProxyProtocolV2)

	if isWildcardListenAddr(s.cfg.ListenAddr) {
		hostCands := discover.GatherAllLocalCandidates(udpAddr.Port)
		if len(hostCands) > 0 {
			log.Printf("[Server] Auto-discovered local host & IPv6 candidates: %v", hostCands)
		}
	}

	// Attempt UPnP IGD automatic port mapping in background
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		port := udpAddr.Port
		if port > 0 {
			extAddr, cleanup := discover.TryUPnPMapping(s.ctx, port, "Left4Proxy Server")
			if extAddr != nil {
				s.serverPubMu.Lock()
				s.upnpCleanup = cleanup
				s.serverPubMu.Unlock()
				log.Printf("[Server] UPnP IGD port mapping succeeded -> %s", extAddr)
				s.updateServerPublic(extAddr)
			} else {
				log.Printf("[Server] UPnP IGD port mapping not available or disabled on router gateway")
			}
		}
	}()

	s.wg.Add(3)
	go s.readUDPDataLoop()
	go s.cleanupSessionsLoop()
	go s.discoverPublicEndpointLoop()

	return nil
}

// readUDPDataLoop handles incoming UDP packets from clients or fronting tunnels (e.g. frp/HAProxy).
func (s *Server) readUDPDataLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, rawSenderAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("[Server] UDP read error: %v", err)
				continue
			}
		}

		packetData := buf[:n]

		// A STUN response is trusted only when it matches a request issued from
		// this exact socket to this exact STUN server.  A magic cookie alone is
		// not authentication and must never update the advertised endpoint.
		if validated, verr := s.stunValidator.Accept(packetData, rawSenderAddr); verr == nil {
			s.updateServerPublic(validated.Reflected)
			continue
		}

		realClientAddr := rawSenderAddr
		var proxyHeaderAddr *net.UDPAddr

		// If ProxyProtocol is enabled on server, parse incoming PROXY protocol v1/v2 header from frp/HAProxy
		if s.cfg.ProxyProtocolV2 {
			extractedAddr, offset, pErr := proxyproto.ParseHeader(packetData)
			if pErr == nil && extractedAddr != nil {
				// Do not cache an asserted PROXY address yet. The encapsulated
				// handshake must authenticate first; otherwise anyone able to reach
				// this UDP port could poison path classification and reflected IPs.
				proxyHeaderAddr = cloneUDPAddr(extractedAddr)
				realClientAddr = proxyHeaderAddr
				packetData = packetData[offset:]
			} else {
				// Headerless packet from a known tunnel: reuse the cached real
				// address AND refresh its timestamp, otherwise the entry gets pruned
				// after 60s of an active tunnel and the real client IP is lost
				// (reflections would then show the frpc socket address instead).
				s.proxyAddrMu.Lock()
				if pending, ok := s.pendingProxyAddrs[rawSenderAddr.String()]; ok {
					realClientAddr = pending.addr
					pending.ts = time.Now()
				}
				s.proxyAddrMu.Unlock()
			}
		}

		if len(packetData) == 0 {
			continue
		}

		pkt, err := protocol.Unmarshal(packetData)
		if err != nil {
			continue
		}
		if proxyHeaderAddr != nil {
			if pkt.Cmd != protocol.CmdHandshakeReq {
				// A tunnel mapping is established only by an authenticated
				// handshake. Later header-bearing packets reuse that mapping rather
				// than accepting an unverified address change.
				s.proxyAddrMu.Lock()
				entry := s.pendingProxyAddrs[rawSenderAddr.String()]
				if entry != nil {
					// Header-bearing packets are still bound to the address learned
					// by the authenticated handshake, but active traffic must keep
					// that mapping alive instead of letting it expire after 60s.
					entry.ts = time.Now()
				}
				s.proxyAddrMu.Unlock()
				if entry == nil {
					continue
				}
				realClientAddr = entry.addr
			} else {
				if _, err := security.VerifyHandshakeRequest(s.authKey, pkt, time.Now().UnixNano()); err != nil {
					continue
				}
				s.cacheProxyAddress(rawSenderAddr, proxyHeaderAddr)
				log.Printf("[Server] [Authenticated PROXY Protocol] Real Client Endpoint: %s (Raw Sender: %s)",
					proxyHeaderAddr, rawSenderAddr)
			}
		}

		s.handlePacket(packetData, pkt, rawSenderAddr, realClientAddr)
	}
}

func (s *Server) cacheProxyAddress(rawSenderAddr, realClientAddr *net.UDPAddr) {
	if rawSenderAddr == nil || realClientAddr == nil {
		return
	}
	s.proxyAddrMu.Lock()
	s.pendingProxyAddrs[rawSenderAddr.String()] = &proxyAddrEntry{addr: cloneUDPAddr(realClientAddr), ts: time.Now()}
	if len(s.pendingProxyAddrs) > 4096 {
		var oldestKey string
		var oldest time.Time
		for key, entry := range s.pendingProxyAddrs {
			if entry == nil || oldestKey == "" || entry.ts.Before(oldest) {
				oldestKey = key
				if entry != nil {
					oldest = entry.ts
				}
			}
		}
		delete(s.pendingProxyAddrs, oldestKey)
	}
	s.proxyAddrMu.Unlock()
}

// publicEndpointString returns the server's known public punch endpoint, or ""
// if not yet discovered.
func (s *Server) publicEndpointString() string {
	s.serverPubMu.RLock()
	defer s.serverPubMu.RUnlock()
	if s.serverPublic == nil {
		return ""
	}
	return s.serverPublic.String()
}

// updateServerPublic records a discovered public endpoint and, when it changes,
// pushes a CmdPunchOffer to every live session so already-connected clients can
// start punching.
func (s *Server) updateServerPublic(addr *net.UDPAddr) {
	if addr == nil || addr.IP == nil || addr.Port == 0 {
		return
	}
	addr = cloneUDPAddr(addr)
	s.serverPubMu.Lock()
	changed := s.serverPublic == nil || s.serverPublic.String() != addr.String()
	if changed {
		s.serverPublic = addr
	}
	s.serverPubMu.Unlock()

	if changed {
		log.Printf("[Server] Public endpoint discovered -> %s", addr)
		s.broadcastPunchOffer()
	}
}

// broadcastPunchOffer tells every live session the server's public punch
// endpoint, so clients that connected before discovery can still punch.
func (s *Server) broadcastPunchOffer() {
	offer := s.publicEndpointString()
	if offer == "" {
		return
	}

	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	for _, sess := range s.sessions {
		sess.mu.RLock()
		dst := sess.rawSenderAddr
		sess.mu.RUnlock()
		if dst != nil {
			_ = s.sendSessionPacket(sess, protocol.CmdPunchOffer, []byte(offer), dst)
		}
	}
}

// sendSessionPacket is the only server-side path for post-handshake packets.
// It assigns a fresh direction-local sequence and seals the complete packet
// before writing it to the currently authenticated return address.
func (s *Server) sendSessionPacket(sess *clientSession, cmd byte, payload []byte, dst *net.UDPAddr) error {
	return s.sendSessionPacketAt(sess, cmd, payload, dst, time.Now().UnixNano())
}

// sendSessionPacketAt is used for authenticated request/response probes whose
// request timestamp must be echoed verbatim so the client can calculate RTT
// without depending on synchronized clocks.
func (s *Server) sendSessionPacketAt(sess *clientSession, cmd byte, payload []byte, dst *net.UDPAddr, timestamp int64) error {
	if sess == nil || dst == nil || sess.secure == nil || s.udpConn == nil {
		return fmt.Errorf("secure session or destination is unavailable")
	}
	seq, err := sess.secure.NextSeq()
	if err != nil {
		return err
	}
	pkt := protocol.NewPacket(cmd, sess.sessionID, seq, payload)
	pkt.Timestamp = timestamp
	data, err := sess.secure.Seal(pkt, security.ServerToClient)
	if err != nil {
		return err
	}
	_, err = s.udpConn.WriteToUDP(data, dst)
	return err
}

// sendStunBindingRequest sends STUN Binding Requests to resolved STUN servers in parallel
// from the main listener socket so the NAT reveals the server's public endpoint.
func (s *Server) sendStunBindingRequest() {
	if len(s.stunAddrs) == 0 {
		candidates := []string{}
		if s.cfg.StunServer != "" {
			candidates = append(candidates, s.cfg.StunServer)
		}
		candidates = append(candidates, stun.DefaultStunServers...)
		s.stunAddrs = stun.ResolveStunServers(candidates)
		if len(s.stunAddrs) == 0 {
			log.Printf("[Server] Failed to resolve any public STUN servers (configured: %q)", s.cfg.StunServer)
			return
		}
		log.Printf("[Server] Resolved %d public STUN servers for endpoint discovery and racing", len(s.stunAddrs))
	}
	if err := s.stunValidator.SendMultiBindingRequests(s.udpConn, s.stunAddrs); err != nil {
		log.Printf("[Server] STUN request send error: %v", err)
	}
}

// discoverPublicEndpointLoop determines the server's public punch endpoint. If
// punch_addr is configured it is used directly (manual override). Otherwise the
// server periodically sends STUN Binding Requests to multiple STUN servers and
// records the reflected endpoint when the response arrives in readUDPDataLoop.
func (s *Server) discoverPublicEndpointLoop() {
	defer s.wg.Done()

	if s.cfg.PunchAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", s.cfg.PunchAddr)
		if err != nil {
			log.Printf("[Server] Invalid punch_addr %q: %v", s.cfg.PunchAddr, err)
		} else {
			s.updateServerPublic(addr)
			log.Printf("[Server] Using manual punch_addr override -> %s", addr)
		}
		return
	}

	// Initial immediate STUN burst
	for i := 0; i < 2; i++ {
		s.sendStunBindingRequest()
		time.Sleep(100 * time.Millisecond)
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.sendStunBindingRequest()
		}
	}
}

// punchProbeLoop sends CmdStunProbe packets from the main listener socket to a
// client's direct socket. These outbound probes create the server-side NAT
// mapping that lets the client's direct packets in, even on restricted-cone
// NATs. Stops once the punch expires or the server is shutting down.
func (s *Server) punchProbeLoop(sess *clientSession, target *net.UDPAddr) {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		sess.mu.RLock()
		expired := time.Now().After(sess.punchExpiry)
		sess.mu.RUnlock()
		if expired {
			return
		}
		if err := s.sendSessionPacket(sess, protocol.CmdStunProbe, []byte("PUNCH"), target); err != nil {
			return
		}
	}
}

// isWildcardListenAddr reports whether a listen address binds to all network interfaces.
func isWildcardListenAddr(listenAddr string) bool {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	host = strings.TrimSpace(host)
	return host == "" || host == "0.0.0.0" || host == "::" || host == "[::]"
}

// determineBehindNAT decides whether the server is behind NAT (no public IP
// directly on the box). It honors an explicit `nat` config value and falls back
// to inspecting the host's interface addresses.
func determineBehindNAT(conf string) bool {
	switch strings.ToLower(strings.TrimSpace(conf)) {
	case "true", "yes", "1", "on":
		return true
	case "false", "no", "0", "off":
		return false
	}
	return !hasPublicInterfaceIP()
}

// hasPublicInterfaceIP reports whether any interface has a global unicast,
// non-private IP address (i.e. the server itself is directly reachable publicly).
func hasPublicInterfaceIP() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if ip.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}

// classifyPath labels how a client connection reached the server:
//
//	relay  — via a PROXY-protocol tunnel (frp/HAProxy)
//	lan    — client source is private/loopback (same LAN)
//	punch  — direct arrival from a public client, but the server is behind NAT
//	         (client got in via a NAT mapping / hole punch / port-forward)
//	direct — direct arrival from a public client to a public (non-NAT) server
func (s *Server) classifyPath(rawSenderAddr, realClientAddr *net.UDPAddr) string {
	if s.cfg.ProxyProtocolV2 && rawSenderAddr != nil {
		s.proxyAddrMu.RLock()
		_, tunneled := s.pendingProxyAddrs[rawSenderAddr.String()]
		s.proxyAddrMu.RUnlock()
		if tunneled {
			return "relay"
		}
	}
	if realClientAddr != nil && (realClientAddr.IP.IsPrivate() || realClientAddr.IP.IsLoopback()) {
		return "lan"
	}
	if s.behindNAT {
		return "punch"
	}
	return "direct"
}

// handlePacket authenticates a wire packet before dispatching it.  Handshake
// requests are the only clear packets; all other commands must belong to an
// existing secure session.
func (s *Server) handlePacket(wire []byte, pkt *protocol.Packet, rawSenderAddr, realClientAddr *net.UDPAddr) {
	if pkt == nil || rawSenderAddr == nil {
		return
	}
	if pkt.Cmd == protocol.CmdHandshakeReq {
		s.handleHandshake(pkt, rawSenderAddr, realClientAddr)
		return
	}
	s.sessionMu.RLock()
	sess := s.sessions[pkt.SessionID]
	s.sessionMu.RUnlock()
	if sess == nil || sess.secure == nil {
		return
	}
	authorizedSource := s.sessionAllowsSource(sess, rawSenderAddr)
	// Once an authenticated PunchInit has opened the migration window, allow
	// the first valid AEAD packet from the NAT's actual mapped source even when
	// it differs from the STUN-reflected address (symmetric NATs can do this).
	// A fresh authenticated Ping is also a path-binding request: it lets a
	// candidate socket join an existing session without minting a new session
	// (important when several relay/direct addresses front the same server).
	// The packet is still authenticated before the new address is retained.
	if !authorizedSource && pkt.Cmd != protocol.CmdPing && !s.sessionAllowsPunchMigration(sess) {
		return
	}
	opened, err := sess.secure.Open(wire, security.ClientToServer)
	if err != nil {
		return
	}
	pkt = opened
	if !authorizedSource && pkt.Cmd != protocol.CmdPing && !s.sessionAllowsPunchMigration(sess) {
		return
	}
	// Every valid packet keeps the session alive and authorizes this source for
	// future packets. Only game data (or the initial handshake) changes the
	// upstream return path; background pings from alternative candidates must
	// not make server replies leak out of the route selected by relay-only.
	s.authorizeSessionSource(sess, rawSenderAddr, realClientAddr)

	switch pkt.Cmd {
	case protocol.CmdHandshakeReq:
		// Handshake requests return from the authenticated prelude above.
		return

	case protocol.CmdLanProbe:
		_ = s.sendSessionPacket(sess, protocol.CmdLanAck, []byte("LAN_ACK"), rawSenderAddr)

	case protocol.CmdStunProbe:
		respPayload := []byte(reflectAddress(realClientAddr))
		wErr := s.sendSessionPacket(sess, protocol.CmdStunAck, respPayload, rawSenderAddr)

		// Log only the first probe per tunnel sender so STUN keepalives don't
		// spam the server log every few seconds.
		key := rawSenderAddr.String()
		s.proxyAddrMu.Lock()
		first := !s.stunProbeLogged[key]
		if first {
			s.stunProbeLogged[key] = true
		}
		s.proxyAddrMu.Unlock()
		if first {
			log.Printf("[Server] STUN probe from %s (real %s, sid=%d) -> ack sent, wErr=%v", rawSenderAddr, realClientAddr, pkt.SessionID, wErr)
		}

	case protocol.CmdPunchInit:
		// A client asking us to open a hole toward its direct (punch) socket.
		// The payload is the client's public endpoint on that socket. We reply
		// over the control (relay) channel and start probing the target, which
		// creates the server-side NAT mapping that lets the client's direct
		// packets through even on restricted-cone NATs.
		target, perr := stun.ParseReflectedAddress(string(pkt.Payload))
		if perr != nil || target == nil || target.Port == 0 {
			log.Printf("[Server] Bad PunchInit payload %q: %v", pkt.Payload, perr)
			return
		}
		sess.mu.Lock()
		sess.punchTarget = target
		sess.punchExpiry = time.Now().Add(30 * time.Second)
		if sess.allowedSenders == nil {
			sess.allowedSenders = make(map[string]struct{})
		}
		sess.allowedSenders[target.String()] = struct{}{}
		sess.mu.Unlock()
		_ = s.sendSessionPacket(sess, protocol.CmdPunchAck, []byte("PUNCH_INIT_OK"), rawSenderAddr)
		log.Printf("[Server] PunchInit (sid=%d) target %s via sender %s", pkt.SessionID, target, rawSenderAddr)

		// Immediately fire a fast burst of 5 probes to establish server-side NAT mapping with minimal latency
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.sendSecureProbeBurst(sess, target, 5, 25*time.Millisecond)
		}()

		s.wg.Add(1)
		go s.punchProbeLoop(sess, target)

	case protocol.CmdPing:
		// Keep idle-but-alive sessions (and their stable upstream socket) from being
		// reaped, otherwise a re-dialed upstream would change the source port the
		// L4D2 server sees and disconnect the player.
		pathPayload := protocol.EncodePathHint(s.classifyPath(rawSenderAddr, realClientAddr))
		if pathPayload == nil {
			return
		}
		_ = s.sendSessionPacketAt(sess, protocol.CmdPong, pathPayload, rawSenderAddr, pkt.Timestamp)

	case protocol.CmdPunchOffer, protocol.CmdPunchAck:
		// The server never sends itself a PunchOffer and only receives a
		// PunchAck as a client echo — nothing to do. Kept for symmetry.

	case protocol.CmdData:
		// A zero session ID means the client hasn't completed its handshake yet.
		// Accepting it here would merge every pre-handshake client into one session.
		if !protocol.IsL4D2Packet(pkt.Payload) {
			return
		}
		// The path carrying actual game traffic is the only one allowed to
		// become the upstream response destination.
		s.setSessionReturnPath(sess, rawSenderAddr, realClientAddr)
		sess.mu.Lock()
		// Direct data from the punch socket proves migration succeeded; stop
		// hole-opening probes while retaining the authorized source.
		if sess.punchTarget != nil && sameUDPAddr(sess.punchTarget, rawSenderAddr) {
			sess.punchExpiry = time.Now()
		}
		sess.mu.Unlock()
		s.forwardToUpstream(sess, pkt.Payload)
	}
}

func (s *Server) sessionAllowsPunchMigration(sess *clientSession) bool {
	if sess == nil {
		return false
	}
	sess.mu.RLock()
	allowed := sess.punchTarget != nil && time.Now().Before(sess.punchExpiry)
	sess.mu.RUnlock()
	return allowed
}

func (s *Server) handleHandshake(pkt *protocol.Packet, rawSenderAddr, realClientAddr *net.UDPAddr) {
	if rawSenderAddr == nil {
		return
	}
	req, err := security.VerifyHandshakeRequest(s.authKey, pkt, time.Now().UnixNano())
	if err != nil {
		return
	}
	cacheKey := string(req.ClientNonce[:])
	clientPub := req.ClientPublic.Bytes()
	now := time.Now()

	s.handshakeMu.Lock()
	if entry := s.handshakes[cacheKey]; entry != nil {
		if now.Sub(entry.created) > 2*time.Minute {
			delete(s.handshakes, cacheKey)
		} else {
			// A nonce is bound to the ephemeral client public key.  Reusing the
			// nonce with a different key must not replace the cached session or
			// let an attacker force session confusion.
			if !bytes.Equal(entry.clientPub, clientPub) {
				s.handshakeMu.Unlock()
				return
			}
			if entry.client == nil || entry.client.secure == nil || !s.sessionPresent(entry.client) {
				delete(s.handshakes, cacheKey)
			} else {
				s.handshakeMu.Unlock()
				// Do not authorize a new source merely because it replayed a
				// previously authenticated handshake.  A captured handshake can be
				// replayed by an observer that does not possess the ephemeral private
				// key; the candidate must first prove possession with a fresh AEAD
				// Ping, which handlePacket deliberately permits for a new source.
				// This also keeps a retransmission from changing the real-client
				// address used by the established session.
				_, _ = s.udpConn.WriteToUDP(entry.response, rawSenderAddr)
				return
			}
		}
	}

	sid := s.nextSessionID()
	metadata := s.handshakeMetadata(rawSenderAddr, realClientAddr)
	respPkt, secureSession, err := security.NewHandshakeResponse(s.authKey, req, sid, metadata)
	if err != nil {
		s.handshakeMu.Unlock()
		return
	}
	sess := &clientSession{
		sessionID:      sid,
		rawSenderAddr:  cloneUDPAddr(rawSenderAddr),
		realClientAddr: cloneUDPAddr(realClientAddr),
		lastActive:     now,
		secure:         secureSession,
		allowedSenders: map[string]struct{}{rawSenderAddr.String(): {}},
	}
	s.sessionMu.Lock()
	// Keep the session map bounded even when an attacker submits many valid
	// handshakes with a compromised key.
	if len(s.sessions) >= maxSessions {
		s.evictOldestSessionLocked()
	}
	s.sessions[sid] = sess
	s.sessionMu.Unlock()
	response := respPkt.Marshal()
	if len(s.handshakes) >= maxSessions*2 {
		var oldestKey string
		var oldestTime time.Time
		for key, entry := range s.handshakes {
			if entry == nil || oldestKey == "" || entry.created.Before(oldestTime) {
				oldestKey = key
				if entry != nil {
					oldestTime = entry.created
				}
			}
		}
		delete(s.handshakes, oldestKey)
	}
	s.handshakes[cacheKey] = &handshakeCacheEntry{
		response:  append([]byte(nil), response...),
		client:    sess,
		clientPub: append([]byte(nil), clientPub...),
		created:   now,
	}
	s.handshakeMu.Unlock()

	_, _ = s.udpConn.WriteToUDP(response, rawSenderAddr)
	log.Printf("[Server] Client Handshake accepted (SessionID: %d, Real Client Endpoint: %s, Socket Sender: %s, Path: %s)",
		sid, reflectAddress(realClientAddr), rawSenderAddr, s.classifyPath(rawSenderAddr, realClientAddr))
}

func (s *Server) sessionPresent(target *clientSession) bool {
	if target == nil {
		return false
	}
	s.sessionMu.RLock()
	current := s.sessions[target.sessionID]
	s.sessionMu.RUnlock()
	return current == target && target.secure != nil && !target.secure.IsClosed()
}

func (s *Server) nextSessionID() uint64 {
	for {
		id := atomic.AddUint64(&s.nextID, 1)
		if id == 0 {
			continue
		}
		s.sessionMu.RLock()
		_, exists := s.sessions[id]
		s.sessionMu.RUnlock()
		if !exists {
			return id
		}
	}
}

func (s *Server) handshakeMetadata(rawSenderAddr, realClientAddr *net.UDPAddr) []byte {
	reflected := reflectAddress(realClientAddr)
	listenPort := 27014
	if s.udpConn != nil {
		if lAddr, ok := s.udpConn.LocalAddr().(*net.UDPAddr); ok && lAddr.Port > 0 {
			listenPort = lAddr.Port
		}
	}
	var localCandidates []string
	if isWildcardListenAddr(s.cfg.ListenAddr) {
		localCandidates = discover.GatherAllLocalCandidates(listenPort)
	}
	var combinedIPs []string
	seenAddrs := make(map[string]bool)
	for _, a := range s.cfg.PublicIPs {
		a = strings.TrimSpace(a)
		if a != "" && !seenAddrs[a] {
			seenAddrs[a] = true
			combinedIPs = append(combinedIPs, a)
		}
	}
	for _, a := range localCandidates {
		if !seenAddrs[a] {
			seenAddrs[a] = true
			combinedIPs = append(combinedIPs, a)
		}
	}
	// The same authenticated handshake may be sent over several candidate
	// sockets.  Path classification is therefore intentionally left blank here
	// and learned with an authenticated per-candidate Ping/Pong exchange; a
	// cached response must never make a direct candidate look like a relay (or
	// vice versa).
	resp := fmt.Sprintf("%s|%s|", reflected, strings.Join(combinedIPs, ","))
	if sp := s.publicEndpointString(); sp != "" {
		resp += "|" + sp
	}
	return []byte(resp)
}

func (s *Server) sessionAllowsSource(sess *clientSession, source *net.UDPAddr) bool {
	if sess == nil || source == nil {
		return false
	}
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	if _, ok := sess.allowedSenders[source.String()]; ok {
		return true
	}
	return sess.rawSenderAddr != nil && sameUDPAddr(sess.rawSenderAddr, source)
}

func (s *Server) authorizeSessionSource(sess *clientSession, rawSenderAddr, realClientAddr *net.UDPAddr) {
	if sess == nil {
		return
	}
	sess.mu.Lock()
	if rawSenderAddr != nil {
		if sess.allowedSenders == nil {
			sess.allowedSenders = make(map[string]struct{})
		}
		sess.allowedSenders[rawSenderAddr.String()] = struct{}{}
	}
	if realClientAddr != nil {
		sess.realClientAddr = cloneUDPAddr(realClientAddr)
	}
	sess.lastActive = time.Now()
	sess.mu.Unlock()
}

// setSessionReturnPath records the authenticated source that actually carried
// game traffic.  It is deliberately separate from authorizeSessionSource so
// control probes from non-selected candidates cannot redirect upstream replies.
func (s *Server) setSessionReturnPath(sess *clientSession, rawSenderAddr, realClientAddr *net.UDPAddr) {
	if sess == nil {
		return
	}
	sess.mu.Lock()
	if rawSenderAddr != nil {
		sess.rawSenderAddr = cloneUDPAddr(rawSenderAddr)
		if sess.allowedSenders == nil {
			sess.allowedSenders = make(map[string]struct{})
		}
		sess.allowedSenders[rawSenderAddr.String()] = struct{}{}
	}
	if realClientAddr != nil {
		sess.realClientAddr = cloneUDPAddr(realClientAddr)
	}
	sess.lastActive = time.Now()
	sess.mu.Unlock()
}

func (s *Server) sendSecureProbeBurst(sess *clientSession, target *net.UDPAddr, count int, interval time.Duration) {
	if sess == nil || target == nil || count <= 0 {
		return
	}
	for i := 0; i < count; i++ {
		if err := s.sendSessionPacket(sess, protocol.CmdStunProbe, []byte("PUNCH"), target); err != nil {
			return
		}
		if i+1 < count && interval > 0 {
			time.Sleep(interval)
		}
	}
}

func reflectAddress(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

// forwardToUpstream transmits L4D2 payload to upstream server target.
func (s *Server) forwardToUpstream(sess *clientSession, payload []byte) {
	sess.upstreamMu.Lock()
	defer sess.upstreamMu.Unlock()

	if sess.upstream == nil {
		targetAddr, err := net.ResolveUDPAddr("udp", s.cfg.TargetAddr)
		if err != nil {
			log.Printf("[Server] Failed to resolve target addr %s: %v", s.cfg.TargetAddr, err)
			return
		}
		upstreamConn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			log.Printf("[Server] Failed to dial upstream %s: %v", s.cfg.TargetAddr, err)
			return
		}
		sess.upstream = upstreamConn

		// Spawn background reader for upstream L4D2 server responses
		s.wg.Add(1)
		go s.readUpstreamLoop(sess, upstreamConn)
	}

	_, _ = sess.upstream.Write(payload)
}

// readUpstreamLoop receives response UDP packets from actual L4D2 server and relays back to client via tunnel return path.
func (s *Server) readUpstreamLoop(sess *clientSession, upstream *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = upstream.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := upstream.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// A transient socket error — e.g. ECONNREFUSED from an ICMP "port
			// unreachable" delivered while the L4D2 server was down or restarting —
			// must NOT kill this loop. If it did, the session would silently lose the
			// server→client direction forever: the client's packets still get
			// forwarded to the L4D2 server (so its receive side looks continuous) but
			// the L4D2 server's replies pile up in this socket's receive buffer and
			// are never relayed back. The client's netchan then degrades (choked
			// usercmds / lost inputs), times out, and reconnects straight into an
			// "Invalid challenge packet" because the reader is gone. Once the L4D2
			// server is back, this same socket works again — we only have to keep
			// reading on it. Only a real shutdown/close stops the loop.
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("[Server] Upstream read error (sid=%d): %v — continuing on same socket", sess.sessionID, err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		sess.mu.RLock()
		dst := sess.rawSenderAddr
		sess.mu.RUnlock()
		if dst == nil {
			continue
		}

		// Encapsulate and authenticate the upstream response before sending it
		// through the current relay or punched return path.
		_ = s.sendSessionPacket(sess, protocol.CmdData, append([]byte(nil), buf[:n]...), dst)
	}
}

// evictOldestSessionLocked removes one idle session. The caller must hold
// sessionMu for writing.
func (s *Server) evictOldestSessionLocked() {
	var oldest *clientSession
	for _, existing := range s.sessions {
		existing.mu.RLock()
		if oldest == nil || existing.lastActive.Before(oldest.lastActive) {
			oldest = existing
		}
		existing.mu.RUnlock()
	}
	if oldest == nil {
		return
	}
	oldest.upstreamMu.Lock()
	if oldest.upstream != nil {
		_ = oldest.upstream.Close()
	}
	oldest.upstreamMu.Unlock()
	if oldest.secure != nil {
		oldest.secure.Close()
	}
	delete(s.sessions, oldest.sessionID)
	log.Printf("[Server] Session %d evicted (max sessions reached)", oldest.sessionID)
}

// cleanupSessionsLoop purges idle sessions after 60s and cleans up pendingProxyAddrs memory leaks.
func (s *Server) cleanupSessionsLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			// Prune PROXY-protocol address mappings for tunnels that went away.
			s.proxyAddrMu.Lock()
			for k, e := range s.pendingProxyAddrs {
				if now.Sub(e.ts) > 60*time.Second {
					delete(s.pendingProxyAddrs, k)
				}
			}
			s.proxyAddrMu.Unlock()

			s.sessionMu.Lock()
			for sid, sess := range s.sessions {
				sess.mu.RLock()
				idle := now.Sub(sess.lastActive) > 60*time.Second
				var rawKey string
				if sess.rawSenderAddr != nil {
					rawKey = sess.rawSenderAddr.String()
				}
				sess.mu.RUnlock()

				if idle {
					sess.upstreamMu.Lock()
					if sess.upstream != nil {
						_ = sess.upstream.Close()
					}
					sess.upstreamMu.Unlock()
					if rawKey != "" {
						s.proxyAddrMu.Lock()
						delete(s.pendingProxyAddrs, rawKey)
						s.proxyAddrMu.Unlock()
					}
					if sess.secure != nil {
						sess.secure.Close()
					}
					delete(s.sessions, sid)
					log.Printf("[Server] Session %d expired and cleaned up", sid)
				}
			}
			s.sessionMu.Unlock()

			s.handshakeMu.Lock()
			for key, entry := range s.handshakes {
				if entry == nil || entry.client == nil || now.Sub(entry.created) > 2*time.Minute || !s.sessionPresent(entry.client) {
					delete(s.handshakes, key)
				}
			}
			s.handshakeMu.Unlock()
		}
	}
}

// Stop shuts down the server.
func (s *Server) Stop() {
	s.cancel()
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}

	s.serverPubMu.Lock()
	if s.upnpCleanup != nil {
		s.upnpCleanup()
		s.upnpCleanup = nil
	}
	s.serverPubMu.Unlock()

	s.sessionMu.Lock()
	for _, sess := range s.sessions {
		sess.upstreamMu.Lock()
		if sess.upstream != nil {
			_ = sess.upstream.Close()
		}
		sess.upstreamMu.Unlock()
		if sess.secure != nil {
			sess.secure.Close()
		}
	}
	s.sessionMu.Unlock()

	s.wg.Wait()

	s.handshakeMu.Lock()
	for key := range s.handshakes {
		delete(s.handshakes, key)
	}
	s.handshakeMu.Unlock()
	for i := range s.authKey {
		s.authKey[i] = 0
	}
	log.Printf("[Server] Server stopped successfully")
}
