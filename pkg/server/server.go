package server

import (
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
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/proxyproto"
	"left4proxy/pkg/stun"
)

// maxSessions bounds the number of concurrent client sessions to protect against
// memory/socket exhaustion from handshakes or data packets with forged IDs.
const maxSessions = 2048

// clientSession tracks one client's state on the server.
type clientSession struct {
	mu             sync.RWMutex // Guards rawSenderAddr / realClientAddr / lastActive.
	sessionID      uint64
	rawSenderAddr  *net.UDPAddr // Socket return path (frpc or direct UDP client)
	realClientAddr *net.UDPAddr // Extracted real client public IP:Port (from PROXY protocol or direct)
	lastActive     time.Time
	upstreamMu     sync.Mutex // Guards upstream dial/close.
	upstream       *net.UDPConn
}

// proxyAddrEntry records the real client endpoint learned from a PROXY protocol
// header for a given raw tunnel sender, plus when it was learned (for pruning).
type proxyAddrEntry struct {
	addr *net.UDPAddr
	ts   time.Time
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
	nextID            uint64
	behindNAT         bool // Whether the server has no public interface IP (for direct vs punch labeling).
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
}

// NewServer creates a new Server instance.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:               cfg,
		sessions:          make(map[uint64]*clientSession),
		pendingProxyAddrs: make(map[string]*proxyAddrEntry),
		stunProbeLogged:   make(map[string]bool),
		// Seed the session ID counter randomly. After a server restart the counter
		// must NOT restart from 0, otherwise a freshly-connected client could be
		// assigned an ID that a client from before the restart is still using, and
		// the two sessions would collide on the server.
		nextID:     rand.Uint64(),
		behindNAT:  determineBehindNAT(cfg.NAT),
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Start launches the UDP listener and packet processing routines.
func (s *Server) Start() error {
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

	s.wg.Add(2)
	go s.readUDPDataLoop()
	go s.cleanupSessionsLoop()

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
		realClientAddr := rawSenderAddr

		// If ProxyProtocol is enabled on server, parse incoming PROXY protocol v1/v2 header from frp/HAProxy
		if s.cfg.ProxyProtocolV2 {
			extractedAddr, offset, pErr := proxyproto.ParseHeader(packetData)
			if pErr == nil && extractedAddr != nil {
				log.Printf("[Server] [PROXY Protocol Detected] Extracted Real Client Endpoint: %s (Raw Sender: %s)",
					extractedAddr.String(), rawSenderAddr.String())

				// Cache the mapping so subsequent packets without a header (some
				// fronting proxies only prepend it on the first datagram) still get the
				// real source address. Bound the map so forged headers cannot grow it unboundedly.
				s.proxyAddrMu.Lock()
				s.pendingProxyAddrs[rawSenderAddr.String()] = &proxyAddrEntry{addr: extractedAddr, ts: time.Now()}
				if len(s.pendingProxyAddrs) > 4096 {
					var oldestKey string
					var oldest time.Time
					for k, e := range s.pendingProxyAddrs {
						if oldestKey == "" || e.ts.Before(oldest) {
							oldestKey, oldest = k, e.ts
						}
					}
					delete(s.pendingProxyAddrs, oldestKey)
				}
				s.proxyAddrMu.Unlock()

				realClientAddr = extractedAddr
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

		s.handlePacket(pkt, rawSenderAddr, realClientAddr)
	}
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
	if s.cfg.ProxyProtocolV2 {
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

// handlePacket processes unmarshaled protocol packets.
func (s *Server) handlePacket(pkt *protocol.Packet, rawSenderAddr, realClientAddr *net.UDPAddr) {
	switch pkt.Cmd {
	case protocol.CmdHandshakeReq:
		sid := atomic.AddUint64(&s.nextID, 1)
		_ = s.getOrCreateSession(sid, rawSenderAddr, realClientAddr)

		reflected := stun.ReflectAddress(realClientAddr)
		// Tell the client how this connection reached us (relay/direct/punch/lan)
		// so it can label the candidate honestly instead of guessing.
		pathHint := s.classifyPath(rawSenderAddr, realClientAddr)
		var respPayload string
		if len(s.cfg.PublicIPs) > 0 {
			respPayload = fmt.Sprintf("%s|%s|%s", reflected, strings.Join(s.cfg.PublicIPs, ","), pathHint)
		} else {
			respPayload = fmt.Sprintf("%s||%s", reflected, pathHint)
		}

		// Echo back client's sent timestamp for instant RTT calculation during handshake
		respPkt := &protocol.Packet{
			Version:   protocol.Version1,
			Cmd:       protocol.CmdHandshakeResp,
			SessionID: sid,
			Seq:       pkt.Seq,
			Timestamp: pkt.Timestamp, // Echo back client's sent timestamp!
			Payload:   []byte(respPayload),
		}

		// Send UDP response back to rawSenderAddr (the frp tunnel return socket!)
		_, _ = s.udpConn.WriteToUDP(respPkt.Marshal(), rawSenderAddr)

		log.Printf("[Server] Client Handshake accepted (SessionID: %d, Real Client Endpoint: %s, Socket Sender: %s, Path: %s)",
			sid, realClientAddr.String(), rawSenderAddr.String(), pathHint)

	case protocol.CmdLanProbe:
		respPkt := protocol.NewPacket(protocol.CmdLanAck, pkt.SessionID, pkt.Seq, []byte("LAN_ACK"))
		_, _ = s.udpConn.WriteToUDP(respPkt.Marshal(), rawSenderAddr)

	case protocol.CmdStunProbe:
		respPayload := []byte(stun.ReflectAddress(realClientAddr))
		respPkt := protocol.NewPacket(protocol.CmdStunAck, pkt.SessionID, pkt.Seq, respPayload)
		_, wErr := s.udpConn.WriteToUDP(respPkt.Marshal(), rawSenderAddr)

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

	case protocol.CmdPing:
		// Keep idle-but-alive sessions (and their stable upstream socket) from being
		// reaped, otherwise a re-dialed upstream would change the source port the
		// L4D2 server sees and disconnect the player.
		if pkt.SessionID != 0 {
			s.sessionMu.RLock()
			if sess := s.sessions[pkt.SessionID]; sess != nil {
				sess.mu.Lock()
				sess.lastActive = time.Now()
				sess.mu.Unlock()
			}
			s.sessionMu.RUnlock()
		}

		// Echo back client's sent timestamp for accurate RTT calculation
		respPkt := &protocol.Packet{
			Version:   protocol.Version1,
			Cmd:       protocol.CmdPong,
			SessionID: pkt.SessionID,
			Seq:       pkt.Seq,
			Timestamp: pkt.Timestamp, // Echo back client's timestamp
			Payload:   pkt.Payload,
		}
		_, _ = s.udpConn.WriteToUDP(respPkt.Marshal(), rawSenderAddr)

	case protocol.CmdData:
		// A zero session ID means the client hasn't completed its handshake yet.
		// Accepting it here would merge every pre-handshake client into one session.
		if pkt.SessionID == 0 || !protocol.IsL4D2Packet(pkt.Payload) {
			return
		}

		sess := s.getOrCreateSession(pkt.SessionID, rawSenderAddr, realClientAddr)
		if sess != nil {
			sess.mu.Lock()
			sess.lastActive = time.Now()
			sess.mu.Unlock()
			s.forwardToUpstream(sess, pkt.Payload)
		}
	}
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
			return
		}

		sess.mu.RLock()
		dst := sess.rawSenderAddr
		sess.mu.RUnlock()
		if dst == nil {
			continue
		}

		// Encapsulate in CmdData Left4Proxy packet and send back to client via rawSenderAddr
		replyPkt := protocol.NewPacket(protocol.CmdData, sess.sessionID, 0, buf[:n])
		_, _ = s.udpConn.WriteToUDP(replyPkt.Marshal(), dst)
	}
}

// getOrCreateSession retrieves or initializes a client session.
func (s *Server) getOrCreateSession(sessionID uint64, rawSenderAddr, realClientAddr *net.UDPAddr) *clientSession {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	sess, exists := s.sessions[sessionID]
	if !exists {
		// Bound memory/socket usage: evict the oldest session when at capacity.
		if len(s.sessions) >= maxSessions {
			var oldest *clientSession
			for _, existing := range s.sessions {
				existing.mu.RLock()
				if oldest == nil || existing.lastActive.Before(oldest.lastActive) {
					oldest = existing
				}
				existing.mu.RUnlock()
			}
			if oldest != nil {
				oldest.upstreamMu.Lock()
				if oldest.upstream != nil {
					_ = oldest.upstream.Close()
				}
				oldest.upstreamMu.Unlock()
				delete(s.sessions, oldest.sessionID)
				log.Printf("[Server] Session %d evicted (max sessions reached)", oldest.sessionID)
			}
		}

		sess = &clientSession{
			sessionID:  sessionID,
			lastActive: time.Now(),
		}
		s.sessions[sessionID] = sess
	}

	sess.mu.Lock()
	sess.rawSenderAddr = rawSenderAddr
	if realClientAddr != nil {
		sess.realClientAddr = realClientAddr
	}
	sess.lastActive = time.Now()
	sess.mu.Unlock()

	return sess
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
					delete(s.sessions, sid)
					log.Printf("[Server] Session %d expired and cleaned up", sid)
				}
			}
			s.sessionMu.Unlock()
		}
	}
}

// Stop shuts down the server.
func (s *Server) Stop() {
	s.cancel()
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}

	s.sessionMu.Lock()
	for _, sess := range s.sessions {
		sess.upstreamMu.Lock()
		if sess.upstream != nil {
			_ = sess.upstream.Close()
		}
		sess.upstreamMu.Unlock()
	}
	s.sessionMu.Unlock()

	s.wg.Wait()
	log.Printf("[Server] Server stopped successfully")
}
