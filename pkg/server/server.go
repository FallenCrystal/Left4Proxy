package server

import (
	"bytes"
	"context"
	"errors"
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

const (
	// maxSessions bounds the number of concurrent client sessions to protect against
	// memory/socket exhaustion from handshakes or data packets with forged IDs.
	maxSessions = 2048
	// Clients retain at most 64 candidates. Bounding the advertised list keeps
	// handshake metadata comfortably within one UDP datagram and prevents useless
	// DNS work for endpoints no client can retain.
	maxAdvertisedEndpoints = 64
	maxTrackedProbeSenders = 4096
	stunProbeLogTTL        = 2 * time.Minute
	proxyDropLogTTL        = 2 * time.Minute
	proxySenderStateTTL    = 2 * time.Minute
)

// clientSession tracks one client's state on the server.
type clientSession struct {
	mu              sync.RWMutex // Guards addresses / lastActive / punchTarget.
	sessionID       uint64
	rawSenderAddr   *net.UDPAddr // Authenticated socket return path.
	proxySenderAddr *net.UDPAddr // Relay source that supplied realClientAddr at the authenticated handshake.
	realClientAddr  *net.UDPAddr // Client endpoint asserted by that authenticated PROXY envelope.
	allowedSenders  map[string]struct{}
	secure          *security.Session
	lastActive      time.Time
	punchTarget     *net.UDPAddr // Client's punch-socket public endpoint (from CmdPunchInit); probed to open the server-side hole.
	punchExpiry     time.Time    // When to stop probing the punch target.
	upstreamMu      sync.Mutex   // Guards upstream dial/close.
	upstream        *net.UDPConn
	punchWake       chan struct{} // Coalesces PunchInit updates for the single per-session probe worker.
	punchWorker     bool          // Guarded by mu; prevents unbounded probe goroutines.
}

type handshakeCacheEntry struct {
	response  []byte
	client    *clientSession
	clientPub []byte
	created   time.Time
}

// proxySenderState records whether a UDP sender has already supplied its one
// allowed PROXY prelude. The optional address is used by a following raw L4DP
// handshake when a relay transmits the header as its own UDP datagram.
type proxySenderState struct {
	realClientAddr *net.UDPAddr
	proxied        bool
	lastSeen       time.Time
}

// Server is the Left4Proxy server daemon.
type Server struct {
	cfg     *config.ServerConfig
	udpConn *net.UDPConn
	// advertisedIPs is normalized once after the listener binds, so bare
	// public_ips entries inherit the actual port (including when listen_addr is
	// :0) and malformed entries cannot be silently sent to clients.
	advertisedIPs     []string
	proxyTrustedNets  []*net.IPNet // Immutable normalized source allowlist for PROXY envelopes.
	proxySenderStates map[string]*proxySenderState
	sessions          map[uint64]*clientSession
	stunProbeLogged   map[string]time.Time // Last authenticated STUN probe per sender, used for bounded log deduplication.
	proxyDropLogged   map[string]time.Time // Last logged rejected PROXY envelope per source/reason.
	proxySenderMu     sync.Mutex
	stunProbeLogMu    sync.Mutex
	proxyDropLogMu    sync.Mutex
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
	ctx               context.Context
	cancel            context.CancelFunc
	// startStopMu serializes listener setup with shutdown.  It prevents Stop
	// from racing a Start that has not yet published its UDP socket or fixed
	// goroutine set.
	startStopMu sync.Mutex
	lifecycleMu sync.Mutex
	started     bool
	stopping    bool
	wg          sync.WaitGroup
}

// NewServer creates a new Server instance.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server configuration is nil")
	}
	// Snapshot configuration and slice/key fields so a caller cannot race the
	// running server by reusing or clearing the loader's struct after startup.
	ownedCfg := *cfg
	ownedCfg.PublicIPs = append([]string(nil), cfg.PublicIPs...)
	if cfg.ProxyTrustedAddrs == nil {
		ownedCfg.ProxyTrustedAddrs = []string{"127.0.0.1"}
	} else {
		// Preserve an explicit empty list: with PROXY parsing enabled it is a
		// configuration error, whereas a nil list means use the safe default.
		ownedCfg.ProxyTrustedAddrs = make([]string, len(cfg.ProxyTrustedAddrs))
		copy(ownedCfg.ProxyTrustedAddrs, cfg.ProxyTrustedAddrs)
	}
	ownedCfg.AuthKey = append([]byte(nil), cfg.AuthKey...)
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:               &ownedCfg,
		proxySenderStates: make(map[string]*proxySenderState),
		sessions:          make(map[uint64]*clientSession),
		stunProbeLogged:   make(map[string]time.Time),
		proxyDropLogged:   make(map[string]time.Time),
		stunValidator:     stun.NewValidator(),
		authKey:           append([]byte(nil), ownedCfg.AuthKey...),
		handshakes:        make(map[string]*handshakeCacheEntry),
		// Seed the session ID counter randomly. After a server restart the counter
		// must NOT restart from 0, otherwise a freshly-connected client could be
		// assigned an ID that a client from before the restart is still using, and
		// the two sessions would collide on the server.
		nextID: rand.Uint64(),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// startTask registers a goroutine while holding the lifecycle gate.  Stop
// closes that gate before waiting, so a packet arriving during shutdown cannot
// call WaitGroup.Add after WaitGroup.Wait has begun.
func (s *Server) startTask(fn func()) bool {
	s.lifecycleMu.Lock()
	if s.stopping {
		s.lifecycleMu.Unlock()
		return false
	}
	s.wg.Add(1)
	s.lifecycleMu.Unlock()
	go fn()
	return true
}

// startTasks is the batched form used for the fixed set of server loops at
// startup. The callback must launch exactly count goroutines, each of which
// calls wg.Done when it exits.
func (s *Server) startTasks(count int, launch func()) bool {
	if count <= 0 {
		return true
	}
	s.lifecycleMu.Lock()
	if s.stopping {
		s.lifecycleMu.Unlock()
		return false
	}
	s.wg.Add(count)
	s.lifecycleMu.Unlock()
	launch()
	return true
}

// Start launches the UDP listener and packet processing routines.
func (s *Server) Start() error {
	s.startStopMu.Lock()
	defer s.startStopMu.Unlock()

	s.lifecycleMu.Lock()
	if s.stopping {
		s.lifecycleMu.Unlock()
		return fmt.Errorf("server is stopping or has already stopped")
	}
	if s.started {
		s.lifecycleMu.Unlock()
		return fmt.Errorf("server is already started")
	}
	s.started = true
	s.lifecycleMu.Unlock()
	rollbackStart := func() {
		s.lifecycleMu.Lock()
		s.started = false
		s.lifecycleMu.Unlock()
	}
	if len(s.authKey) != security.KeySize {
		rollbackStart()
		return fmt.Errorf("server authentication key is missing or invalid; load the shared .secret file before starting")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		rollbackStart()
		return fmt.Errorf("failed to resolve server UDP listen addr %s: %w", s.cfg.ListenAddr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		rollbackStart()
		return fmt.Errorf("failed to listen on UDP %s: %w", s.cfg.ListenAddr, err)
	}
	s.udpConn = conn
	actualAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || actualAddr == nil || actualAddr.Port < 1 {
		_ = conn.Close()
		s.udpConn = nil
		rollbackStart()
		return fmt.Errorf("failed to determine bound UDP port")
	}
	advertised, err := discover.NormalizeEndpoints(s.cfg.PublicIPs, actualAddr.Port)
	if err != nil {
		_ = conn.Close()
		s.udpConn = nil
		rollbackStart()
		return fmt.Errorf("invalid public_ips: %w", err)
	}
	if len(advertised) > maxAdvertisedEndpoints {
		_ = conn.Close()
		s.udpConn = nil
		rollbackStart()
		return fmt.Errorf("invalid public_ips: %d endpoints exceeds limit %d", len(advertised), maxAdvertisedEndpoints)
	}
	s.advertisedIPs = advertised
	trustedProxyNets, err := parseTrustedProxyAddrs(s.cfg.ProxyTrustedAddrs)
	if err != nil {
		_ = conn.Close()
		s.udpConn = nil
		rollbackStart()
		return fmt.Errorf("invalid proxy_protocol_trusted_addrs: %w", err)
	}
	if s.cfg.ProxyProtocolV2 && len(trustedProxyNets) == 0 {
		_ = conn.Close()
		s.udpConn = nil
		rollbackStart()
		return fmt.Errorf("proxy_protocol_trusted_addrs must not be empty when proxy_protocol_v2 is enabled")
	}
	s.proxyTrustedNets = trustedProxyNets
	if punch := strings.TrimSpace(s.cfg.PunchAddr); punch != "" {
		normalizedPunch, err := discover.NormalizeEndpoint(punch, actualAddr.Port)
		if err != nil {
			_ = conn.Close()
			s.udpConn = nil
			rollbackStart()
			return fmt.Errorf("invalid punch_addr: %w", err)
		}
		s.cfg.PunchAddr = normalizedPunch
	}

	log.Printf("[Server] Left4Proxy Server listening on UDP %s | Target L4D2: %s | PROXY Protocol Parser: %v | Trusted PROXY Sources: %s",
		actualAddr, s.cfg.TargetAddr, s.cfg.ProxyProtocolV2, strings.Join(s.cfg.ProxyTrustedAddrs, ","))

	if isWildcardListenAddr(s.cfg.ListenAddr) {
		hostCands := discover.GatherAllLocalCandidates(actualAddr.Port)
		if len(hostCands) > 0 {
			log.Printf("[Server] Auto-discovered local host & IPv6 candidates: %v", hostCands)
		}
	}

	// Attempt UPnP IGD automatic port mapping only when explicitly enabled and
	// no manual punch endpoint is configured. Both operations affect the same
	// advertised endpoint; racing them made a late UPnP result unexpectedly
	// overwrite an operator's explicit punch_addr.
	if s.cfg.EnableUPnP && strings.TrimSpace(s.cfg.PunchAddr) == "" {
		s.startTask(func() {
			defer s.wg.Done()
			extAddr, cleanup := discover.TryUPnPMapping(s.ctx, actualAddr.Port, "Left4Proxy Server")
			if extAddr == nil {
				if cleanup != nil {
					cleanup()
				}
				log.Printf("[Server] UPnP IGD port mapping not available or disabled on router gateway")
				return
			}
			// Publish the cleanup callback while holding the lifecycle gate used by
			// Stop. Otherwise Stop could observe a nil callback, return, and then
			// this goroutine could publish a mapping that would never be released.
			s.lifecycleMu.Lock()
			if s.stopping {
				s.lifecycleMu.Unlock()
				if cleanup != nil {
					cleanup()
				}
				return
			}
			s.serverPubMu.Lock()
			oldCleanup := s.upnpCleanup
			s.upnpCleanup = cleanup
			s.serverPubMu.Unlock()
			s.lifecycleMu.Unlock()
			if oldCleanup != nil {
				oldCleanup()
			}
			log.Printf("[Server] UPnP IGD port mapping succeeded -> %s", extAddr)
			s.updateServerPublic(extAddr)
		})
	} else if strings.TrimSpace(s.cfg.PunchAddr) != "" {
		log.Printf("[Server] UPnP IGD mapping skipped because punch_addr is configured")
	} else {
		log.Printf("[Server] UPnP IGD mapping disabled (enable_upnp=false)")
	}

	if !s.startTasks(3, func() {
		go s.readUDPDataLoop()
		go s.cleanupSessionsLoop()
		go s.discoverPublicEndpointLoop()
	}) {
		_ = s.udpConn.Close()
		s.udpConn = nil
		return fmt.Errorf("server stopped during startup")
	}

	return nil
}

// readUDPDataLoop handles incoming UDP packets from clients or UDP relays.
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
		cachedProxyAddr, cachedProxied, firstPacket := s.observeProxySender(rawSenderAddr)

		// A STUN response is trusted only when it matches a request issued from
		// this exact socket to this exact STUN server.  A magic cookie alone is
		// not authentication and must never update the advertised endpoint.
		if validated, verr := s.stunValidator.Accept(packetData, rawSenderAddr); verr == nil {
			s.updateServerPublicFromSTUN(validated.Reflected)
			continue
		}

		// A UDP relay may send its PROXY envelope as the source's first datagram
		// and the L4DP handshake in the next one. Only that first datagram can
		// be interpreted as PROXY Protocol; later bytes are ordinary L4DP input
		// even when they happen to resemble a PROXY header.
		realClientAddr := rawSenderAddr
		proxied := cachedProxied
		if cachedProxyAddr != nil {
			realClientAddr = cachedProxyAddr
		}
		if firstPacket && proxyproto.IsHeader(packetData) {
			if !s.cfg.ProxyProtocolV2 {
				s.logDroppedProxyHeader(rawSenderAddr, "proxy_protocol_v2 is disabled")
				continue
			}
			if !s.proxySourceTrusted(rawSenderAddr) {
				s.logDroppedProxyHeader(rawSenderAddr, "this address is not in proxy_protocol_trusted_addrs")
				continue
			}
			extractedAddr, offset, proxyErr := proxyproto.ParseHeader(packetData)
			if proxyErr != nil {
				s.logDroppedProxyHeader(rawSenderAddr, fmt.Sprintf("the header is invalid: %v", proxyErr))
				continue
			}
			// LOCAL/UNKNOWN envelopes intentionally have no extractable peer
			// address, but they are still relayed connections for path selection.
			proxied = true
			s.setProxySenderAddress(rawSenderAddr, extractedAddr)
			if extractedAddr != nil {
				realClientAddr = extractedAddr
			}
			if offset >= len(packetData) {
				continue
			}
			packetData = packetData[offset:]
		}

		pkt, err := protocol.Unmarshal(packetData)
		if err != nil {
			continue
		}
		s.handlePacket(packetData, pkt, rawSenderAddr, realClientAddr, proxied)
	}
}

func (s *Server) recordStunProbe(sender string, now time.Time) bool {
	if sender == "" {
		return false
	}
	s.stunProbeLogMu.Lock()
	_, seen := s.stunProbeLogged[sender]
	s.stunProbeLogged[sender] = now
	if len(s.stunProbeLogged) > maxTrackedProbeSenders {
		var oldestKey string
		var oldest time.Time
		for key, lastSeen := range s.stunProbeLogged {
			if oldestKey == "" || lastSeen.Before(oldest) {
				oldestKey = key
				oldest = lastSeen
			}
		}
		delete(s.stunProbeLogged, oldestKey)
	}
	s.stunProbeLogMu.Unlock()
	return !seen
}

// observeProxySender records a sender's first UDP datagram. Only that datagram
// may carry a PROXY envelope; later datagrams are L4DP payloads.
func (s *Server) observeProxySender(source *net.UDPAddr) (*net.UDPAddr, bool, bool) {
	if s == nil || source == nil {
		return nil, false, false
	}
	now := time.Now()
	key := source.String()
	s.proxySenderMu.Lock()
	entry, seen := s.proxySenderStates[key]
	if seen {
		entry.lastSeen = now
		address := cloneUDPAddr(entry.realClientAddr)
		proxied := entry.proxied
		s.proxySenderMu.Unlock()
		return address, proxied, false
	}
	s.proxySenderStates[key] = &proxySenderState{lastSeen: now}
	if len(s.proxySenderStates) > maxTrackedProbeSenders {
		var oldestKey string
		var oldest time.Time
		for candidate, state := range s.proxySenderStates {
			if state == nil || oldestKey == "" || state.lastSeen.Before(oldest) {
				oldestKey = candidate
				if state != nil {
					oldest = state.lastSeen
				}
			}
		}
		delete(s.proxySenderStates, oldestKey)
	}
	s.proxySenderMu.Unlock()
	return nil, false, true
}

func (s *Server) setProxySenderAddress(source, realClientAddr *net.UDPAddr) {
	if s == nil || source == nil {
		return
	}
	now := time.Now()
	key := source.String()
	s.proxySenderMu.Lock()
	entry := s.proxySenderStates[key]
	if entry == nil {
		entry = &proxySenderState{}
		s.proxySenderStates[key] = entry
	}
	entry.proxied = true
	if realClientAddr != nil {
		entry.realClientAddr = cloneUDPAddr(realClientAddr)
	}
	entry.lastSeen = now
	s.proxySenderMu.Unlock()
}

func parseTrustedProxyAddrs(values []string) ([]*net.IPNet, error) {
	trusted := make([]*net.IPNet, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("empty address")
		}

		var network *net.IPNet
		if ip := net.ParseIP(value); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				network = &net.IPNet{IP: append(net.IP(nil), ip4...), Mask: net.CIDRMask(32, 32)}
			} else {
				network = &net.IPNet{IP: append(net.IP(nil), ip...), Mask: net.CIDRMask(128, 128)}
			}
		} else {
			parsedIP, parsedNetwork, err := net.ParseCIDR(value)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR: %w", value, err)
			}
			ones, bits := parsedNetwork.Mask.Size()
			if ones < 0 || (bits != 32 && bits != 128) {
				return nil, fmt.Errorf("%q has an invalid CIDR mask", value)
			}
			if ip4 := parsedIP.To4(); ip4 != nil && bits == 32 {
				parsedNetwork.IP = append(net.IP(nil), ip4...)
			} else {
				parsedNetwork.IP = append(net.IP(nil), parsedNetwork.IP...)
			}
			network = parsedNetwork
		}
		key := network.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		trusted = append(trusted, network)
	}
	return trusted, nil
}

func (s *Server) proxySourceTrusted(source *net.UDPAddr) bool {
	if s == nil || source == nil || source.IP == nil {
		return false
	}
	ip := source.IP
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, network := range s.proxyTrustedNets {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) logDroppedProxyHeader(source *net.UDPAddr, reason string) {
	if source == nil {
		return
	}
	now := time.Now()
	key := source.String() + "|" + reason
	s.proxyDropLogMu.Lock()
	last, seen := s.proxyDropLogged[key]
	shouldLog := !seen || now.Sub(last) >= proxyDropLogTTL
	if shouldLog {
		s.proxyDropLogged[key] = now
	}
	if len(s.proxyDropLogged) > maxTrackedProbeSenders {
		var oldestKey string
		var oldest time.Time
		for candidate, loggedAt := range s.proxyDropLogged {
			if oldestKey == "" || loggedAt.Before(oldest) {
				oldestKey, oldest = candidate, loggedAt
			}
		}
		delete(s.proxyDropLogged, oldestKey)
	}
	s.proxyDropLogMu.Unlock()
	if shouldLog {
		log.Printf("[Server] Dropped PROXY header from %s because %s", source, reason)
	}
}

func (s *Server) pruneStunProbeLog(now time.Time) {
	s.stunProbeLogMu.Lock()
	for key, lastSeen := range s.stunProbeLogged {
		if now.Sub(lastSeen) > stunProbeLogTTL {
			delete(s.stunProbeLogged, key)
		}
	}
	s.stunProbeLogMu.Unlock()
}

func (s *Server) pruneProxyDropLog(now time.Time) {
	s.proxyDropLogMu.Lock()
	for key, loggedAt := range s.proxyDropLogged {
		if now.Sub(loggedAt) > proxyDropLogTTL {
			delete(s.proxyDropLogged, key)
		}
	}
	s.proxyDropLogMu.Unlock()
}

func (s *Server) pruneProxySenderStates(now time.Time) {
	s.proxySenderMu.Lock()
	for key, state := range s.proxySenderStates {
		if state == nil || now.Sub(state.lastSeen) > proxySenderStateTTL {
			delete(s.proxySenderStates, key)
		}
	}
	s.proxySenderMu.Unlock()
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
	s.updateServerPublicWithPriority(addr, false)
}

// updateServerPublicFromSTUN ignores a late reflection once UPnP has installed
// a fixed external mapping. An outstanding STUN request may have observed the
// old random NAT port just before AddPortMapping completed; allowing that reply
// to win would advertise an endpoint the router no longer forwards.
func (s *Server) updateServerPublicFromSTUN(addr *net.UDPAddr) {
	s.updateServerPublicWithPriority(addr, true)
}

func (s *Server) updateServerPublicWithPriority(addr *net.UDPAddr, deferToUPnP bool) {
	if addr == nil || addr.IP == nil || addr.Port < 1 || addr.Port > 65535 {
		return
	}
	addr = cloneUDPAddr(addr)
	s.serverPubMu.Lock()
	if deferToUPnP && s.upnpCleanup != nil {
		s.serverPubMu.Unlock()
		return
	}
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
	s.serverPubMu.RLock()
	upnpActive := s.upnpCleanup != nil
	s.serverPubMu.RUnlock()
	if upnpActive {
		return
	}
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
func (s *Server) punchProbeLoop(sess *clientSession) {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			sess.mu.Lock()
			sess.punchWorker = false
			sess.mu.Unlock()
			return
		case <-sess.punchWake:
			s.sendCurrentPunchBurst(sess, 5, 25*time.Millisecond)
			continue
		case <-ticker.C:
		}

		// Clear the worker flag while holding the same lock PunchInit uses to
		// publish a new target. This closes the otherwise tiny window where a new
		// request could signal a worker that was already committed to exiting.
		sess.mu.Lock()
		active := sess.punchTarget != nil && time.Now().Before(sess.punchExpiry) && sess.secure != nil && !sess.secure.IsClosed()
		if !active {
			sess.punchWorker = false
			sess.mu.Unlock()
			return
		}
		target := cloneUDPAddr(sess.punchTarget)
		sess.mu.Unlock()
		// UDP errors are often transient. Keep the one bounded worker alive until
		// its migration window expires instead of letting repeated PunchInit
		// packets create replacement goroutines.
		_ = s.sendSessionPacket(sess, protocol.CmdStunProbe, []byte("PUNCH"), target)
	}
}

func (s *Server) sendCurrentPunchBurst(sess *clientSession, count int, interval time.Duration) {
	for i := 0; i < count; i++ {
		sess.mu.RLock()
		active := sess.punchTarget != nil && time.Now().Before(sess.punchExpiry) && sess.secure != nil && !sess.secure.IsClosed()
		target := cloneUDPAddr(sess.punchTarget)
		sess.mu.RUnlock()
		if !active {
			return
		}
		_ = s.sendSessionPacket(sess, protocol.CmdStunProbe, []byte("PUNCH"), target)
		if i+1 < count && interval > 0 {
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(interval):
			}
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

// handlePacket authenticates a wire packet before dispatching it.  Handshake
// requests are the only clear packets; all other commands must belong to an
// existing secure session.
func (s *Server) handlePacket(wire []byte, pkt *protocol.Packet, rawSenderAddr, realClientAddr *net.UDPAddr, proxied bool) {
	if pkt == nil || rawSenderAddr == nil {
		return
	}
	if pkt.Cmd == protocol.CmdHandshakeReq {
		s.handleHandshake(pkt, rawSenderAddr, realClientAddr, proxied)
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
	clientAddr := s.effectiveClientAddress(sess, rawSenderAddr, realClientAddr, proxied)
	// Every valid packet keeps the session alive and authorizes this source for
	// future packets. Only game data (or the initial handshake) changes the
	// upstream return path; background pings from alternative candidates must
	// not make server replies leak out of the route selected by relay-only.
	s.authorizeSessionSource(sess, rawSenderAddr)

	switch pkt.Cmd {
	case protocol.CmdHandshakeReq:
		// Handshake requests return from the authenticated prelude above.
		return

	case protocol.CmdStunProbe:
		respPayload := []byte(reflectAddress(clientAddr))
		wErr := s.sendSessionPacket(sess, protocol.CmdStunAck, respPayload, rawSenderAddr)

		// Log only the first probe per tunnel sender so STUN keepalives don't
		// spam the server log every few seconds.
		key := rawSenderAddr.String()
		first := s.recordStunProbe(key, time.Now())
		if first {
			log.Printf("[Server] STUN probe from %s (real %s, sid=%d) -> ack sent, wErr=%v", rawSenderAddr, clientAddr, pkt.SessionID, wErr)
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
		if sess.punchWake == nil {
			sess.punchWake = make(chan struct{}, 1)
		}
		wake := sess.punchWake
		startWorker := !sess.punchWorker
		if startWorker {
			sess.punchWorker = true
		}
		sess.mu.Unlock()
		_ = s.sendSessionPacket(sess, protocol.CmdPunchAck, []byte("PUNCH_INIT_OK"), rawSenderAddr)
		log.Printf("[Server] PunchInit (sid=%d) target %s via sender %s", pkt.SessionID, target, rawSenderAddr)

		// Coalesce repeated/retargeted PunchInit packets into one worker. The
		// buffered wake-up triggers an immediate burst without spawning a new pair
		// of goroutines for every authenticated datagram.
		select {
		case wake <- struct{}{}:
		default:
		}
		if startWorker && !s.startTask(func() { s.punchProbeLoop(sess) }) {
			sess.mu.Lock()
			sess.punchWorker = false
			sess.mu.Unlock()
		}

	case protocol.CmdPing:
		// Keep idle-but-alive sessions (and their stable upstream socket) from being
		// reaped, otherwise a re-dialed upstream would change the source port the
		// L4D2 server sees and disconnect the player.
		// Path classification is deliberately per packet/candidate. The same
		// authenticated handshake response can be reused by several candidate
		// sockets, so public_ips (or the first handshake source) cannot tell the
		// client whether this particular path is relayed.
		pathPayload := protocol.EncodePathHint(s.classifyPacketPath(sess, rawSenderAddr, proxied))
		if pathPayload == nil {
			return
		}
		// Keep the literal PONG payload for older clients. They ignore the new
		// authenticated hint command but continue to count the heartbeat.
		_ = s.sendSessionPacketAt(sess, protocol.CmdPathHint, pathPayload, rawSenderAddr, pkt.Timestamp)
		_ = s.sendSessionPacketAt(sess, protocol.CmdPong, []byte("PONG"), rawSenderAddr, pkt.Timestamp)

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
		s.setSessionReturnPath(sess, rawSenderAddr)
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

func (s *Server) handleHandshake(pkt *protocol.Packet, rawSenderAddr, realClientAddr *net.UDPAddr, proxied bool) {
	if rawSenderAddr == nil {
		return
	}
	if realClientAddr == nil {
		realClientAddr = rawSenderAddr
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
				_, _ = s.udpConn.WriteToUDP(entry.response, rawSenderAddr)
				return
			}
		}
	}

	sid := s.nextSessionID()
	metadata := s.handshakeMetadata(realClientAddr)
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
	if proxied {
		sess.proxySenderAddr = cloneUDPAddr(rawSenderAddr)
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
	if proxied {
		log.Printf("[Server] Client Handshake accepted (SessionID: %d, Real Client Endpoint: %s, Relay Sender: %s)", sid, realClientAddr, rawSenderAddr)
	} else {
		log.Printf("[Server] Client Handshake accepted (SessionID: %d, Sender: %s)", sid, rawSenderAddr)
	}
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

func (s *Server) handshakeMetadata(sender *net.UDPAddr) []byte {
	reflected := reflectAddress(sender)
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
	advertised := s.advertisedIPs
	if advertised == nil {
		// Keep direct callers/tests safe before Start; production startup has
		// already validated and normalized this list with the bound port.
		if normalized, err := discover.NormalizeEndpoints(s.cfg.PublicIPs, listenPort); err == nil {
			advertised = normalized
		} else {
			log.Printf("[Server] Ignoring invalid public_ips while building handshake metadata: %v", err)
		}
	}
	for _, a := range advertised {
		if len(combinedIPs) >= maxAdvertisedEndpoints {
			break
		}
		if a != "" && !seenAddrs[a] {
			seenAddrs[a] = true
			combinedIPs = append(combinedIPs, a)
		}
	}
	for _, a := range localCandidates {
		if len(combinedIPs) >= maxAdvertisedEndpoints {
			break
		}
		if !seenAddrs[a] {
			seenAddrs[a] = true
			combinedIPs = append(combinedIPs, a)
		}
	}
	// public_ips is an address advertisement only. The client learns whether a
	// particular candidate is Relay or Direct from its authenticated Ping/Pong
	// exchange, because one handshake response may be shared across sources.
	return []byte(fmt.Sprintf("%s|%s|%s", reflected, strings.Join(combinedIPs, ","), s.publicEndpointString()))
}

// classifyPacketPath reports how this exact authenticated packet reached the
// server. A PROXY envelope is the sole Relay signal; the advertised address,
// source IP shape, and real client IP must not promote a path to Direct.
func (s *Server) classifyPacketPath(sess *clientSession, rawSenderAddr *net.UDPAddr, proxied bool) string {
	if proxied || s.sessionUsesProxySource(sess, rawSenderAddr) {
		return protocol.PathHintRelay
	}
	return protocol.PathHintDirect
}

// classifyPath is retained for package-local diagnostics and older tests. New
// packet handling uses classifyPacketPath so it can distinguish candidates
// that share one cached handshake response.
func (s *Server) classifyPath(rawSenderAddr, realClientAddr *net.UDPAddr) string {
	if s != nil && s.proxySourceRecorded(rawSenderAddr) {
		return protocol.PathHintRelay
	}
	return protocol.PathHintDirect
}

func (s *Server) sessionUsesProxySource(sess *clientSession, rawSenderAddr *net.UDPAddr) bool {
	if sess == nil || rawSenderAddr == nil {
		return false
	}
	sess.mu.RLock()
	proxySenderAddr := cloneUDPAddr(sess.proxySenderAddr)
	sess.mu.RUnlock()
	return sameUDPAddr(proxySenderAddr, rawSenderAddr)
}

func (s *Server) proxySourceRecorded(source *net.UDPAddr) bool {
	if s == nil || source == nil {
		return false
	}
	s.proxySenderMu.Lock()
	entry := s.proxySenderStates[source.String()]
	s.proxySenderMu.Unlock()
	return entry != nil && entry.proxied
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

// effectiveClientAddress returns an address for reflection and diagnostics.
// It never participates in session authorization: that always uses the raw UDP
// sender plus the authenticated packet. A proxied address becomes usable only
// after the inner handshake/AEAD packet has validated, and is retained per
// session so a multiplexing relay cannot mix one client's address into another
// client's session when later datagrams omit the envelope.
func (s *Server) effectiveClientAddress(sess *clientSession, rawSenderAddr, reportedAddr *net.UDPAddr, proxied bool) *net.UDPAddr {
	if proxied && reportedAddr != nil {
		return cloneUDPAddr(reportedAddr)
	}
	if sess != nil && rawSenderAddr != nil {
		sess.mu.RLock()
		proxySenderAddr := cloneUDPAddr(sess.proxySenderAddr)
		realClientAddr := cloneUDPAddr(sess.realClientAddr)
		sess.mu.RUnlock()
		if proxySenderAddr != nil && realClientAddr != nil && sameUDPAddr(proxySenderAddr, rawSenderAddr) {
			return realClientAddr
		}
	}
	return cloneUDPAddr(rawSenderAddr)
}

func (s *Server) authorizeSessionSource(sess *clientSession, rawSenderAddr *net.UDPAddr) {
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
	sess.lastActive = time.Now()
	sess.mu.Unlock()
}

// setSessionReturnPath records the authenticated source that actually carried
// game traffic.  It is deliberately separate from authorizeSessionSource so
// control probes from non-selected candidates cannot redirect upstream replies.
func (s *Server) setSessionReturnPath(sess *clientSession, rawSenderAddr *net.UDPAddr) {
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
	sess.lastActive = time.Now()
	sess.mu.Unlock()
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
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
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
		// Register the reader before publishing the socket. Stop closes the
		// lifecycle gate first, so this cannot race with WaitGroup.Wait.
		if !s.startTask(func() { s.readUpstreamLoop(sess, upstreamConn) }) {
			_ = upstreamConn.Close()
			return
		}
		sess.upstream = upstreamConn
	}

	if _, err := sess.upstream.Write(payload); err != nil {
		// A locally closed/failed UDP socket must not remain published forever;
		// otherwise subsequent packets keep writing to the dead descriptor and the
		// reader can never be recreated. The next game packet will establish a new
		// upstream socket while preserving the authenticated session.
		_ = sess.upstream.Close()
		sess.upstream = nil
		log.Printf("[Server] Upstream write failed (sid=%d): %v; socket will be recreated", sess.sessionID, err)
	}
}

// readUpstreamLoop receives response UDP packets from actual L4D2 server and relays back to client via tunnel return path.
func (s *Server) readUpstreamLoop(sess *clientSession, upstream *net.UDPConn) {
	defer s.wg.Done()
	defer func() {
		// Clear only the socket this reader owns. A later packet may already have
		// installed a replacement after an independent write failure.
		sess.upstreamMu.Lock()
		if sess.upstream == upstream {
			sess.upstream = nil
		}
		sess.upstreamMu.Unlock()
	}()
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
			if errors.Is(err, net.ErrClosed) {
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
	var oldestLastActive time.Time
	for _, existing := range s.sessions {
		existing.mu.RLock()
		lastActive := existing.lastActive
		if oldest == nil || lastActive.Before(oldestLastActive) {
			oldest = existing
			oldestLastActive = lastActive
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

// cleanupSessionsLoop purges idle sessions and expired diagnostic state.
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

			// Keep diagnostic log-dedup state bounded across sender churn.
			s.pruneStunProbeLog(now)
			s.pruneProxyDropLog(now)
			s.pruneProxySenderStates(now)

			s.sessionMu.Lock()
			for sid, sess := range s.sessions {
				sess.mu.RLock()
				idle := now.Sub(sess.lastActive) > 60*time.Second
				sess.mu.RUnlock()

				if idle {
					sess.upstreamMu.Lock()
					if sess.upstream != nil {
						_ = sess.upstream.Close()
					}
					sess.upstreamMu.Unlock()
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
	s.startStopMu.Lock()
	defer s.startStopMu.Unlock()

	s.lifecycleMu.Lock()
	if s.stopping {
		s.lifecycleMu.Unlock()
		return
	}
	s.stopping = true
	s.lifecycleMu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}

	var upnpCleanup func()
	s.serverPubMu.Lock()
	upnpCleanup = s.upnpCleanup
	s.upnpCleanup = nil
	s.serverPubMu.Unlock()
	if upnpCleanup != nil {
		upnpCleanup()
	}

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
