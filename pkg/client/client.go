package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/discover"
	"left4proxy/pkg/protocol"
	"left4proxy/pkg/router"
	"left4proxy/pkg/security"
	"left4proxy/pkg/stun"
)

// gameConnIdleTimeout is how long the game netchannel socket can be silent
// before the client logs it as closed (the game returned to the main menu or
// its connection dropped). The game keeps sending heartbeats/timesync while
// connected, so 30s is well beyond normal idle.
const gameConnIdleTimeout = 30 * time.Second

// A failed punch endpoint can be re-advertised by the server after a NAT
// change. Bound retained sockets so repeated offers cannot consume an
// unbounded number of file descriptors and reader goroutines.
const maxPunchCandidates = 8
const maxCandidates = 64
const defaultServerPort = 27014

const (
	candidatePathLAN    = "lan"
	candidatePathRelay  = "relay"
	candidatePathPunch  = "punch"
	candidatePathDirect = "direct"
)

type serverCandidate struct {
	mu            sync.RWMutex
	addrStr       string
	udpAddr       *net.UDPAddr
	conn          *net.UDPConn
	traffic       *trafficCounters
	sendTo        *net.UDPAddr // Non-nil only for the punch candidate: an unconnected socket that must use WriteToUDP.
	isPunch       bool         // Punch (STUN hole-punched) candidate.
	pubEndpoint   string       // Punch candidate's own public endpoint (C_direct), learned via STUN reflection.
	lastActive    time.Time
	lastHandshake time.Time // Last handshake attempt to an offline candidate (reconnect backoff).
	rtt           time.Duration
	pingSent      uint64
	pingReceived  uint64
	isLAN         bool
	online        bool
	lastReflected string // Last STUN-reflected public endpoint, for deduped logging.
	pathClass     string // Authenticated path class: "relay" | "direct" | "punch" | "lan".
	punchEndpoint string // Authenticated server punch endpoint advertised in the handshake.
	stunValidator *stun.Validator
	retired       bool // Set before a failed punch socket is closed and removed.
}

// send writes data through the candidate's socket. Connected candidate sockets
// use conn.Write; the unconnected punch socket uses WriteToUDP to sendTo.
func (cand *serverCandidate) send(data []byte) error {
	if cand == nil {
		return fmt.Errorf("candidate is nil")
	}
	cand.mu.RLock()
	conn := cand.conn
	sendTo := cand.sendTo
	cand.mu.RUnlock()
	if conn == nil {
		return fmt.Errorf("candidate connection is nil")
	}
	var n int
	var err error
	if sendTo != nil {
		n, err = conn.WriteToUDP(data, sendTo)
	} else {
		n, err = conn.Write(data)
	}
	if n > 0 && cand.traffic != nil {
		cand.traffic.l4pUploadBytes.Add(uint64(n))
	}
	return err
}

func (cand *serverCandidate) recordWireReceive(n int) {
	if cand != nil && n > 0 && cand.traffic != nil {
		cand.traffic.l4pDownloadBytes.Add(uint64(n))
	}
}

// trafficCounters are process-local monotonic counters. Atomic counters keep
// the data plane independent from the CLI renderer and make a one-second rate
// sample cheap even while multiple candidate sockets are active.
type trafficCounters struct {
	gameUploadBytes   atomic.Uint64
	gameDownloadBytes atomic.Uint64
	l4pUploadBytes    atomic.Uint64
	l4pDownloadBytes  atomic.Uint64
}

// TrafficSnapshot is a point-in-time view of the four traffic directions
// exposed by the ping graph. L4P values are wire bytes, including protocol and
// encryption overhead and traffic sent on alternative candidates.
type TrafficSnapshot struct {
	GameUploadBytes   uint64 `json:"game_upload_bytes"`
	GameDownloadBytes uint64 `json:"game_download_bytes"`
	L4PUploadBytes    uint64 `json:"l4p_upload_bytes"`
	L4PDownloadBytes  uint64 `json:"l4p_download_bytes"`
}

// Client is the Left4Proxy client daemon.
type Client struct {
	cfg              *config.ClientConfig
	sessionID        atomic.Uint64 // Written by handshake responses, read by senders — must be atomic.
	secureSession    atomic.Pointer[security.Session]
	sessionMu        sync.Mutex
	acceptedHSSeq    uint32 // Handshake sequence that established secureSession.
	seq              uint32
	handshakeMu      sync.Mutex
	pendingHandshake *security.PendingHandshake
	handshakeWire    []byte
	authKey          []byte
	mode             atomic.Value // stores the normalized route mode for race-free runtime switches.
	localConn        *net.UDPConn
	traffic          trafficCounters
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
	natDetecting     atomic.Bool
	natMu            sync.Mutex // Serializes explicit CLI NAT checks with background detection.
	router           *router.Router
	holePuncher      atomic.Pointer[stun.HolePuncher]
	lastReportedPath router.PathType
	lastReportedCand string
	ctx              context.Context
	cancel           context.CancelFunc
	// startStopMu serializes the one-time socket setup with shutdown.  Without
	// this second gate, Stop could observe nil while Start was still publishing a
	// socket, then return before the newly-created loops were registered.
	startStopMu sync.Mutex
	lifecycleMu sync.Mutex
	started     bool
	stopping    bool
	wg          sync.WaitGroup
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
	if cfg == nil {
		return nil, fmt.Errorf("client configuration is nil")
	}
	mode, err := normalizeRouteMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	// Own an immutable configuration snapshot. Callers often reuse the YAML
	// struct for UI updates or wipe its key after construction; sharing its
	// slices/pointer with the live data plane would create races and could erase
	// the key while a handshake is in flight.
	ownedCfg := *cfg
	ownedCfg.Mode = mode
	ownedCfg.ServerAddrs = append([]string(nil), cfg.ServerAddrs...)
	ownedCfg.AuthKey = append([]byte(nil), cfg.AuthKey...)
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		cfg:              &ownedCfg,
		authKey:          append([]byte(nil), ownedCfg.AuthKey...),
		router:           router.NewRouter(mode),
		lastReportedPath: "",
		lastReportedCand: "",
		ctx:              ctx,
		cancel:           cancel,
	}
	client.mode.Store(mode)
	return client, nil
}

// startTask registers a background goroutine under the lifecycle gate. Stop
// closes this gate before waiting, preventing dynamic candidate callbacks from
// adding WaitGroup work after Wait has started.
func (s *Client) startTask(fn func()) bool {
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

func (s *Client) startTasks(count int) bool {
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
	return true
}

func normalizeRouteMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return "auto", nil
	case "direct-only", "direct":
		return "direct-only", nil
	case "relay-only", "relay":
		return "relay-only", nil
	default:
		return "", fmt.Errorf("invalid route mode %q: must be 'auto', 'direct-only' (or 'direct'), or 'relay-only' (or 'relay')", mode)
	}
}

func (s *Client) routeMode() string {
	if s != nil {
		if value := s.mode.Load(); value != nil {
			if mode, ok := value.(string); ok && mode != "" {
				return mode
			}
		}
		if s.cfg != nil && s.cfg.Mode != "" {
			return s.cfg.Mode
		}
	}
	return "auto"
}

// Start initializes local socket, connects to server candidates, and starts background loops.
func (s *Client) Start() error {
	s.startStopMu.Lock()
	defer s.startStopMu.Unlock()

	s.lifecycleMu.Lock()
	if s.stopping {
		s.lifecycleMu.Unlock()
		return fmt.Errorf("client is stopping or has already stopped")
	}
	if s.started {
		s.lifecycleMu.Unlock()
		return fmt.Errorf("client is already started")
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
		return fmt.Errorf("client authentication key is missing or invalid; provision the shared .secret file before starting")
	}
	// 1. Bind local listener (default: 127.0.0.2:27015 - L4D2 loopback requirement)
	localAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		rollbackStart()
		return fmt.Errorf("failed to resolve local listen addr %s: %w", s.cfg.ListenAddr, err)
	}

	lConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		rollbackStart()
		return fmt.Errorf("failed to listen on local UDP %s: %w", s.cfg.ListenAddr, err)
	}
	s.localConn = lConn

	// 2. Resolve remote server external addresses/domains
	addrs := s.cfg.GetServerAddrs()
	for _, addrStr := range addrs {
		// The address source is not a path classification. Wait for this socket's
		// authenticated Ping/Pong before admitting it to the data route.
		s.addCandidate(addrStr, "")
	}

	if len(s.candidates) == 0 {
		_ = s.localConn.Close()
		s.localConn = nil
		rollbackStart()
		return fmt.Errorf("no valid server candidates reachable from configured addrs: %v", addrs)
	}

	// Do not send game data until a configured or authenticated candidate has
	// completed the secure handshake.
	s.candidateMu.Lock()
	s.bestCandidate = nil
	s.prevCandidate = nil
	s.dualSendUntil = time.Time{}
	s.candidateMu.Unlock()

	// 3. Send initial Handshake across candidates
	s.candidateMu.RLock()
	cands := make([]*serverCandidate, len(s.candidates))
	copy(cands, s.candidates)
	s.candidateMu.RUnlock()

	for _, cand := range cands {
		s.sendHandshake(cand)
	}

	log.Printf("[Client] Left4Proxy Client active on %s | Initial Candidate: %s",
		s.cfg.ListenAddr, cands[0].addrStr)

	// 4. Start Hole Puncher & Background Loops
	if s.cfg.EnablePunch && s.routeMode() != "relay-only" && len(cands) > 0 {
		interval := time.Duration(s.cfg.PingInterval) * time.Second
		if interval <= 0 {
			interval = 3 * time.Second
		}
		holePuncher := stun.NewHolePuncher(s.sessionID.Load(), cands[0].conn, nil)
		holePuncher.SetSecureSender(s.sendHolePunchProbe)
		s.holePuncher.Store(holePuncher)
		// Close the publication race with a handshake that completed between
		// construction and Store. A later handshake also updates this value.
		holePuncher.SetSessionID(s.sessionID.Load())
		holePuncher.StartPunching(interval)
		log.Printf("[Client] STUN hole-punching enabled -> candidate [%s] (interval %v)", cands[0].addrStr, interval)
	} else {
		log.Printf("[Client] STUN hole-punching disabled (enable_punch=%v)", s.cfg.EnablePunch)
	}

	if !s.startTasks(3) {
		_ = s.localConn.Close()
		s.localConn = nil
		return fmt.Errorf("client is stopping")
	}
	go s.localReadLoop()
	go s.pingProbeLoop()
	go s.detectNATLoop()

	return nil
}

// addCandidate resolves an endpoint and records only a provisional candidate.
// Whether the path is actually Relay or Direct is learned from the server's
// authenticated Ping/Pong exchange; public_ips itself is only an address list.
func (s *Client) addCandidate(addrStr, path string) (*serverCandidate, bool) {
	normalized, err := discover.NormalizeEndpoint(addrStr, defaultServerPort)
	if err != nil {
		log.Printf("[Client] Ignoring invalid server endpoint %q: %v", addrStr, err)
		return nil, false
	}
	addrStr = normalized
	// Apply the hard cap before DNS resolution. Authenticated metadata can carry
	// many hostnames, and resolving entries that cannot possibly be retained
	// would let a bad configuration stall the client on unnecessary DNS work.
	s.candidateMu.RLock()
	for _, candidate := range s.candidates {
		if candidate != nil && candidate.addrStr == addrStr {
			s.setCandidatePath(candidate, path)
			s.candidateMu.RUnlock()
			return candidate, false
		}
	}
	atLimit := len(s.candidates) >= maxCandidates
	s.candidateMu.RUnlock()
	if atLimit {
		log.Printf("[Client] Candidate limit reached (%d); ignoring endpoint [%s]", maxCandidates, addrStr)
		return nil, false
	}
	udpAddr, err := net.ResolveUDPAddr("udp", normalized)
	if err != nil {
		return nil, false
	}

	s.candidateMu.Lock()
	defer s.candidateMu.Unlock()

	// Deduplicate by resolved IP:Port rather than input domain string!
	for _, c := range s.candidates {
		if c == nil || c.udpAddr == nil {
			continue
		}
		if c.udpAddr.String() == udpAddr.String() {
			s.setCandidatePath(c, path)
			return c, false
		}
	}
	if len(s.candidates) >= maxCandidates {
		log.Printf("[Client] Candidate limit reached (%d); ignoring endpoint [%s]", maxCandidates, addrStr)
		return nil, false
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
		traffic: &s.traffic,
		online:  false,
		rtt:     999 * time.Millisecond,
		isLAN:   isLAN,
	}
	s.setCandidatePath(cand, path)
	s.candidates = append(s.candidates, cand)

	if !s.startTask(func() { s.candidateReadLoop(cand) }) {
		_ = conn.Close()
		s.candidates = s.candidates[:len(s.candidates)-1]
		return nil, false
	}

	cand.mu.RLock()
	candidatePath := cand.pathClass
	cand.mu.RUnlock()
	log.Printf("[Client] Discovered Candidate Endpoint: [%s] (IP: %s, Path: %s)", addrStr, udpAddr.String(), candidatePath)
	return cand, true
}

func (s *Client) setCandidatePath(cand *serverCandidate, path string) {
	if cand == nil {
		return
	}
	cand.mu.Lock()
	defer cand.mu.Unlock()
	if cand.isPunch {
		cand.pathClass = candidatePathPunch
		return
	}
	// Relay can be retained as a legacy fallback after an old server's plain
	// Pong. Direct/LAN labels are observations, not candidate-list provenance,
	// and are applied only by applyPathHint.
	if path == candidatePathRelay {
		if cand.pathClass == "" || cand.pathClass == candidatePathRelay {
			cand.pathClass = path
		}
	}
}

// applyPathHint applies the server's authenticated classification for this
// exact candidate socket. A relay hint always wins over address-based LAN
// detection; a non-relay hint may be displayed as LAN when that local
// optimization is enabled.
func (s *Client) applyPathHint(cand *serverCandidate, hint string) bool {
	if cand == nil {
		return false
	}
	if hint != protocol.PathHintRelay && hint != protocol.PathHintDirect && hint != protocol.PathHintLAN && hint != protocol.PathHintPunch {
		return false
	}
	cand.mu.Lock()
	defer cand.mu.Unlock()
	if cand.isPunch {
		cand.pathClass = candidatePathPunch
		return true
	}
	switch hint {
	case protocol.PathHintRelay:
		cand.pathClass = candidatePathRelay
	case protocol.PathHintLAN:
		if s != nil && s.cfg != nil && s.cfg.EnableLAN && cand.isLAN {
			cand.pathClass = candidatePathLAN
		} else {
			cand.pathClass = candidatePathDirect
		}
	case protocol.PathHintDirect:
		if s != nil && s.cfg != nil && s.cfg.EnableLAN && cand.isLAN {
			cand.pathClass = candidatePathLAN
		} else {
			cand.pathClass = candidatePathDirect
		}
	case protocol.PathHintPunch:
		// A punch socket is identified locally by isPunch. Keep a non-punch
		// candidate conservative if an older server sends this hint.
		cand.pathClass = candidatePathDirect
	}
	return true
}

func (s *Client) applyPathHintPayload(cand *serverCandidate, payload []byte) bool {
	hint, ok := protocol.DecodePathHint(payload)
	if !ok {
		return false
	}
	cand.mu.RLock()
	oldPath := cand.pathClass
	cand.mu.RUnlock()
	if !s.applyPathHint(cand, hint) {
		return false
	}
	cand.mu.RLock()
	newPath := cand.pathClass
	cand.mu.RUnlock()
	if oldPath != newPath {
		log.Printf("[Client] Candidate path authenticated -> [%s] (Path: %s, PROXY: %v)", cand.addrStr, newPath, hint == protocol.PathHintRelay)
	}
	return true
}

// maybeCreatePunchCandidate establishes a STUN hole-punched direct candidate
// toward the server's public endpoint. It needs one authenticated non-punch
// control path for PunchInit; that path can be a relay or direct candidate
// after its authenticated per-socket classification.
func (s *Client) maybeCreatePunchCandidate(serverPublic string) {
	if !s.cfg.EnablePunch || s.routeMode() == "relay-only" {
		return
	}
	addr, err := net.ResolveUDPAddr("udp", serverPublic)
	if err != nil || addr == nil || addr.IP == nil || addr.Port < 1 || addr.Port > 65535 {
		log.Printf("[Client] Ignoring invalid punch endpoint %q: %v", serverPublic, err)
		return
	}

	s.candidateMu.RLock()
	for _, c := range s.candidates {
		if c == nil || c.udpAddr == nil {
			continue
		}
		if c.udpAddr.IP.Equal(addr.IP) && c.udpAddr.Port == addr.Port {
			s.candidateMu.RUnlock()
			return // already have this endpoint (e.g. a direct / port-forwarded candidate)
		}
	}
	s.candidateMu.RUnlock()

	if s.punchControlCandidate() == nil {
		return
	}
	s.addPunchCandidate(addr)
}

// addPunchCandidate creates the unconnected punch socket toward the server's
// public endpoint and starts its read loop and establishment goroutine.
func (s *Client) addPunchCandidate(serverPublic *net.UDPAddr) {
	if serverPublic == nil || s.routeMode() == "relay-only" {
		return
	}
	serverPublic = cloneUDPAddr(serverPublic)
	// Unconnected socket: it must talk to BOTH the public STUN server (to learn
	// this socket's NAT-mapped endpoint) and the server's public endpoint
	// (probes and, after migration, data).
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("[Client] Failed to create punch socket: %v", err)
		return
	}
	cand := &serverCandidate{
		addrStr:       serverPublic.String(),
		udpAddr:       serverPublic,
		conn:          conn,
		traffic:       &s.traffic,
		sendTo:        serverPublic,
		isPunch:       true,
		rtt:           999 * time.Millisecond,
		pathClass:     candidatePathPunch,
		stunValidator: stun.NewValidator(),
	}
	s.candidateMu.Lock()
	// maybeCreatePunchCandidate performs a pre-check for cheap gating, but the
	// check and append must be repeated while holding the write lock: handshake
	// responses and push offers can arrive concurrently.
	if s.routeMode() == "relay-only" {
		s.candidateMu.Unlock()
		_ = conn.Close()
		return
	}
	if len(s.candidates) >= maxCandidates {
		s.candidateMu.Unlock()
		_ = conn.Close()
		log.Printf("[Client] Candidate limit reached (%d); ignoring punch endpoint [%s]", maxCandidates, serverPublic)
		return
	}
	punchCount := 0
	for _, existing := range s.candidates {
		if existing == nil {
			continue
		}
		existing.mu.RLock()
		existingPunch := existing.isPunch
		existingAddr := existing.udpAddr
		existing.mu.RUnlock()
		if existingPunch {
			punchCount++
		}
		// A normal connected relay/direct candidate and an unconnected punch
		// candidate may intentionally share the same destination address: they
		// use different local sockets and therefore different NAT mappings. Only
		// suppress duplicate punch sockets.
		if existingPunch && existingAddr != nil && sameUDPAddr(existingAddr, serverPublic) {
			s.candidateMu.Unlock()
			_ = conn.Close()
			return
		}
	}
	if punchCount >= maxPunchCandidates {
		s.candidateMu.Unlock()
		_ = conn.Close()
		log.Printf("[Client] Punch candidate limit reached (%d); ignoring endpoint [%s]", maxPunchCandidates, serverPublic)
		return
	}
	s.candidates = append(s.candidates, cand)
	s.candidateMu.Unlock()

	if !s.startTask(func() { s.candidateReadLoop(cand) }) {
		s.punchFailed(cand)
		return
	}
	if !s.startTask(func() { s.establishPunch(cand) }) {
		s.punchFailed(cand)
		return
	}

	log.Printf("[Client] Punch candidate created -> direct endpoint [%s] (socket %s)", serverPublic, conn.LocalAddr())
}

// relayCandidate returns an online candidate used as the control channel to the
// server. The punch negotiation must travel over the tunnel so the server maps
// it to our session.
func (s *Client) relayCandidate() *serverCandidate {
	s.candidateMu.RLock()
	defer s.candidateMu.RUnlock()
	for _, c := range s.candidates {
		if c == nil {
			continue
		}
		c.mu.RLock()
		hint := c.pathClass
		online := c.online
		c.mu.RUnlock()
		if hint == candidatePathRelay && online {
			return c
		}
	}
	return nil
}

// punchControlCandidate returns an authenticated non-punch socket suitable for
// carrying PunchInit. Relay is preferred, but a local integration path can be
// reclassified as LAN/Direct by the next authenticated Pong while a punch
// attempt is already in flight. Any still-online non-punch socket is a valid
// control channel in that case; the server binds the requested target only
// after validating the AEAD session.
func (s *Client) punchControlCandidate() *serverCandidate {
	if relay := s.relayCandidate(); relay != nil {
		return relay
	}
	s.candidateMu.RLock()
	defer s.candidateMu.RUnlock()
	for _, c := range s.candidates {
		if c == nil {
			continue
		}
		c.mu.RLock()
		isPunch, online := c.isPunch, c.online
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
	if s.routeMode() == "relay-only" {
		return
	}
	relay := s.punchControlCandidate()
	if relay == nil {
		return
	}
	data, err := s.sealClientPacket(protocol.CmdPunchInit, []byte(cDirect))
	if err != nil {
		return
	}
	if err := relay.send(data); err != nil {
		log.Printf("[Client] PunchInit send failed: %v", err)
		return
	}
	log.Printf("[Client] PunchInit sent (my public endpoint %s) via candidate [%s]", cDirect, relay.addrStr)
}

// sealClientPacket creates an authenticated client-to-server packet using the
// one session adopted from the first valid handshake response.
func (s *Client) sealClientPacket(cmd byte, payload []byte) ([]byte, error) {
	sess := s.secureSession.Load()
	if sess == nil {
		return nil, fmt.Errorf("secure session is not established")
	}
	seq, err := sess.NextSeq()
	if err != nil {
		return nil, err
	}
	pkt := protocol.NewPacket(cmd, sess.ID, seq, payload)
	return sess.Seal(pkt, security.ClientToServer)
}

// sendCandidatePing sends one authenticated RTT probe and records it only
// after the candidate socket accepts the complete UDP datagram. The counters
// are used for the CLI quality view; route selection keeps its existing
// hysteresis behavior independent from presentation sampling.
func (s *Client) sendCandidatePing(cand *serverCandidate) bool {
	if s == nil || cand == nil {
		return false
	}
	data, err := s.sealClientPacket(protocol.CmdPing, []byte("PING"))
	if err != nil {
		return false
	}
	if err := cand.send(data); err != nil {
		return false
	}
	cand.mu.Lock()
	cand.pingSent++
	cand.mu.Unlock()
	return true
}

func (s *Client) sendSecureProbeBurst(cand *serverCandidate, count int, interval time.Duration) {
	if cand == nil || count <= 0 {
		return
	}
	for i := 0; i < count; i++ {
		if s.routeMode() == "relay-only" {
			return
		}
		data, err := s.sealClientPacket(protocol.CmdStunProbe, []byte("PUNCH"))
		if err == nil {
			cand.mu.RLock()
			retired := cand.retired
			cand.mu.RUnlock()
			if retired {
				return
			}
			_ = cand.send(data)
		}
		if i+1 < count && interval > 0 {
			time.Sleep(interval)
		}
	}
}

// sendHolePunchProbe is used by the periodic HolePuncher callback.  It always
// follows the currently selected candidate and seals the probe before send.
func (s *Client) sendHolePunchProbe() error {
	if s.routeMode() == "relay-only" {
		return fmt.Errorf("hole punching is disabled in relay-only mode")
	}
	s.candidateMu.RLock()
	cand := s.bestCandidate
	s.candidateMu.RUnlock()
	if cand == nil {
		return fmt.Errorf("no active candidate")
	}
	data, err := s.sealClientPacket(protocol.CmdStunProbe, []byte("PUNCH"))
	if err != nil {
		return err
	}
	return cand.send(data)
}

// waitPublicEndpoint blocks until the punch socket learns its public endpoint
// via STUN reflection (or the timeout elapses).
func (s *Client) waitPublicEndpoint(cand *serverCandidate, timeout time.Duration) string {
	if cand == nil {
		return ""
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-s.ctx.Done():
			return ""
		default:
		}
		cand.mu.RLock()
		pe, retired := cand.pubEndpoint, cand.retired
		cand.mu.RUnlock()
		if retired {
			return ""
		}
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
	if s.routeMode() == "relay-only" {
		s.retirePunchCandidate(cand, "aborted because route mode is relay-only")
		return
	}

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
	cand.mu.Lock()
	if cand.stunValidator == nil {
		cand.stunValidator = stun.NewValidator()
	}
	validator := cand.stunValidator
	conn := cand.conn
	cand.mu.Unlock()
	if conn == nil {
		s.punchFailed(cand)
		return
	}
	for i := 0; i < 2; i++ {
		if s.routeMode() == "relay-only" {
			s.retirePunchCandidate(cand, "aborted because route mode is relay-only")
			return
		}
		_ = validator.SendMultiBindingRequests(conn, stunAddrs)
		time.Sleep(20 * time.Millisecond)
	}
	cDirect := s.waitPublicEndpoint(cand, 2*time.Second)
	initSent := false
	if cDirect != "" {
		s.sendPunchInit(cand, cDirect)
		initSent = true
	}

	// 2. Probe the server's public endpoint until confirmed or timed out.
	// Immediately send an initial authenticated burst to establish the client
	// NAT mapping within ~100ms.
	if !s.startTask(func() {
		defer s.wg.Done()
		s.sendSecureProbeBurst(cand, 5, 25*time.Millisecond)
	}) {
		return
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		if s.routeMode() == "relay-only" {
			s.retirePunchCandidate(cand, "aborted because route mode is relay-only")
			return
		}
		if data, err := s.sealClientPacket(protocol.CmdStunProbe, []byte("PUNCH")); err == nil {
			_ = cand.send(data)
		}

		cand.mu.RLock()
		online := cand.online
		reflected := cand.lastReflected
		retired := cand.retired
		cand.mu.RUnlock()
		if retired {
			return
		}

		if online {
			log.Printf("[Client] Punch path confirmed -> direct endpoint [%s] (socket %s)", cand.udpAddr, cand.conn.LocalAddr())
			s.selectBestCandidate()
			// One-shot diagnostic: once the ping loop has measured the punch
			// candidate's RTT, report how it compares to the current best so it's
			// obvious whether the direct path won or why it didn't.
			s.startTask(func() {
				defer s.wg.Done()
				s.logPunchRttDiagnostic(cand)
			})
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
	s.retirePunchCandidate(cand, "failed (no direct path), staying on relay")
}

func (s *Client) retirePunchCandidate(cand *serverCandidate, reason string) {
	if cand == nil {
		return
	}
	cand.mu.Lock()
	if cand.retired {
		cand.mu.Unlock()
		return
	}
	cand.online = false
	cand.retired = true
	conn := cand.conn
	cand.mu.Unlock()
	if conn != nil {
		// Closing the socket wakes candidateReadLoop immediately. The pointer is
		// intentionally retained until the goroutine exits; setting it to nil
		// would race with the reader's ReadFromUDP call.
		_ = conn.Close()
	}
	s.removeCandidate(cand)
	if reason != "" {
		log.Printf("[Client] Punch candidate [%s] %s", cand.addrStr, reason)
	}
}

func (s *Client) removeCandidate(target *serverCandidate) {
	if target == nil {
		return
	}
	s.candidateMu.Lock()
	for i, cand := range s.candidates {
		if cand != target {
			continue
		}
		s.candidates = append(s.candidates[:i], s.candidates[i+1:]...)
		if s.bestCandidate == target {
			s.bestCandidate = nil
		}
		if s.prevCandidate == target {
			s.prevCandidate = nil
			s.dualSendUntil = time.Time{}
		}
		break
	}
	s.candidateMu.Unlock()
	// Re-evaluate the route after removal so a healthy relay can become active
	// immediately instead of waiting for the next ping tick.
	s.selectBestCandidate()
}

// logPunchRttDiagnostic waits (up to ~6s) for the punch candidate's RTT to be
// measured by the normal ping loop, then logs how it compares to the current
// best candidate. This makes the routing decision — and the direct path's real
// latency — visible, so a human can tell "direct is genuinely slower" apart
// from "RTT was never measured".
func (s *Client) logPunchRttDiagnostic(cand *serverCandidate) {
	if cand == nil {
		return
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		cand.mu.RLock()
		punchRTT, retired := cand.rtt, cand.retired
		cand.mu.RUnlock()
		if retired {
			return
		}
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
	// Once a session exists, bind/reprobe this candidate with an authenticated
	// Ping instead of minting a new X25519 session.  Replacing a healthy session
	// merely because one candidate went quiet would also replace the server's
	// upstream UDP socket and drop an active game.
	if sess := s.secureSession.Load(); sess != nil && !sess.IsClosed() {
		s.sendCandidatePing(cand)
		return
	}
	s.handshakeMu.Lock()
	// A pending request is shared across candidate sockets, but it must not be
	// reused forever: after a server restart the old session/cache may be gone,
	// and an old timestamp would eventually be rejected as stale.
	if s.pendingHandshake == nil || time.Since(time.Unix(0, s.pendingHandshake.Timestamp)) > 90*time.Second {
		seq := atomic.AddUint32(&s.seq, 1)
		pkt, pending, err := security.NewHandshakeRequest(s.authKey, seq)
		if err != nil {
			s.handshakeMu.Unlock()
			log.Printf("[Client] Failed to create authenticated handshake: %v", err)
			return
		}
		s.pendingHandshake = pending
		s.handshakeWire = pkt.Marshal()
	}
	data := append([]byte(nil), s.handshakeWire...)
	s.handshakeMu.Unlock()
	_ = cand.send(data)
}

// pathForCandidate maps an authenticated path class to the routing tier.
func (s *Client) pathForCandidate(cand *serverCandidate) router.PathType {
	if cand == nil {
		return router.PathNone
	}
	cand.mu.RLock()
	isLAN := cand.isLAN
	hint := cand.pathClass
	isPunch := cand.isPunch
	cand.mu.RUnlock()
	return pathForCandidateValues(isLAN, hint, isPunch)
}

func pathForCandidateValues(isLAN bool, hint string, isPunch bool) router.PathType {
	switch hint {
	case candidatePathRelay:
		return router.PathRelay
	case candidatePathPunch:
		return router.PathPunch
	case candidatePathDirect:
		return router.PathDirect
	case candidatePathLAN:
		return router.PathLAN
	default:
		if isPunch {
			return router.PathPunch
		}
		if isLAN {
			return router.PathLAN
		}
		// Unknown candidates are displayed as Relay for compatibility, but are
		// not admitted to the data path.
		return router.PathRelay
	}
}

func (s *Client) candidateAllowed(cand *serverCandidate) bool {
	if cand == nil {
		return false
	}
	cand.mu.RLock()
	isLAN, hint, isPunch := cand.isLAN, cand.pathClass, cand.isPunch
	cand.mu.RUnlock()
	return s.candidateAllowedValues(isLAN, hint, isPunch)
}

func (s *Client) candidateAllowedValues(isLAN bool, hint string, isPunch bool) bool {
	mode := s.routeMode()
	enableLAN := true
	if s != nil && s.cfg != nil {
		enableLAN = s.cfg.EnableLAN
	}
	// Provenance is authoritative. Address shape alone is ambiguous because a
	// local endpoint can still front a relay process.
	switch mode {
	case "relay-only":
		return !isPunch && hint == candidatePathRelay
	case "direct-only":
		if hint == "" || hint == candidatePathRelay {
			return false
		}
		if hint == candidatePathLAN {
			return enableLAN
		}
		return hint == candidatePathDirect || hint == candidatePathPunch
	default:
		switch hint {
		case candidatePathLAN:
			return enableLAN
		case candidatePathRelay, candidatePathDirect, candidatePathPunch:
			return true
		default:
			return false
		}
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
		if cand == nil {
			continue
		}
		cand.mu.RLock()
		lastActive := cand.lastActive
		online := cand.online
		rtt := cand.rtt
		isLAN := cand.isLAN
		pathClass := cand.pathClass
		isPunch := cand.isPunch
		cand.mu.RUnlock()
		lanCandidate := pathClass == candidatePathLAN

		// Apply the routing mode to the actual candidate, not just to the display
		// router. In particular relay-only excludes every non-relay candidate.
		if !s.candidateAllowedValues(isLAN, pathClass, isPunch) {
			continue
		}

		if online && !lastActive.IsZero() && now.Sub(lastActive) <= 15*time.Second {
			effRTT := rtt
			if lanCandidate {
				effRTT = effRTT / 10 // Strongly favor LAN candidates
			}
			if best == nil || effRTT < bestEffectiveRTT {
				best = cand
				bestEffectiveRTT = effRTT
			}
		}
	}

	if best == nil {
		// No candidate satisfies the current mode and liveness window. Keep the
		// data plane fail-closed in every mode; retaining a stale best candidate
		// here would continue sending game packets over a route that the selector
		// has already deemed unavailable.
		s.bestCandidate = nil
		s.prevCandidate = nil
		s.dualSendUntil = time.Time{}
		return
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
			currLAN := s.bestCandidate.pathClass == candidatePathLAN
			currOnline := s.bestCandidate.online
			currLastActive := s.bestCandidate.lastActive
			s.bestCandidate.mu.RUnlock()

			best.mu.RLock()
			bestLAN := best.pathClass == candidatePathLAN
			bestRTT := best.rtt
			best.mu.RUnlock()

			currDead := !s.candidateAllowed(s.bestCandidate) || !currOnline || now.Sub(currLastActive) > 15*time.Second
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
		oldBestOnline := false
		if oldBest != nil {
			oldBest.mu.RLock()
			oldBestOnline = oldBest.online
			oldBest.mu.RUnlock()
		}
		if oldBest != nil && oldBestOnline && oldBest != best && s.candidateAllowed(oldBest) && s.candidateAllowed(best) {
			s.prevCandidate = oldBest
			s.dualSendUntil = time.Now().Add(400 * time.Millisecond)
			log.Printf("[Client] Route migration: Dual-sending to [%s] and [%s] for 400ms (0-RTT handoff)", best.addrStr, oldBest.addrStr)
		}

		best.mu.RLock()
		bestRTT := best.rtt
		bestLAN := best.pathClass == candidatePathLAN
		best.mu.RUnlock()

		// Keep the hole puncher following the active candidate, so STUN keepalives
		// keep the NAT mapping of the path that actually carries data alive.
		if holePuncher := s.holePuncher.Load(); s.cfg.EnablePunch && s.routeMode() != "relay-only" && holePuncher != nil {
			best.mu.RLock()
			bestSendTo := best.sendTo
			best.mu.RUnlock()
			holePuncher.Retarget(best.conn, bestSendTo)
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
		s.traffic.gameUploadBytes.Add(uint64(n))

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

		marshaled, err := s.sealClientPacket(protocol.CmdData, append([]byte(nil), payload...))
		if err != nil {
			continue
		}

		s.candidateMu.RLock()
		activeCand := s.bestCandidate
		prevCand := s.prevCandidate
		dualUntil := s.dualSendUntil
		s.candidateMu.RUnlock()

		if activeCand != nil && s.candidateAllowed(activeCand) {
			_ = activeCand.send(marshaled)
			// 0-RTT dual-sending: during route migration, send to both paths to prevent single packet drops
			if prevCand != nil && prevCand != activeCand && s.candidateAllowed(prevCand) && time.Now().Before(dualUntil) {
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
	if cand == nil {
		return
	}
	cand.mu.RLock()
	conn := cand.conn
	cand.mu.RUnlock()
	if conn == nil {
		return
	}
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
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
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		data := buf[:n]
		cand.recordWireReceive(n)

		// STUN responses are accepted only through the punch socket's pending
		// transaction validator.  A forged magic-cookie packet is discarded.
		cand.mu.RLock()
		validator := cand.stunValidator
		isPunch := cand.isPunch
		udpAddr := cand.udpAddr
		cand.mu.RUnlock()
		if validator != nil {
			if validated, verr := validator.Accept(data, src); verr == nil {
				addr := validated.Reflected
				cand.mu.Lock()
				if cand.pubEndpoint == "" || cand.pubEndpoint != addr.String() {
					cand.pubEndpoint = addr.String()
					log.Printf("[Client] Punch socket public endpoint discovered -> %s (candidate %s)", addr, cand.addrStr)
				}
				cand.mu.Unlock()
				continue
			}
			if stun.IsStunResponse(data) {
				continue
			}
		}

		pkt, err := protocol.Unmarshal(data)
		if err != nil {
			continue
		}

		if pkt.Cmd == protocol.CmdHandshakeResp {
			s.handleHandshakeResponse(cand, pkt)
			continue
		}
		sess := s.secureSession.Load()
		if sess == nil {
			continue
		}
		// For an unconnected punch socket, reject datagrams from any source
		// other than the authenticated server endpoint before opening the AEAD.
		// Otherwise a captured valid ciphertext sent by an unexpected peer could
		// consume the replay-window slot and make the legitimate packet look like
		// a replay when it arrives on the correct path.
		if isPunch && (udpAddr == nil || !sameUDPAddr(src, udpAddr)) {
			continue
		}
		opened, err := sess.Open(data, security.ServerToClient)
		if err != nil {
			continue
		}
		pkt = opened

		cand.mu.Lock()
		cand.lastActive = time.Now()
		cand.online = true
		cand.mu.Unlock()

		// A server-initiated STUN probe on the punch socket proves the
		// server→client direction and keeps both NAT mappings open — reply to the
		// exact source so the reply flows back on the direct path.
		s.handleServerPacket(cand, pkt)
	}
}

func (s *Client) handleHandshakeResponse(cand *serverCandidate, pkt *protocol.Packet) {
	s.handshakeMu.Lock()
	pending := s.pendingHandshake
	s.handshakeMu.Unlock()
	if pending == nil {
		return
	}
	response, session, err := security.VerifyHandshakeResponse(s.authKey, pkt, pending, time.Now().UnixNano())
	if err != nil {
		return
	}
	s.sessionMu.Lock()
	current := s.secureSession.Load()
	// A single pending request may be sent over several candidate sockets.
	// Adopt only the first authenticated session response for that request;
	// accepting a later response with a different session ID would let a delayed
	// replay roll the client back to a session the server no longer owns.
	if current != nil && s.acceptedHSSeq == pending.Seq && current.ID != response.SessionID {
		s.sessionMu.Unlock()
		session.Close()
		return
	}
	if current == nil || current.ID != response.SessionID {
		// A different authenticated session is accepted only for a new pending
		// handshake (or after an explicit reconnect reset); late responses for
		// the already-adopted request were rejected above.
		s.secureSession.Store(session)
		s.sessionID.Store(response.SessionID)
		s.acceptedHSSeq = pending.Seq
		if current != nil {
			current.Close()
		}
	} else {
		// Every valid candidate response derives an equivalent Session object;
		// keep the adopted one and wipe the redundant key copy.
		session.Close()
	}
	s.sessionMu.Unlock()
	if holePuncher := s.holePuncher.Load(); holePuncher != nil {
		holePuncher.SetSessionID(response.SessionID)
	}

	// Use the session selected by the first valid response for all candidates;
	// the server accepts that authenticated session on each address learned from
	// the same handshake, which keeps route migration on one upstream socket.
	handshakeRTT := time.Duration(time.Now().UnixNano() - pkt.Timestamp)
	if handshakeRTT <= 0 || handshakeRTT > 10*time.Second {
		handshakeRTT = 999 * time.Millisecond
	}
	cand.mu.Lock()
	cand.lastActive = time.Now()
	cand.online = true
	cand.rtt = handshakeRTT
	candRTT := cand.rtt
	parts := strings.SplitN(string(response.Metadata), "|", 3)
	if len(parts) > 2 {
		cand.punchEndpoint = parts[2]
	}
	cand.mu.Unlock()

	reflected := ""
	if len(parts) > 0 {
		reflected = parts[0]
	}
	log.Printf("[Client] Connected & Handshake Verified -> Candidate [%s] (IP: %s, RTT: %v) | SessionID: %d | Apparent Endpoint: %s",
		cand.addrStr, cand.udpAddr.String(), candRTT, response.SessionID, reflected)
	if len(parts) > 1 && parts[1] != "" {
		for _, advAddr := range strings.Split(parts[1], ",") {
			advAddr = strings.TrimSpace(advAddr)
			if advAddr != "" {
				// public_ips only declares another address to try. Do not label it
				// Direct until this socket's authenticated Pong reports that no
				// PROXY envelope was used.
				newCand, isNew := s.addCandidate(advAddr, "")
				if isNew && newCand != nil {
					s.sendHandshake(newCand)
				}
			}
		}
	}
	// Bind this candidate source to the shared session and obtain a fresh RTT.
	s.sendCandidatePing(cand)
	s.selectBestCandidate()
}

// writeGamePacket is the single game-facing write path. Counting after the
// socket write means the graph reports bytes actually handed to the game UDP
// socket rather than merely bytes received from the remote server.
func (s *Client) writeGamePacket(payload []byte, addr *net.UDPAddr) {
	if s == nil || s.localConn == nil || addr == nil || len(payload) == 0 {
		return
	}
	n, _ := s.localConn.WriteToUDP(payload, addr)
	if n > 0 {
		s.traffic.gameDownloadBytes.Add(uint64(n))
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
	case protocol.CmdStunProbe:
		// Reply through the same authenticated candidate so the server can keep
		// the punched mapping alive and prove the reverse direction.
		if s.routeMode() != "relay-only" {
			if data, err := s.sealClientPacket(protocol.CmdStunAck, []byte(reflectAddress(cand.conn.LocalAddr()))); err == nil {
				_ = cand.send(data)
			}
		}

	case protocol.CmdHandshakeResp:
		// Handshake responses are authenticated and handled exclusively by
		// handleHandshakeResponse before this secure-packet dispatcher.
		return

	case protocol.CmdPathHint:
		if !s.applyPathHintPayload(cand, pkt.Payload) {
			return
		}
		s.selectBestCandidate()

	case protocol.CmdPong:
		if string(pkt.Payload) != "PONG" {
			// Accept the short-lived path-in-Pong format during a rolling update,
			// but current servers send CmdPathHint plus the stable PONG payload.
			if !s.applyPathHintPayload(cand, pkt.Payload) {
				return
			}
		} else {
			// Older servers returned a plain PONG and had no authenticated path
			// hint. Preserve the historical safe fallback for those peers while
			// requiring current peers to report Relay/Direct explicitly.
			cand.mu.Lock()
			if cand.pathClass == "" && !cand.isPunch {
				cand.pathClass = candidatePathRelay
			}
			cand.mu.Unlock()
		}
		cand.mu.Lock()
		cand.pingReceived++
		candRTT := cand.rtt
		punchEndpoint := cand.punchEndpoint
		isPunch := cand.isPunch
		cand.mu.Unlock()

		s.router.UpdateMetrics(s.pathForCandidate(cand), candRTT, 0.0)
		if punchEndpoint != "" && !isPunch {
			s.maybeCreatePunchCandidate(punchEndpoint)
		}
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
		cand.mu.RLock()
		isPunch := cand.isPunch
		cand.mu.RUnlock()
		if !isPunch {
			log.Printf("[Client] Server acknowledged punch init (candidate %s)", cand.addrStr)
		}

	case protocol.CmdData:
		// Route mode is enforced in both directions. A queued response can
		// still arrive on a candidate that was active before a mode switch; do
		// not deliver it to the game when that candidate is no longer allowed
		// (in particular, relay-only must not accept Punch/LAN/Direct data).
		if !s.candidateAllowed(cand) {
			return
		}
		if len(pkt.Payload) == 0 {
			break
		}
		// A2S query responses belong to the server-browser socket, NOT the
		// game's netchannel socket. Sending them to lastClientAddr (the last
		// local sender — often the netchannel ack) makes the netchannel see a
		// spurious 0x41 challenge and abort with "Invalid challenge packet".
		if isA2SResponse(pkt.Payload) {
			if a2s := s.a2sQueryAddr.Load(); a2s != nil {
				s.writeGamePacket(pkt.Payload, a2s)
				break
			}
		}
		if addr := s.lastClientAddr.Load(); addr != nil {
			s.writeGamePacket(pkt.Payload, addr)
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

			s.candidateMu.RLock()
			cands := make([]*serverCandidate, len(s.candidates))
			copy(cands, s.candidates)
			s.candidateMu.RUnlock()

			anyOnline := false
			anyRecent := false
			now := time.Now()

			for _, cand := range cands {
				if cand == nil {
					continue
				}
				allowed := s.candidateAllowed(cand)
				cand.mu.RLock()
				isPunch := cand.isPunch
				hint := cand.pathClass
				lastActive := cand.lastActive
				cand.mu.RUnlock()
				if !lastActive.IsZero() && now.Sub(lastActive) <= 15*time.Second {
					anyRecent = true
				}

				gameActive := s.gameConnAddr.Load() != nil
				// Normal timeout is 15s. However, during active gameplay on a punched path,
				// if no packet is received for > 2.5s, trigger fast failover to Relay to prevent game disconnect.
				maxStale := 15 * time.Second
				if gameActive && isPunch {
					maxStale = 2500 * time.Millisecond
				}

				if allowed && !lastActive.IsZero() && now.Sub(lastActive) <= maxStale {
					cand.mu.Lock()
					cand.online = true
					cand.mu.Unlock()
					anyOnline = true
					// Each path gets a distinct sequence/nonce. Reusing one
					// ciphertext across candidates would make the replay window
					// discard the second copy before it can measure that path.
					s.sendCandidatePing(cand)
				} else {
					cand.mu.RLock()
					wasOnline := cand.online
					cand.mu.RUnlock()
					if gameActive && isPunch && wasOnline {
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
					// In relay-only, do not keep probing a candidate that has
					// already been authenticated as direct/LAN/punch. An unknown
					// candidate may still receive a classification handshake.
					if !isPunch && canRehandshake && (s.routeMode() != "relay-only" || hint == "") {
						s.sendHandshake(cand)
					}
				}
			}

			s.selectBestCandidate()

			if !anyOnline {
				// Clear every route class, including direct-tier metrics. Otherwise
				// Router can continue reporting a stale Direct/Punch path even though
				// the candidate selector has established that no socket is live.
				s.router.SetInactive(router.PathLAN)
				s.router.SetInactive(router.PathDirect)
				s.router.SetInactive(router.PathPunch)
				s.router.SetInactive(router.PathRelay)

				if s.lastReportedCand != "OFFLINE" {
					s.lastReportedCand = "OFFLINE"
					s.lastReportedPath = ""
					log.Printf("[Client] Warning: All server candidates offline. Retrying connection...")
				}
				// A live session can reprobe new candidate sockets indefinitely.
				// Only discard its keys after every candidate has been silent long
				// enough to indicate a server restart or total outage; this avoids
				// replacing an active upstream socket during a transient route loss.
				if !anyRecent && s.secureSession.Load() != nil {
					s.resetSecureSessionForReconnect()
					for _, cand := range cands {
						cand.mu.RLock()
						isPunch := cand.isPunch
						cand.mu.RUnlock()
						if !isPunch {
							s.sendHandshake(cand)
						}
					}
				}
				continue
			}

			s.candidateMu.RLock()
			bestCand := s.bestCandidate
			s.candidateMu.RUnlock()

			curPath := router.PathNone
			candKey := ""
			if bestCand != nil {
				bestCand.mu.RLock()
				if bestCand.udpAddr != nil {
					candKey = bestCand.udpAddr.String()
				}
				curPath = pathForCandidateValues(bestCand.isLAN, bestCand.pathClass, bestCand.isPunch)
				bestCand.mu.RUnlock()
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

// resetSecureSessionForReconnect drops a session only after the liveness loop
// has established that every candidate is stale.  It is intentionally separate
// from Stop so normal route changes never wipe a session that still backs an
// active upstream game socket.
func (s *Client) resetSecureSessionForReconnect() {
	s.sessionMu.Lock()
	if sess := s.secureSession.Load(); sess != nil {
		sess.Close()
		s.secureSession.Store(nil)
	}
	s.sessionID.Store(0)
	if holePuncher := s.holePuncher.Load(); holePuncher != nil {
		holePuncher.SetSessionID(0)
	}
	s.acceptedHSSeq = 0
	s.sessionMu.Unlock()

	s.handshakeMu.Lock()
	s.pendingHandshake = nil
	for i := range s.handshakeWire {
		s.handshakeWire[i] = 0
	}
	s.handshakeWire = nil
	s.handshakeMu.Unlock()
}

// Stop shuts down the client.
func (s *Client) Stop() {
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
	if holePuncher := s.holePuncher.Load(); holePuncher != nil {
		holePuncher.Stop()
	}
	if s.localConn != nil {
		_ = s.localConn.Close()
	}

	s.candidateMu.Lock()
	for _, cand := range s.candidates {
		if cand == nil {
			continue
		}
		if cand.conn != nil {
			_ = cand.conn.Close()
		}
	}
	s.candidateMu.Unlock()

	s.wg.Wait()
	s.sessionMu.Lock()
	if sess := s.secureSession.Load(); sess != nil {
		sess.Close()
		s.secureSession.Store(nil)
	}
	s.sessionID.Store(0)
	s.acceptedHSSeq = 0
	s.sessionMu.Unlock()
	s.handshakeMu.Lock()
	s.pendingHandshake = nil
	for i := range s.handshakeWire {
		s.handshakeWire[i] = 0
	}
	s.handshakeWire = nil
	s.handshakeMu.Unlock()
	for i := range s.authKey {
		s.authKey[i] = 0
	}
	log.Printf("[Client] Client stopped successfully")
}

// CandidateStatus holds snapshot information about a server candidate.
type CandidateStatus struct {
	Addr          string          `json:"addr"`
	ResolvedIP    string          `json:"resolved_ip"`
	Online        bool            `json:"online"`
	RTT           time.Duration   `json:"rtt"`
	LossRate      float64         `json:"loss_rate"`
	PathType      router.PathType `json:"path_type"`
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
	ActiveLossRate  float64              `json:"active_loss_rate"`
	GameConnected   bool                 `json:"game_connected"`
	GameAddr        string               `json:"game_addr,omitempty"`
	GameLastSeen    time.Time            `json:"game_last_seen,omitempty"`
	PunchEnabled    bool                 `json:"punch_enabled"`
	NATSummary      string               `json:"nat_summary"`
	NATInfo         *stun.NATMappingInfo `json:"nat_info,omitempty"`
	Candidates      []CandidateStatus    `json:"candidates"`
}

func pingLossRate(sent, received uint64) float64 {
	if sent == 0 || received >= sent {
		return 0
	}
	return float64(sent-received) / float64(sent)
}

// Traffic returns monotonic byte totals used to derive one-second rates in the
// CLI. It is intentionally a snapshot instead of a rate so callers can choose
// their own sampling interval without coupling the data plane to a renderer.
func (s *Client) Traffic() TrafficSnapshot {
	if s == nil {
		return TrafficSnapshot{}
	}
	return TrafficSnapshot{
		GameUploadBytes:   s.traffic.gameUploadBytes.Load(),
		GameDownloadBytes: s.traffic.gameDownloadBytes.Load(),
		L4PUploadBytes:    s.traffic.l4pUploadBytes.Load(),
		L4PDownloadBytes:  s.traffic.l4pDownloadBytes.Load(),
	}
}

// Status returns a point-in-time snapshot of the client state.
func (s *Client) Status() ClientStatus {
	s.candidateMu.RLock()
	activeCand := s.bestCandidate
	cands := make([]*serverCandidate, len(s.candidates))
	copy(cands, s.candidates)
	mode := s.routeMode()
	listenAddr := ""
	enablePunch := false
	if s.cfg != nil {
		listenAddr = s.cfg.ListenAddr
		enablePunch = s.cfg.EnablePunch
	}
	s.candidateMu.RUnlock()

	activeCandStr := ""
	activePath := router.PathNone
	var activeRTT time.Duration
	var activeLossRate float64
	activeOnline := false
	if activeCand != nil {
		activeCandStr = activeCand.addrStr
		activeCand.mu.RLock()
		activeOnline = activeCand.online && s.candidateAllowedValues(activeCand.isLAN, activeCand.pathClass, activeCand.isPunch)
		activeRTT = activeCand.rtt
		activeLossRate = pingLossRate(activeCand.pingSent, activeCand.pingReceived)
		activePath = pathForCandidateValues(activeCand.isLAN, activeCand.pathClass, activeCand.isPunch)
		if activeCand.udpAddr != nil && activeCand.addrStr != activeCand.udpAddr.String() {
			activeCandStr = fmt.Sprintf("%s (%s)", activeCand.addrStr, activeCand.udpAddr.String())
		}
		activeCand.mu.RUnlock()
	}
	if !activeOnline {
		activeCandStr = ""
		activePath = router.PathNone
		activeRTT = 0
		activeLossRate = 0
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
		if c == nil {
			continue
		}
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
			LossRate:      pingLossRate(c.pingSent, c.pingReceived),
			PathType:      pathForCandidateValues(c.isLAN, c.pathClass, c.isPunch),
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
		ActivePath:      activePath,
		ActiveCandidate: activeCandStr,
		ActiveRTT:       activeRTT,
		ActiveLossRate:  activeLossRate,
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
		fmt.Fprintf(&b, "  Active Route     : [%s] -> %s (RTT: %s, Loss: %.1f%%)\n", st.ActivePath, st.ActiveCandidate, rttStr, st.ActiveLossRate*100)
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
		fmt.Fprintf(&b, "      Status: %-7s | RTT: %-7s | Loss: %-6.1f%% | LAN: %-5v | Last Seen: %s\n",
			statusStr, rttStr, c.LossRate*100, c.IsLAN, lastSeenStr)

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
	if s.routeMode() == "relay-only" {
		return
	}
	s.runNATDetection()
}

// runNATDetection coalesces concurrent requests from startup and Probe.  NAT
// probing opens its own socket and can take several seconds; spawning one copy
// per CLI/status probe needlessly consumes descriptors and outbound traffic.
func (s *Client) runNATDetection() *stun.NATMappingInfo {
	if s == nil || !s.natDetecting.CompareAndSwap(false, true) {
		return nil
	}
	defer s.natDetecting.Store(false)
	return s.DetectNAT()
}

func (s *Client) scheduleNATDetection() {
	if s == nil || !s.natDetecting.CompareAndSwap(false, true) {
		return
	}
	if !s.startTask(func() {
		defer s.wg.Done()
		defer s.natDetecting.Store(false)
		_ = s.DetectNAT()
	}) {
		s.natDetecting.Store(false)
	}
}

// DetectNAT performs STUN-based NAT mapping detection and updates the cached NAT info.
func (s *Client) DetectNAT() *stun.NATMappingInfo {
	if s == nil {
		return nil
	}
	s.natMu.Lock()
	defer s.natMu.Unlock()
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

// probeCandidates sends an immediate RTT probe without doing the slower NAT
// detection. The ping graph calls this once per second so its samples remain
// independent from the configured background interval.
func (s *Client) probeCandidates() {
	s.candidateMu.RLock()
	cands := make([]*serverCandidate, len(s.candidates))
	copy(cands, s.candidates)
	s.candidateMu.RUnlock()

	for _, cand := range cands {
		if cand == nil {
			continue
		}
		if s.candidateAllowed(cand) {
			s.sendCandidatePing(cand)
		}
		cand.mu.RLock()
		isPunch := cand.isPunch
		online := cand.online
		hint := cand.pathClass
		cand.mu.RUnlock()
		if !isPunch && !online && (s.routeMode() != "relay-only" || hint == "") {
			s.sendHandshake(cand)
		}
	}

	s.selectBestCandidate()
}

// ProbeCandidates sends immediate authenticated probes to all eligible
// candidates. It is intentionally lightweight for the live ping view.
func (s *Client) ProbeCandidates() {
	if s == nil {
		return
	}
	s.probeCandidates()
}

// Probe actively sends ping probe packets to all candidates and refreshes
// route state and NAT type.
func (s *Client) Probe() {
	if s == nil {
		return
	}
	s.probeCandidates()

	// Trigger async NAT re-detection if unknown.
	if s.routeMode() != "relay-only" && s.natInfo.Load() == nil {
		s.scheduleNATDetection()
	}

	time.Sleep(100 * time.Millisecond)
	s.selectBestCandidate()
}

// SetMode changes the routing mode dynamically ("auto", "direct-only", "relay-only").
func (s *Client) SetMode(mode string) error {
	normalized, err := normalizeRouteMode(mode)
	if err != nil {
		return err
	}
	mode = normalized
	previousMode := s.routeMode()

	s.mode.Store(mode)
	s.candidateMu.Lock()
	if s.cfg != nil {
		s.cfg.Mode = mode
	}
	s.candidateMu.Unlock()

	s.router.SetMode(mode)
	var retire []*serverCandidate
	if mode == "relay-only" {
		s.candidateMu.Lock()
		if s.bestCandidate != nil && !s.candidateAllowed(s.bestCandidate) {
			s.bestCandidate = nil
		}
		s.prevCandidate = nil
		s.dualSendUntil = time.Time{}
		for _, cand := range s.candidates {
			if cand == nil {
				continue
			}
			cand.mu.RLock()
			isPunch := cand.isPunch
			cand.mu.RUnlock()
			if isPunch {
				retire = append(retire, cand)
			}
		}
		s.candidateMu.Unlock()
	}
	for _, cand := range retire {
		s.retirePunchCandidate(cand, "retired after switching to relay-only")
	}
	s.selectBestCandidate()
	if previousMode == "relay-only" && mode != "relay-only" && s.cfg != nil && s.cfg.EnablePunch {
		// Punch candidates are intentionally closed in relay-only mode. Recreate
		// them from the authenticated endpoint cached on an online relay when the
		// operator enables direct routing again.
		s.candidateMu.RLock()
		offers := make([]string, 0, len(s.candidates))
		seen := make(map[string]struct{})
		for _, cand := range s.candidates {
			if cand == nil {
				continue
			}
			cand.mu.RLock()
			isPunch, online, offer := cand.isPunch, cand.online, cand.punchEndpoint
			cand.mu.RUnlock()
			if !isPunch && online && offer != "" {
				if _, exists := seen[offer]; !exists {
					seen[offer] = struct{}{}
					offers = append(offers, offer)
				}
			}
		}
		s.candidateMu.RUnlock()
		for _, offer := range offers {
			s.maybeCreatePunchCandidate(offer)
		}
	}
	log.Printf("[Client] Route mode switched to: %s", mode)
	return nil
}

// GetMode returns the current routing mode.
func (s *Client) GetMode() string {
	return s.routeMode()
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func reflectAddress(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
