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
	mu         sync.RWMutex
	addrStr    string
	udpAddr    *net.UDPAddr
	conn       *net.UDPConn
	lastActive time.Time
	rtt        time.Duration
	isLAN      bool
	online     bool
}

// Client is the Left4Proxy client daemon.
type Client struct {
	cfg              *config.ClientConfig
	sessionID        uint64
	seq              uint32
	localConn        *net.UDPConn
	candidates       []*serverCandidate
	bestCandidate    *serverCandidate
	candidateMu      sync.RWMutex
	lastClientAddr   *net.UDPAddr
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
		s.holePuncher = stun.NewHolePuncher(s.sessionID, s.bestCandidate.conn, s.bestCandidate.udpAddr)
		s.holePuncher.StartPunching(3 * time.Second)
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

// sendHandshake transmits a handshake request packet over a candidate's socket.
func (s *Client) sendHandshake(cand *serverCandidate) {
	if cand == nil || cand.conn == nil {
		return
	}
	handshakePkt := protocol.NewPacket(protocol.CmdHandshakeReq, 0, 0, []byte("HANDSHAKE"))
	_, _ = cand.conn.Write(handshakePkt.Marshal())
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
		cand.mu.RUnlock()

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
		// Hysteresis threshold: require 15% RTT improvement to switch away from current candidate (unless switching to LAN)
		if s.bestCandidate != nil {
			s.bestCandidate.mu.RLock()
			currRTT := s.bestCandidate.rtt
			currLAN := s.bestCandidate.isLAN
			s.bestCandidate.mu.RUnlock()

			if !best.isLAN && currLAN {
				// Don't switch away from LAN to WAN
				return
			}

			if !best.isLAN && !currLAN {
				improvement := currRTT - best.rtt
				if improvement < 5*time.Millisecond && improvement < currRTT/7 {
					// Latency improvement too small, avoid flapping
					return
				}
			}
		}

		s.bestCandidate = best
		best.mu.RLock()
		bestRTT := best.rtt
		bestLAN := best.isLAN
		best.mu.RUnlock()

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

		s.lastClientAddr = clientAddr
		payload := buf[:n]

		if !protocol.IsL4D2Packet(payload) {
			continue
		}

		seq := atomic.AddUint32(&s.seq, 1)
		pkt := protocol.NewPacket(protocol.CmdData, s.sessionID, seq, payload)

		s.candidateMu.RLock()
		activeCand := s.bestCandidate
		s.candidateMu.RUnlock()

		if activeCand != nil {
			_, _ = activeCand.conn.Write(pkt.Marshal())
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
		n, err := cand.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.ctx.Done():
				return
			default:
				return
			}
		}

		pkt, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			continue
		}

		cand.mu.Lock()
		cand.lastActive = time.Now()
		cand.online = true
		cand.mu.Unlock()

		s.handleServerPacket(cand, pkt)
	}
}

// handleServerPacket handles all incoming server packets from a candidate socket.
func (s *Client) handleServerPacket(cand *serverCandidate, pkt *protocol.Packet) {
	now := time.Now().UnixNano()
	handshakeRTT := time.Duration(now - pkt.Timestamp)

	cand.mu.Lock()
	cand.lastActive = time.Now()
	cand.online = true
	if handshakeRTT > 0 && handshakeRTT < 10*time.Second {
		cand.rtt = handshakeRTT
	}
	candRTT := cand.rtt
	isLAN := cand.isLAN
	cand.mu.Unlock()

	switch pkt.Cmd {
	case protocol.CmdHandshakeResp:
		if s.sessionID == 0 {
			s.sessionID = pkt.SessionID
		}

		payloadStr := string(pkt.Payload)
		parts := strings.Split(payloadStr, "|")
		reflected := parts[0]

		log.Printf("[Client] Connected & Handshake Verified -> Candidate [%s] (IP: %s, RTT: %v) | SessionID: %d | Apparent Endpoint: %s",
			cand.addrStr, cand.udpAddr.String(), candRTT, pkt.SessionID, reflected)

		if isLAN {
			s.router.UpdateMetrics(router.PathLAN, candRTT, 0.0)
		} else {
			s.router.UpdateMetrics(router.PathDirect, candRTT, 0.0)
		}

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
		s.selectBestCandidate()

	case protocol.CmdPong:
		if isLAN {
			s.router.UpdateMetrics(router.PathLAN, candRTT, 0.0)
		} else {
			s.router.UpdateMetrics(router.PathDirect, candRTT, 0.0)
		}

		s.selectBestCandidate()

	case protocol.CmdLanAck:
		cand.mu.Lock()
		cand.rtt = 1 * time.Millisecond
		cand.isLAN = true
		cand.mu.Unlock()
		s.router.UpdateMetrics(router.PathLAN, 1*time.Millisecond, 0.0)
		s.selectBestCandidate()

	case protocol.CmdStunAck:
		s.router.UpdateMetrics(router.PathDirect, 20*time.Millisecond, 0.0)
		s.selectBestCandidate()

	case protocol.CmdData:
		if s.lastClientAddr != nil && len(pkt.Payload) > 0 {
			_, _ = s.localConn.WriteToUDP(pkt.Payload, s.lastClientAddr)
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
			pingPkt := protocol.NewPacket(protocol.CmdPing, s.sessionID, seq, []byte("PING"))
			marshaledPing := pingPkt.Marshal()

			s.candidateMu.RLock()
			cands := make([]*serverCandidate, len(s.candidates))
			copy(cands, s.candidates)
			s.candidateMu.RUnlock()

			anyOnline := false
			now := time.Now()

			for _, cand := range cands {
				cand.mu.RLock()
				lastActive := cand.lastActive
				cand.mu.RUnlock()

				if !lastActive.IsZero() && now.Sub(lastActive) <= 15*time.Second {
					cand.mu.Lock()
					cand.online = true
					cand.mu.Unlock()
					anyOnline = true
					_, _ = cand.conn.Write(marshaledPing)
				} else {
					cand.mu.Lock()
					cand.online = false
					cand.mu.Unlock()
					s.sendHandshake(cand)
				}
			}

			s.selectBestCandidate()

			if !anyOnline {
				s.router.SetInactive(router.PathLAN)
				s.router.SetInactive(router.PathDirect)

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
