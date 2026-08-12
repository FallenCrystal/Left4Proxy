package server

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
	"left4proxy/pkg/proxyproto"
	"left4proxy/pkg/stun"
	"left4proxy/pkg/transport"
)

type clientSession struct {
	sessionID      uint64
	rawSenderAddr  *net.UDPAddr // Socket return path (frpc or direct UDP client)
	realClientAddr *net.UDPAddr // Extracted real client public IP:Port (from PROXY protocol or direct)
	lastActive     time.Time
	upstream       *net.UDPConn
}

// Server is the Left4Proxy server daemon.
type Server struct {
	cfg               *config.ServerConfig
	udpConn           *net.UDPConn
	tcpListener       net.Listener
	sessions          map[uint64]*clientSession
	pendingProxyAddrs map[string]*net.UDPAddr // Map raw tunnel sender IP:Port -> real client UDPAddr
	proxyAddrMu       sync.RWMutex
	sessionMu         sync.RWMutex
	nextID            uint64
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
		pendingProxyAddrs: make(map[string]*net.UDPAddr),
		ctx:               ctx,
		cancel:            cancel,
	}, nil
}

// Start launches the UDP/TCP server listeners and packet processing routines.
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

	tcpListener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err == nil {
		s.tcpListener = tcpListener
		s.wg.Add(1)
		go s.acceptTCPLoop()
	} else {
		log.Printf("[Server] Warning: TCP listen failed on %s: %v (continuing UDP only)", s.cfg.ListenAddr, err)
	}

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

				s.proxyAddrMu.Lock()
				s.pendingProxyAddrs[rawSenderAddr.String()] = extractedAddr
				s.proxyAddrMu.Unlock()

				realClientAddr = extractedAddr
				packetData = packetData[offset:]
			} else {
				s.proxyAddrMu.RLock()
				if pendingAddr, ok := s.pendingProxyAddrs[rawSenderAddr.String()]; ok {
					realClientAddr = pendingAddr
				}
				s.proxyAddrMu.RUnlock()
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

// handlePacket processes unmarshaled protocol packets.
func (s *Server) handlePacket(pkt *protocol.Packet, rawSenderAddr, realClientAddr *net.UDPAddr) {
	switch pkt.Cmd {
	case protocol.CmdHandshakeReq:
		sid := atomic.AddUint64(&s.nextID, 1)
		_ = s.getOrCreateSession(sid, rawSenderAddr, realClientAddr)

		reflected := stun.ReflectAddress(realClientAddr)
		var respPayload string
		if len(s.cfg.PublicIPs) > 0 {
			respPayload = fmt.Sprintf("%s|%s", reflected, strings.Join(s.cfg.PublicIPs, ","))
		} else {
			respPayload = reflected
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

		log.Printf("[Server] Client Handshake accepted (SessionID: %d, Real Client Endpoint: %s, Socket Sender: %s)",
			sid, realClientAddr.String(), rawSenderAddr.String())

	case protocol.CmdLanProbe:
		respPkt := protocol.NewPacket(protocol.CmdLanAck, pkt.SessionID, pkt.Seq, []byte("LAN_ACK"))
		_, _ = s.udpConn.WriteToUDP(respPkt.Marshal(), rawSenderAddr)

	case protocol.CmdStunProbe:
		respPayload := []byte(stun.ReflectAddress(realClientAddr))
		respPkt := protocol.NewPacket(protocol.CmdStunAck, pkt.SessionID, pkt.Seq, respPayload)
		_, _ = s.udpConn.WriteToUDP(respPkt.Marshal(), rawSenderAddr)

	case protocol.CmdPing:
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
		if !protocol.IsL4D2Packet(pkt.Payload) {
			return
		}

		sess := s.getOrCreateSession(pkt.SessionID, rawSenderAddr, realClientAddr)
		if sess != nil {
			sess.lastActive = time.Now()
			s.forwardToUpstream(sess, pkt.Payload, realClientAddr)
		}
	}
}

// forwardToUpstream transmits L4D2 payload to upstream server target.
func (s *Server) forwardToUpstream(sess *clientSession, payload []byte, realClientAddr *net.UDPAddr) {
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
		go s.readUpstreamLoop(sess)
	}

	_, _ = sess.upstream.Write(payload)
}

// readUpstreamLoop receives response UDP packets from actual L4D2 server and relays back to client via tunnel return path.
func (s *Server) readUpstreamLoop(sess *clientSession) {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = sess.upstream.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := sess.upstream.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// Encapsulate in CmdData Left4Proxy packet and send back to client via rawSenderAddr
		replyPkt := protocol.NewPacket(protocol.CmdData, sess.sessionID, 0, buf[:n])
		_, _ = s.udpConn.WriteToUDP(replyPkt.Marshal(), sess.rawSenderAddr)
	}
}

// getOrCreateSession retrieves or initializes a client session.
func (s *Server) getOrCreateSession(sessionID uint64, rawSenderAddr, realClientAddr *net.UDPAddr) *clientSession {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	sess, exists := s.sessions[sessionID]
	if !exists {
		sess = &clientSession{
			sessionID:      sessionID,
			rawSenderAddr:  rawSenderAddr,
			realClientAddr: realClientAddr,
			lastActive:     time.Now(),
		}
		s.sessions[sessionID] = sess
	} else {
		sess.rawSenderAddr = rawSenderAddr
		if realClientAddr != nil {
			sess.realClientAddr = realClientAddr
		}
	}
	return sess
}

// acceptTCPLoop accepts incoming TCP connection fallback.
func (s *Server) acceptTCPLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleTCPConn(conn)
	}
}

// handleTCPConn handles a single TCP fallback connection.
func (s *Server) handleTCPConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	tr := transport.NewTCPTransport(conn)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := tr.Receive()
		if err != nil {
			return
		}

		clientUDPAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			clientUDPAddr = &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port}
		}

		s.handlePacket(pkt, clientUDPAddr, clientUDPAddr)
	}
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
			s.sessionMu.Lock()
			now := time.Now()
			for sid, sess := range s.sessions {
				if now.Sub(sess.lastActive) > 60*time.Second {
					if sess.upstream != nil {
						_ = sess.upstream.Close()
					}
					if sess.rawSenderAddr != nil {
						s.proxyAddrMu.Lock()
						delete(s.pendingProxyAddrs, sess.rawSenderAddr.String())
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
	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}

	s.sessionMu.Lock()
	for _, sess := range s.sessions {
		if sess.upstream != nil {
			_ = sess.upstream.Close()
		}
	}
	s.sessionMu.Unlock()

	s.wg.Wait()
	log.Printf("[Server] Server stopped successfully")
}
