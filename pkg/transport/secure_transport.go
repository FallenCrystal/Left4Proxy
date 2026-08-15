package transport

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"left4proxy/pkg/protocol"
	"left4proxy/pkg/security"
)

// SecureUDPTransport is an authenticated packet transport.  It is the
// transport-package counterpart of the client/server send paths: every
// non-handshake packet is assigned a fresh sequence and sealed with the
// session's AES-GCM key before it reaches the socket, and every received frame
// must pass AEAD and replay validation before being returned to the caller.
type SecureUDPTransport struct {
	conn          *net.UDPConn
	targetAddr    *net.UDPAddr
	session       *security.Session
	sendDirection security.Direction
	recvDirection security.Direction
	mu            sync.RWMutex
}

// NewSecureUDPTransport creates a secure UDP transport.  targetAddr may be
// nil for a connected UDP socket; for an unconnected socket it must be set
// before Send is called (or supplied by the first received datagram).
func NewSecureUDPTransport(conn *net.UDPConn, targetAddr *net.UDPAddr, session *security.Session, sendDirection, recvDirection security.Direction) (*SecureUDPTransport, error) {
	if conn == nil {
		return nil, errors.New("secure UDP transport: connection is nil")
	}
	if session == nil || session.IsClosed() {
		return nil, errors.New("secure UDP transport: session is nil or closed")
	}
	if !validDirection(sendDirection) || !validDirection(recvDirection) {
		return nil, errors.New("secure UDP transport: invalid packet direction")
	}
	return &SecureUDPTransport{
		conn:          conn,
		targetAddr:    cloneUDPAddr(targetAddr),
		session:       session,
		sendDirection: sendDirection,
		recvDirection: recvDirection,
	}, nil
}

func (u *SecureUDPTransport) Send(pkt *protocol.Packet) error {
	if u == nil || pkt == nil {
		return errors.New("secure UDP transport: packet is nil")
	}
	u.mu.RLock()
	session := u.session
	dst := cloneUDPAddr(u.targetAddr)
	direction := u.sendDirection
	conn := u.conn
	u.mu.RUnlock()
	if session == nil || conn == nil {
		return errors.New("secure UDP transport: transport is closed")
	}
	secured := *pkt
	if secured.SessionID == 0 {
		secured.SessionID = session.ID
	}
	if secured.SessionID != session.ID {
		return security.ErrSessionMismatch
	}
	if secured.Seq == 0 {
		seq, err := session.NextSeq()
		if err != nil {
			return err
		}
		secured.Seq = seq
	}
	data, err := session.Seal(&secured, direction)
	if err != nil {
		return err
	}
	if dst != nil {
		_, err = conn.WriteToUDP(data, dst)
		return err
	}
	_, err = conn.Write(data)
	return err
}

func (u *SecureUDPTransport) Receive() (*protocol.Packet, error) {
	if u == nil {
		return nil, errors.New("secure UDP transport is nil")
	}
	u.mu.RLock()
	conn := u.conn
	session := u.session
	direction := u.recvDirection
	target := cloneUDPAddr(u.targetAddr)
	u.mu.RUnlock()
	if conn == nil || session == nil {
		return nil, errors.New("secure UDP transport is closed")
	}
	buf := make([]byte, 65535)
	n, source, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	if target != nil && !sameUDPAddr(source, target) {
		return nil, fmt.Errorf("secure UDP transport: unexpected packet source %s", source)
	}
	u.mu.Lock()
	if u.targetAddr == nil {
		u.targetAddr = cloneUDPAddr(source)
	}
	u.mu.Unlock()
	return session.Open(buf[:n], direction)
}

func (u *SecureUDPTransport) Close() error {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	conn := u.conn
	u.conn = nil
	session := u.session
	u.session = nil
	u.mu.Unlock()
	if session != nil {
		session.Close()
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (u *SecureUDPTransport) RemoteAddr() net.Addr {
	if u == nil {
		return nil
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return cloneUDPAddr(u.targetAddr)
}

func validDirection(direction security.Direction) bool {
	return direction == security.ClientToServer || direction == security.ServerToClient
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
