package transport

import (
	"fmt"
	"io"
	"net"
	"sync"

	"left4proxy/pkg/protocol"
)

// Transport defines the common packet transmission interface.
type Transport interface {
	Send(pkt *protocol.Packet) error
	Receive() (*protocol.Packet, error)
	Close() error
	RemoteAddr() net.Addr
}

// UDPTransport is a low-level, unauthenticated framing primitive. It is kept
// for protocol tooling and handshake experiments; production Left4Proxy data
// traffic must use the authenticated security.Session path (or its
// SecureUDPTransport adapter) so packets cannot be forged or read.
//
// Deprecated: use SecureUDPTransport for network traffic.
type UDPTransport struct {
	conn       *net.UDPConn
	targetAddr *net.UDPAddr
	mu         sync.Mutex
}

func NewUDPTransport(conn *net.UDPConn, targetAddr *net.UDPAddr) *UDPTransport {
	return &UDPTransport{
		conn:       conn,
		targetAddr: targetAddr,
	}
}

func (u *UDPTransport) Send(pkt *protocol.Packet) error {
	if u == nil || pkt == nil || u.conn == nil {
		return fmt.Errorf("UDP transport is not ready")
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	data := pkt.Marshal()
	var err error
	if u.targetAddr != nil {
		_, err = u.conn.WriteToUDP(data, u.targetAddr)
	} else {
		_, err = u.conn.Write(data)
	}
	return err
}

func (u *UDPTransport) Receive() (*protocol.Packet, error) {
	buf := make([]byte, 65535)
	n, addr, err := u.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	if u.targetAddr == nil {
		u.targetAddr = cloneUDPAddr(addr)
	}
	u.mu.Unlock()
	return protocol.Unmarshal(buf[:n])
}

func (u *UDPTransport) Close() error {
	return u.conn.Close()
}

func (u *UDPTransport) RemoteAddr() net.Addr {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return cloneUDPAddr(u.targetAddr)
}

// TCPTransport is a legacy, unauthenticated framing primitive retained for
// offline tooling compatibility only. It has never been used in Left4Proxy's
// production environment; production paths are UDP-only and never construct
// this type. Do not use it for network traffic.
//
// Deprecated: production Left4Proxy transport is UDP-only.
type TCPTransport struct {
	conn net.Conn
	mu   sync.Mutex
}

func NewTCPTransport(conn net.Conn) *TCPTransport {
	return &TCPTransport{
		conn: conn,
	}
}

func (t *TCPTransport) Send(pkt *protocol.Packet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := pkt.Marshal()
	_, err := t.conn.Write(data)
	return err
}

func (t *TCPTransport) Receive() (*protocol.Packet, error) {
	headerBuf := make([]byte, protocol.HeaderSize)
	_, err := io.ReadFull(t.conn, headerBuf)
	if err != nil {
		return nil, err
	}

	payloadLen := int(headerBuf[26])<<8 | int(headerBuf[27])
	fullBuf := make([]byte, protocol.HeaderSize+payloadLen)
	copy(fullBuf[0:protocol.HeaderSize], headerBuf)

	if payloadLen > 0 {
		_, err := io.ReadFull(t.conn, fullBuf[protocol.HeaderSize:])
		if err != nil {
			return nil, fmt.Errorf("failed to read TCP packet payload: %w", err)
		}
	}

	return protocol.Unmarshal(fullBuf)
}

func (t *TCPTransport) Close() error {
	return t.conn.Close()
}

func (t *TCPTransport) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}
