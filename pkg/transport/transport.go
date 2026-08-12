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

// UDPTransport encapsulates UDP packet read/write.
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
	if u.targetAddr == nil {
		u.targetAddr = addr
	}
	return protocol.Unmarshal(buf[:n])
}

func (u *UDPTransport) Close() error {
	return u.conn.Close()
}

func (u *UDPTransport) RemoteAddr() net.Addr {
	return u.targetAddr
}

// TCPTransport encapsulates TCP packet stream framing read/write.
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
