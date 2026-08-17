package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var (
	wireMagic = [...]byte{'L', '4', 'D', 'P'}
	// Magic is retained as a compatibility value for callers constructing test
	// fixtures. Runtime framing uses wireMagic so an external assignment cannot
	// change the protocol recognizer while the process is running.
	Magic = wireMagic
)

const (
	// Version1 is kept as a named value so callers can produce a useful
	// migration error, but it is no longer accepted by Unmarshal.  All network
	// traffic must use the authenticated Version2 framing.
	Version1 byte = 0x01
	Version2 byte = 0x02

	CmdHandshakeReq  byte = 0x01
	CmdHandshakeResp byte = 0x02
	CmdStunProbe     byte = 0x05
	CmdStunAck       byte = 0x06
	CmdPing          byte = 0x07
	CmdPong          byte = 0x08
	CmdData          byte = 0x09
	CmdPunchOffer    byte = 0x0A // server→client: server's public punch endpoint (ip:port)
	CmdPunchInit     byte = 0x0B // client→server (over relay): client's direct-socket public endpoint
	CmdPunchAck      byte = 0x0C // server→client: PunchInit acknowledged

	HeaderSize = 28 // 4 + 1 + 1 + 8 + 4 + 8 + 2

	// IPv4/IPv6 UDP leaves at most 65507 bytes for one datagram payload. Keep
	// the protocol parser and AEAD sender within that bound instead of allowing
	// a syntactically valid uint16 payload length that can never traverse UDP.
	MaxUDPPayloadSize    = 65507
	MaxPacketPayloadSize = MaxUDPPayloadSize - HeaderSize
)

var (
	ErrInvalidMagic   = errors.New("invalid protocol magic header")
	ErrInvalidVersion = errors.New("unsupported protocol version")
	ErrBufferTooShort = errors.New("packet buffer too short")
	ErrPacketTooLarge = errors.New("packet payload too large for UDP")
	ErrNotL4D2Packet  = errors.New("not a valid L4D2/Source Engine packet")
)

// Packet represents a Left4Proxy protocol frame.
type Packet struct {
	Version   byte
	Cmd       byte
	SessionID uint64
	Seq       uint32
	Timestamp int64
	Payload   []byte
}

// NewPacket creates a new packet with current timestamp.
func NewPacket(cmd byte, sessionID uint64, seq uint32, payload []byte) *Packet {
	return &Packet{
		Version:   Version2,
		Cmd:       cmd,
		SessionID: sessionID,
		Seq:       seq,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}
}

// Marshal encodes the Packet into a byte slice.
func (p *Packet) Marshal() []byte {
	buf := make([]byte, HeaderSize+len(p.Payload))
	header := p.MarshalHeader(len(p.Payload))
	copy(buf[:HeaderSize], header)
	if len(p.Payload) > 0 {
		copy(buf[HeaderSize:], p.Payload)
	}
	return buf
}

// MarshalHeader returns the wire header for p with a caller-supplied payload
// length.  Secure transports use this header as AEAD associated data before
// the encrypted payload has been assembled.
func (p *Packet) MarshalHeader(payloadLen int) []byte {
	if payloadLen < 0 {
		payloadLen = 0
	}
	if payloadLen > int(^uint16(0)) {
		payloadLen = int(^uint16(0))
	}
	buf := make([]byte, HeaderSize)
	copy(buf[0:4], wireMagic[:])
	buf[4] = p.Version
	buf[5] = p.Cmd
	binary.BigEndian.PutUint64(buf[6:14], p.SessionID)
	binary.BigEndian.PutUint32(buf[14:18], p.Seq)
	binary.BigEndian.PutUint64(buf[18:26], uint64(p.Timestamp))
	binary.BigEndian.PutUint16(buf[26:28], uint16(payloadLen))
	return buf
}

// Unmarshal decodes a byte slice into a Packet.
func Unmarshal(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, ErrBufferTooShort
	}
	if data[0] != wireMagic[0] || data[1] != wireMagic[1] || data[2] != wireMagic[2] || data[3] != wireMagic[3] {
		return nil, ErrInvalidMagic
	}
	ver := data[4]
	if ver != Version2 {
		return nil, ErrInvalidVersion
	}
	cmd := data[5]
	sessionID := binary.BigEndian.Uint64(data[6:14])
	seq := binary.BigEndian.Uint32(data[14:18])
	ts := int64(binary.BigEndian.Uint64(data[18:26]))
	payloadLen := int(binary.BigEndian.Uint16(data[26:28]))
	if payloadLen > MaxPacketPayloadSize {
		return nil, fmt.Errorf("%w: declared payload len %d", ErrPacketTooLarge, payloadLen)
	}

	if len(data) < HeaderSize+payloadLen {
		return nil, fmt.Errorf("%w: expected payload len %d, got %d", ErrBufferTooShort, payloadLen, len(data)-HeaderSize)
	}
	if len(data) != HeaderSize+payloadLen {
		return nil, fmt.Errorf("unexpected trailing bytes: header declares %d payload bytes, got %d", payloadLen, len(data)-HeaderSize)
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		copy(payload, data[HeaderSize:HeaderSize+payloadLen])
	}

	return &Packet{
		Version:   ver,
		Cmd:       cmd,
		SessionID: sessionID,
		Seq:       seq,
		Timestamp: ts,
		Payload:   payload,
	}, nil
}

// IsL4D2Packet inspects the payload to verify whether it matches Source Engine / L4D2 UDP packet signature.
func IsL4D2Packet(payload []byte) bool {
	if len(payload) < 4 || len(payload) > MaxUDPPayloadSize {
		return false
	}
	// Source Engine OOB (Out of Band) queries start with 0xFF 0xFF 0xFF 0xFF
	if payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF {
		return true
	}
	// Source Engine connected netchannel UDP packet headers (sequence number <= 0x7FFFFFFF)
	// or in-game packet data stream
	return len(payload) >= 8
}
