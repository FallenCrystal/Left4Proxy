package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var (
	Magic = [4]byte{'L', '4', 'D', 'P'}
)

const (
	Version1 byte = 0x01

	CmdHandshakeReq  byte = 0x01
	CmdHandshakeResp byte = 0x02
	CmdLanProbe      byte = 0x03
	CmdLanAck        byte = 0x04
	CmdStunProbe     byte = 0x05
	CmdStunAck       byte = 0x06
	CmdPing          byte = 0x07
	CmdPong          byte = 0x08
	CmdData          byte = 0x09

	HeaderSize = 28 // 4 + 1 + 1 + 8 + 4 + 8 + 2
)

var (
	ErrInvalidMagic   = errors.New("invalid protocol magic header")
	ErrInvalidVersion = errors.New("unsupported protocol version")
	ErrBufferTooShort = errors.New("packet buffer too short")
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
		Version:   Version1,
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
	copy(buf[0:4], Magic[:])
	buf[4] = p.Version
	buf[5] = p.Cmd
	binary.BigEndian.PutUint64(buf[6:14], p.SessionID)
	binary.BigEndian.PutUint32(buf[14:18], p.Seq)
	binary.BigEndian.PutUint64(buf[18:26], uint64(p.Timestamp))
	binary.BigEndian.PutUint16(buf[26:28], uint16(len(p.Payload)))
	if len(p.Payload) > 0 {
		copy(buf[28:], p.Payload)
	}
	return buf
}

// Unmarshal decodes a byte slice into a Packet.
func Unmarshal(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, ErrBufferTooShort
	}
	if data[0] != Magic[0] || data[1] != Magic[1] || data[2] != Magic[2] || data[3] != Magic[3] {
		return nil, ErrInvalidMagic
	}
	ver := data[4]
	if ver != Version1 {
		return nil, ErrInvalidVersion
	}
	cmd := data[5]
	sessionID := binary.BigEndian.Uint64(data[6:14])
	seq := binary.BigEndian.Uint32(data[14:18])
	ts := int64(binary.BigEndian.Uint64(data[18:26]))
	payloadLen := int(binary.BigEndian.Uint16(data[26:28]))

	if len(data) < HeaderSize+payloadLen {
		return nil, fmt.Errorf("%w: expected payload len %d, got %d", ErrBufferTooShort, payloadLen, len(data)-HeaderSize)
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
	if len(payload) < 4 {
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
