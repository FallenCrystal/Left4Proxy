package stun

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
)

// STUN (RFC 5389) message constants used by the hole-punching path. The server
// and the client's punch socket each send a Binding Request to a public STUN
// server to learn their own NAT-mapped public endpoint; the Binding Response's
// XOR-MAPPED-ADDRESS attribute carries it.
const (
	stunMagicCookie = 0x2112A442

	stunBindingRequest  = 0x0001
	stunBindingResponse = 0x0101

	attrXORMappedAddress = 0x0020

	stunHeaderLen = 20
)

// DefaultStunServers provides a robust list of reliable public STUN servers for fallback and racing.
var DefaultStunServers = []string{
	"stun.cloudflare.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.syncthing.net:3478",
	"stun.miwifi.com:3478",
}

// ResolveStunServers resolves a slice of "host:port" STUN server strings into UDP addresses,
// skipping unresolvable ones.
func ResolveStunServers(servers []string) []*net.UDPAddr {
	var addrs []*net.UDPAddr
	seen := make(map[string]bool)
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", s)
		if err == nil && addr != nil {
			k := addr.String()
			if !seen[k] {
				seen[k] = true
				addrs = append(addrs, addr)
			}
		}
	}
	return addrs
}

// SendMultiBindingRequests transmits STUN Binding Requests to multiple STUN server addresses in parallel
// from the provided UDP socket to race them for the fastest reflection.
func SendMultiBindingRequests(conn *net.UDPConn, addrs []*net.UDPAddr) {
	if conn == nil || len(addrs) == 0 {
		return
	}
	req := BuildBindingRequest()
	for _, addr := range addrs {
		if addr != nil {
			_, _ = conn.WriteToUDP(req, addr)
		}
	}
}


// BuildBindingRequest builds a 20-byte STUN Binding Request with a random
// transaction ID. It carries no attributes.
func BuildBindingRequest() []byte {
	buf := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	for i := 8; i < 20; i++ {
		buf[i] = byte(rand.Uint32())
	}
	return buf
}

// IsStunResponse reports whether data looks like a STUN message (magic cookie
// at offset 4). The server and client read loops use this to separate STUN
// replies from Left4Proxy packets arriving on the same UDP socket.
func IsStunResponse(data []byte) bool {
	return len(data) >= stunHeaderLen && binary.BigEndian.Uint32(data[4:8]) == stunMagicCookie
}

// ParseBindingResponse extracts the XOR-MAPPED-ADDRESS from a successful STUN
// Binding Response and returns the reflected public endpoint (RFC 5389 §15.2).
func ParseBindingResponse(data []byte) (*net.UDPAddr, error) {
	if len(data) < stunHeaderLen {
		return nil, errors.New("stun: message too short")
	}
	if !IsStunResponse(data) {
		return nil, errors.New("stun: bad magic cookie")
	}
	if msgType := binary.BigEndian.Uint16(data[0:2]); msgType != stunBindingResponse {
		return nil, errors.New("stun: not a binding response")
	}
	txid := data[8:20]

	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	end := stunHeaderLen + msgLen
	if end > len(data) {
		end = len(data)
	}

	// Walk TLV attributes (values padded to a 4-byte boundary).
	offset := stunHeaderLen
	for offset+4 <= end {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		val := offset + 4
		if val+attrLen > end {
			return nil, errors.New("stun: attribute overruns message")
		}
		if attrType == attrXORMappedAddress {
			return parseXORMappedAddress(data[val:val+attrLen], txid)
		}
		padded := attrLen + (4 - attrLen%4) % 4
		offset = val + padded
	}
	return nil, errors.New("stun: no XOR-MAPPED-ADDRESS attribute")
}

// parseXORMappedAddress decodes the XOR-MAPPED-ADDRESS attribute value.
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|0 0 0 0 0 0 0 0|    Family     |         X-Port                |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                X-Address (Variable)                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func parseXORMappedAddress(v []byte, txid []byte) (*net.UDPAddr, error) {
	if len(v) < 4 {
		return nil, errors.New("stun: short XOR-MAPPED-ADDRESS")
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4]) ^ (stunMagicCookie >> 16)

	switch family {
	case 0x01: // IPv4
		if len(v) < 8 {
			return nil, errors.New("stun: short IPv4 XOR-MAPPED-ADDRESS")
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(v[4:8])^stunMagicCookie)
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	case 0x02: // IPv6
		if len(v) < 20 {
			return nil, errors.New("stun: short IPv6 XOR-MAPPED-ADDRESS")
		}
		// X-Address = address XOR (magic cookie || transaction ID).
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:16], txid)
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			ip[i] = v[4+i] ^ mask[i]
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	default:
		return nil, errors.New("stun: unsupported address family")
	}
}
