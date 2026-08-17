// Package proxyproto parses the optional PROXY Protocol envelope used by
// trusted UDP relays such as frp. The envelope is removed before Left4Proxy
// framing and authentication are processed.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	// V2Signature is the fixed 12-byte PROXY Protocol v2 marker.
	V2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	v1Prefix    = []byte("PROXY ")
)

var (
	ErrInvalidAddress = errors.New("invalid PROXY protocol address")
	ErrHeaderTooShort = errors.New("PROXY protocol header buffer too short")
	ErrInvalidHeader  = errors.New("invalid PROXY protocol header")
)

// BuildV2Header constructs a PROXY Protocol v2 UDP/DGRAM header. It is kept
// here for fixtures and relay integration tests; production only parses it.
func BuildV2Header(srcAddr, dstAddr *net.UDPAddr) ([]byte, error) {
	if srcAddr == nil || dstAddr == nil || srcAddr.Port < 1 || dstAddr.Port < 1 {
		return nil, ErrInvalidAddress
	}

	srcIP4 := srcAddr.IP.To4()
	dstIP4 := dstAddr.IP.To4()
	if srcIP4 != nil && dstIP4 != nil {
		header := make([]byte, 16+12)
		copy(header[:12], V2Signature)
		header[12] = 0x21 // Version 2, command PROXY.
		header[13] = 0x12 // AF_INET, UDP/DGRAM.
		binary.BigEndian.PutUint16(header[14:16], 12)
		copy(header[16:20], srcIP4)
		copy(header[20:24], dstIP4)
		binary.BigEndian.PutUint16(header[24:26], uint16(srcAddr.Port))
		binary.BigEndian.PutUint16(header[26:28], uint16(dstAddr.Port))
		return header, nil
	}

	srcIP6 := srcAddr.IP.To16()
	dstIP6 := dstAddr.IP.To16()
	if srcIP6 != nil && dstIP6 != nil {
		header := make([]byte, 16+36)
		copy(header[:12], V2Signature)
		header[12] = 0x21 // Version 2, command PROXY.
		header[13] = 0x22 // AF_INET6, UDP/DGRAM.
		binary.BigEndian.PutUint16(header[14:16], 36)
		copy(header[16:32], srcIP6)
		copy(header[32:48], dstIP6)
		binary.BigEndian.PutUint16(header[48:50], uint16(srcAddr.Port))
		binary.BigEndian.PutUint16(header[50:52], uint16(dstAddr.Port))
		return header, nil
	}

	return nil, ErrInvalidAddress
}

// ParseHeader parses an optional PROXY Protocol v1/v2 envelope. A nil address
// and offset zero means no envelope was present. A non-zero offset with a nil
// address is a valid LOCAL/UNKNOWN envelope whose inner payload still must be
// handled using the UDP socket source address.
func ParseHeader(data []byte) (realSrc *net.UDPAddr, payloadOffset int, err error) {
	if bytes.HasPrefix(data, V2Signature) {
		return parseV2(data)
	}
	if bytes.HasPrefix(data, v1Prefix) {
		return parseV1(data)
	}
	return nil, 0, nil
}

// IsHeader reports whether a datagram begins with a complete PROXY v1/v2
// envelope marker. It intentionally does not validate the rest of the header;
// callers use it to report a clear rejection reason before ParseHeader does the
// full validation.
func IsHeader(data []byte) bool {
	return bytes.HasPrefix(data, V2Signature) || bytes.HasPrefix(data, v1Prefix)
}

func parseV2(data []byte) (*net.UDPAddr, int, error) {
	if len(data) < 16 {
		return nil, 0, ErrHeaderTooShort
	}
	verCmd := data[12]
	if verCmd>>4 != 0x2 {
		return nil, 0, ErrInvalidHeader
	}
	command := verCmd & 0x0F
	if command != 0x0 && command != 0x1 { // LOCAL or PROXY
		return nil, 0, ErrInvalidHeader
	}
	addrLen := int(binary.BigEndian.Uint16(data[14:16]))
	totalLen := 16 + addrLen
	if len(data) < totalLen {
		return nil, 0, ErrHeaderTooShort
	}
	if command == 0x0 { // LOCAL deliberately carries no usable peer address.
		return nil, totalLen, nil
	}

	family := data[13] >> 4
	switch family {
	case 0x0: // UNSPEC
		return nil, totalLen, nil
	case 0x1: // AF_INET
		if addrLen < 12 {
			return nil, 0, ErrInvalidHeader
		}
		addr := &net.UDPAddr{
			IP:   net.IPv4(data[16], data[17], data[18], data[19]),
			Port: int(binary.BigEndian.Uint16(data[24:26])),
		}
		if !validAddress(addr) {
			return nil, 0, ErrInvalidAddress
		}
		return addr, totalLen, nil
	case 0x2: // AF_INET6
		if addrLen < 36 {
			return nil, 0, ErrInvalidHeader
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, data[16:32])
		addr := &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(data[48:50]))}
		if !validAddress(addr) {
			return nil, 0, ErrInvalidAddress
		}
		return addr, totalLen, nil
	default:
		return nil, 0, ErrInvalidHeader
	}
}

func parseV1(data []byte) (*net.UDPAddr, int, error) {
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 {
		return nil, 0, ErrHeaderTooShort
	}
	fields := strings.Fields(string(data[len(v1Prefix):lineEnd]))
	if len(fields) == 1 && fields[0] == "UNKNOWN" {
		return nil, lineEnd + 2, nil
	}
	if len(fields) != 5 {
		return nil, 0, ErrInvalidHeader
	}
	if fields[0] != "TCP4" && fields[0] != "TCP6" && fields[0] != "UDP4" && fields[0] != "UDP6" {
		return nil, 0, ErrInvalidHeader
	}
	ip := net.ParseIP(fields[1])
	port, portErr := strconv.Atoi(fields[3])
	if portErr != nil || ip == nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrInvalidAddress, portErr)
	}
	if strings.HasSuffix(fields[0], "4") && ip.To4() == nil {
		return nil, 0, ErrInvalidAddress
	}
	if strings.HasSuffix(fields[0], "6") && (ip.To4() != nil || ip.To16() == nil) {
		return nil, 0, ErrInvalidAddress
	}
	addr := &net.UDPAddr{IP: ip, Port: port}
	if !validAddress(addr) {
		return nil, 0, ErrInvalidAddress
	}
	return addr, lineEnd + 2, nil
}

func validAddress(addr *net.UDPAddr) bool {
	return addr != nil && addr.IP != nil && !addr.IP.IsUnspecified() && addr.Port > 0 && addr.Port <= 65535
}
