package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

var (
	// PROXY Protocol v2 Signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
	V2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

var (
	ErrInvalidAddress = errors.New("invalid IP address for PROXY protocol v2 header")
	ErrHeaderTooShort = errors.New("PROXY protocol header buffer too short")
	ErrInvalidHeader  = errors.New("invalid PROXY protocol header format")
)

// BuildV2Header constructs a PROXY protocol v2 binary header for UDP/DGRAM connections.
func BuildV2Header(srcAddr, dstAddr *net.UDPAddr) ([]byte, error) {
	if srcAddr == nil || dstAddr == nil {
		return nil, ErrInvalidAddress
	}

	srcIP4 := srcAddr.IP.To4()
	dstIP4 := dstAddr.IP.To4()

	if srcIP4 != nil && dstIP4 != nil {
		// IPv4 UDP (AF_INET + DGRAM = 0x12)
		header := make([]byte, 16+12)
		copy(header[0:12], V2Signature)
		header[12] = 0x21 // Version 2, Command PROXY
		header[13] = 0x12 // AF_INET, UDP/DGRAM
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
		// IPv6 UDP (AF_INET6 + DGRAM = 0x22)
		header := make([]byte, 16+36)
		copy(header[0:12], V2Signature)
		header[12] = 0x21 // Version 2, Command PROXY
		header[13] = 0x22 // AF_INET6, UDP/DGRAM
		binary.BigEndian.PutUint16(header[14:16], 36)

		copy(header[16:32], srcIP6)
		copy(header[32:48], dstIP6)
		binary.BigEndian.PutUint16(header[48:50], uint16(srcAddr.Port))
		binary.BigEndian.PutUint16(header[50:52], uint16(dstAddr.Port))
		return header, nil
	}

	return nil, ErrInvalidAddress
}

// ParseHeader parses incoming PROXY protocol v1 or v2 headers sent by frpc/frps/HAProxy/Nginx.
func ParseHeader(data []byte) (realSrc *net.UDPAddr, payloadOffset int, err error) {
	if len(data) < 12 {
		return nil, 0, ErrHeaderTooShort
	}

	// 1. Check PROXY Protocol v2 Binary Header
	if bytes.HasPrefix(data, V2Signature) {
		if len(data) < 16 {
			return nil, 0, ErrHeaderTooShort
		}
		addrLen := int(binary.BigEndian.Uint16(data[14:16]))
		totalHdrLen := 16 + addrLen
		if len(data) < totalHdrLen {
			return nil, 0, ErrHeaderTooShort
		}

		family := data[13]
		switch family & 0xF0 {
		case 0x10: // IPv4 (0x11 TCP, 0x12 UDP)
			if addrLen < 12 {
				return nil, 0, ErrInvalidHeader
			}
			srcIP := net.IPv4(data[16], data[17], data[18], data[19])
			srcPort := int(binary.BigEndian.Uint16(data[24:26]))
			return &net.UDPAddr{IP: srcIP, Port: srcPort}, totalHdrLen, nil

		case 0x20: // IPv6 (0x21 TCP, 0x22 UDP)
			if addrLen < 36 {
				return nil, 0, ErrInvalidHeader
			}
			srcIP := make(net.IP, 16)
			copy(srcIP, data[16:32])
			srcPort := int(binary.BigEndian.Uint16(data[48:50]))
			return &net.UDPAddr{IP: srcIP, Port: srcPort}, totalHdrLen, nil
		default:
			return nil, totalHdrLen, nil
		}
	}

	// 2. Check PROXY Protocol v1 Text Header (PROXY TCP4/TCP6/UNKNOWN ...)
	if bytes.HasPrefix(data, []byte("PROXY ")) {
		crlfIdx := bytes.Index(data, []byte("\r\n"))
		if crlfIdx == -1 {
			return nil, 0, ErrHeaderTooShort
		}
		line := strings.TrimSpace(string(data[6:crlfIdx]))
		parts := strings.Fields(line)
		if len(parts) >= 4 && (parts[0] == "TCP4" || parts[0] == "TCP6" || parts[0] == "UDP4" || parts[0] == "UDP6") {
			srcIP := net.ParseIP(parts[1])
			srcPort, err := strconv.Atoi(parts[3])
			if err == nil && srcIP != nil {
				return &net.UDPAddr{IP: srcIP, Port: srcPort}, crlfIdx + 2, nil
			}
		}
		return nil, crlfIdx + 2, nil
	}

	return nil, 0, nil
}
