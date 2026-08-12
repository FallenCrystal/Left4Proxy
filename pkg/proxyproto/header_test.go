package proxyproto

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildV2HeaderIPv4(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321}
	dst := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 27015}

	hdr, err := BuildV2Header(src, dst)
	if err != nil {
		t.Fatalf("BuildV2Header failed: %v", err)
	}

	if len(hdr) != 28 {
		t.Fatalf("expected header length 28, got %d", len(hdr))
	}

	if !bytes.Equal(hdr[0:12], V2Signature) {
		t.Errorf("signature mismatch")
	}

	if hdr[12] != 0x21 {
		t.Errorf("version/cmd byte expected 0x21, got 0x%x", hdr[12])
	}
	if hdr[13] != 0x12 {
		t.Errorf("family/proto byte expected 0x12, got 0x%x", hdr[13])
	}

	addrLen := binary.BigEndian.Uint16(hdr[14:16])
	if addrLen != 12 {
		t.Errorf("address length expected 12, got %d", addrLen)
	}

	srcPort := binary.BigEndian.Uint16(hdr[24:26])
	dstPort := binary.BigEndian.Uint16(hdr[26:28])

	if srcPort != 54321 || dstPort != 27015 {
		t.Errorf("ports mismatch: src %d, dst %d", srcPort, dstPort)
	}
}

func TestParseHeaderV2(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.45"), Port: 12345}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 27014}

	hdr, err := BuildV2Header(src, dst)
	if err != nil {
		t.Fatalf("failed to build v2 header: %v", err)
	}

	payload := append(hdr, []byte("INNER_PACKET")...)
	realAddr, offset, err := ParseHeader(payload)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}

	if realAddr == nil {
		t.Fatalf("expected realAddr, got nil")
	}
	if realAddr.IP.String() != "203.0.113.45" || realAddr.Port != 12345 {
		t.Errorf("extracted address mismatch: got %s", realAddr.String())
	}
	if offset != len(hdr) {
		t.Errorf("expected offset %d, got %d", len(hdr), offset)
	}
	if string(payload[offset:]) != "INNER_PACKET" {
		t.Errorf("inner payload mismatch")
	}
}

func TestParseHeaderV1(t *testing.T) {
	v1Header := []byte("PROXY TCP4 203.0.113.88 198.51.100.1 55443 27014\r\nINNER_DATA")

	realAddr, offset, err := ParseHeader(v1Header)
	if err != nil {
		t.Fatalf("ParseHeader v1 failed: %v", err)
	}

	if realAddr == nil {
		t.Fatalf("expected realAddr, got nil")
	}
	if realAddr.IP.String() != "203.0.113.88" || realAddr.Port != 55443 {
		t.Errorf("extracted v1 address mismatch: got %s", realAddr.String())
	}
	if string(v1Header[offset:]) != "INNER_DATA" {
		t.Errorf("v1 inner payload mismatch")
	}
}
