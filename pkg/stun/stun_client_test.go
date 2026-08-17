package stun

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildResponse assembles a STUN Binding Response with an XOR-MAPPED-ADDRESS
// attribute for the given endpoint, following RFC 5389.
func buildResponse(ip net.IP, port int) []byte {
	buf := make([]byte, 0, 32)
	var typePort, family byte
	if ip4 := ip.To4(); ip4 != nil {
		family = 0x01
		typePort = 8 // 4 (family+port) + 4 (IPv4)
	} else {
		family = 0x02
		typePort = 20 // 4 + 16 (IPv6)
	}
	msg := make([]byte, stunHeaderLen+4+typePort)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(msg[2:4], uint16(4+typePort)) // attr header + value
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	txid := msg[8:20]
	for i := range txid {
		txid[i] = byte(i + 1)
	}

	attr := msg[stunHeaderLen:]
	binary.BigEndian.PutUint16(attr[0:2], attrXORMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], uint16(typePort))
	attr[4] = 0
	attr[5] = family
	binary.BigEndian.PutUint16(attr[6:8], uint16(port)^(stunMagicCookie>>16))

	if family == 0x01 {
		binary.BigEndian.PutUint32(attr[8:12], binary.BigEndian.Uint32(ip.To4())^stunMagicCookie)
	} else {
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:16], txid)
		ip16 := ip.To16()
		for i := 0; i < 16; i++ {
			attr[8+i] = ip16[i] ^ mask[i]
		}
	}
	buf = append(buf, msg...)
	return buf
}

func TestBuildBindingRequest(t *testing.T) {
	req := BuildBindingRequest()
	if len(req) != stunHeaderLen {
		t.Fatalf("expected %d bytes, got %d", stunHeaderLen, len(req))
	}
	if binary.BigEndian.Uint16(req[0:2]) != stunBindingRequest {
		t.Fatalf("bad message type")
	}
	if binary.BigEndian.Uint32(req[4:8]) != stunMagicCookie {
		t.Fatalf("bad magic cookie")
	}
	if !IsStunMessage(req) {
		t.Fatalf("request should look like a STUN message")
	}
	if IsStunResponse(req) {
		t.Fatalf("request must not be classified as a response")
	}
}

func TestValidatorRejectsForgedResponses(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	validator := NewValidator()
	if err := validator.SendBindingRequest(clientConn, serverAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, src, err := serverConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	valid := buildResponse(net.IPv4(203, 0, 113, 7), 42123)
	copy(valid[8:20], buf[8:20])
	// A wrong transaction ID must not be accepted.
	for i := 8; i < 20; i++ {
		valid[i] = 0
	}
	if _, err := validator.Accept(valid, src); err == nil {
		t.Fatal("response with wrong transaction ID accepted")
	}
	copy(valid[8:20], buf[8:20])
	// A valid response from a different source is still rejected.
	wrongPort := serverAddr.Port + 1
	if wrongPort > 65535 {
		wrongPort = serverAddr.Port - 1
	}
	wrongSource := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: wrongPort}
	if _, err := validator.Accept(valid, wrongSource); err == nil {
		t.Fatal("response from wrong source accepted")
	}
	if _, err := validator.Accept(valid, serverAddr); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if _, err := validator.Accept(valid, serverAddr); err == nil {
		t.Fatal("consumed transaction accepted twice")
	}
}

func TestValidatorRejectsExpiredTransaction(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	validator := NewValidator()
	validator.ttl = 10 * time.Millisecond
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	if err := validator.SendBindingRequest(clientConn, serverAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = serverConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp := buildResponse(net.IPv4(203, 0, 113, 8), 40000)
	copy(resp[8:20], buf[8:20])
	time.Sleep(20 * time.Millisecond)
	if _, err := validator.Accept(resp, serverAddr); err == nil {
		t.Fatal("expired transaction accepted")
	}
}

func TestParseBindingResponseIPv4(t *testing.T) {
	resp := buildResponse(net.IPv4(203, 0, 113, 42), 51820)
	addr, err := ParseBindingResponse(resp)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !addr.IP.Equal(net.IPv4(203, 0, 113, 42)) || addr.Port != 51820 {
		t.Fatalf("got %v, want 203.0.113.42:51820", addr)
	}
}

func TestParseBindingResponseIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	resp := buildResponse(ip, 5555)
	addr, err := ParseBindingResponse(resp)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !addr.IP.Equal(ip) || addr.Port != 5555 {
		t.Fatalf("got %v, want %s:5555", addr, ip)
	}
}

func TestParseBindingResponseJunk(t *testing.T) {
	if _, err := ParseBindingResponse([]byte("garbage")); err == nil {
		t.Fatalf("expected error for junk")
	}
	if IsStunResponse([]byte("garbage")) {
		t.Fatalf("junk should not look like STUN")
	}
	// A valid-looking request (not a response) must be rejected.
	if _, err := ParseBindingResponse(BuildBindingRequest()); err == nil {
		t.Fatalf("expected error for a request, not a response")
	}
}

func TestParseBindingResponseRejectsMalformedTrailingAttributes(t *testing.T) {
	resp := buildResponse(net.IPv4(203, 0, 113, 9), 40001)
	// Append an attribute whose declared value is truncated. The mapped address
	// is valid, but the complete message must still be rejected structurally.
	resp = append(resp, 0x00, 0x01, 0x00, 0x02, 0xFF)
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)-stunHeaderLen))
	if _, err := ParseBindingResponse(resp); err == nil {
		t.Fatal("response with malformed trailing attribute was accepted")
	}

	// Duplicate mapped-address attributes are ambiguous and should not be
	// accepted as if the first one were authoritative.
	valid := buildResponse(net.IPv4(203, 0, 113, 10), 40002)
	duplicate := buildResponse(net.IPv4(203, 0, 113, 11), 40003)[stunHeaderLen:]
	valid = append(valid, duplicate...)
	binary.BigEndian.PutUint16(valid[2:4], uint16(len(valid)-stunHeaderLen))
	if _, err := ParseBindingResponse(valid); err == nil {
		t.Fatal("response with duplicate mapped-address attributes was accepted")
	}
}
