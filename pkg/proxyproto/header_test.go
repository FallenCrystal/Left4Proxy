package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestBuildAndParseV2HeaderIPv4(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.45"), Port: 12345}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 27014}
	header, err := BuildV2Header(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header[:12], V2Signature) || header[13] != 0x12 {
		t.Fatalf("unexpected v2 header: %x", header)
	}
	payload := append(header, []byte("INNER_PACKET")...)
	got, offset, err := ParseHeader(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddr(got, src) {
		t.Fatalf("source = %v, want %v", got, src)
	}
	if offset != len(header) || string(payload[offset:]) != "INNER_PACKET" {
		t.Fatalf("offset/payload mismatch: offset=%d payload=%q", offset, payload[offset:])
	}
}

func TestParseV2HeaderIPv6WithTLV(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 12345}
	dst := &net.UDPAddr{IP: net.ParseIP("2001:db8::20"), Port: 27014}
	header, err := BuildV2Header(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	// Append a harmless TLV and update the v2 address block length.
	header = append(header, 0x01, 0x00, 0x01, 0x7f)
	binary.BigEndian.PutUint16(header[14:16], 40)
	payload := append(header, []byte("INNER")...)
	got, offset, err := ParseHeader(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddr(got, src) || offset != len(header) {
		t.Fatalf("got address=%v offset=%d, want address=%v offset=%d", got, offset, src, len(header))
	}
}

func TestParseV1Header(t *testing.T) {
	payload := []byte("PROXY UDP4 203.0.113.88 198.51.100.1 55443 27014\r\nINNER_DATA")
	got, offset, err := ParseHeader(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := &net.UDPAddr{IP: net.ParseIP("203.0.113.88"), Port: 55443}
	if !sameAddr(got, want) || string(payload[offset:]) != "INNER_DATA" {
		t.Fatalf("got address=%v payload=%q", got, payload[offset:])
	}
}

func TestParseNoHeaderAndRejectMalformedHeader(t *testing.T) {
	if addr, offset, err := ParseHeader([]byte("L4DP\x02")); err != nil || addr != nil || offset != 0 {
		t.Fatalf("plain payload parsed as proxy header: addr=%v offset=%d err=%v", addr, offset, err)
	}
	truncated := append(append([]byte(nil), V2Signature...), 0x21, 0x12)
	if _, _, err := ParseHeader(truncated); !errors.Is(err, ErrHeaderTooShort) {
		t.Fatalf("truncated header error = %v, want ErrHeaderTooShort", err)
	}
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}
