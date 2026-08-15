package protocol

import (
	"bytes"
	"testing"
)

func TestPacketMarshalUnmarshal(t *testing.T) {
	payload := []byte("hello l4d2 proxy")
	p1 := NewPacket(CmdData, 123456789, 42, payload)

	data := p1.Marshal()
	if len(data) != HeaderSize+len(payload) {
		t.Fatalf("expected marshaled size %d, got %d", HeaderSize+len(payload), len(data))
	}

	p2, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if p2.Cmd != CmdData {
		t.Errorf("expected cmd %d, got %d", CmdData, p2.Cmd)
	}
	if p2.SessionID != 123456789 {
		t.Errorf("expected session ID 123456789, got %d", p2.SessionID)
	}
	if p2.Seq != 42 {
		t.Errorf("expected seq 42, got %d", p2.Seq)
	}
	if !bytes.Equal(p2.Payload, payload) {
		t.Errorf("payload mismatch: expected %s, got %s", payload, p2.Payload)
	}
}

func TestIsL4D2Packet(t *testing.T) {
	// Source Engine OOB Packet (e.g. A2S_INFO query)
	oob := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'T', 'S', 'o', 'u', 'r', 'c', 'e'}
	if !IsL4D2Packet(oob) {
		t.Errorf("expected true for OOB packet")
	}

	// Normal L4D2 game netchannel packet (8+ bytes)
	netPacket := []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10}
	if !IsL4D2Packet(netPacket) {
		t.Errorf("expected true for netchannel packet")
	}

	// Invalid short random packet
	invalid := []byte{0x12, 0x34}
	if IsL4D2Packet(invalid) {
		t.Errorf("expected false for 2-byte random packet")
	}
}

func TestUnmarshalInvalidMagic(t *testing.T) {
	badData := make([]byte, HeaderSize)
	copy(badData[0:4], []byte("XXXX"))
	_, err := Unmarshal(badData)
	if err != ErrInvalidMagic {
		t.Errorf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestUnmarshalRejectsLegacyAndTrailingBytes(t *testing.T) {
	pkt := NewPacket(CmdPing, 1, 1, []byte("x"))
	wire := pkt.Marshal()
	wire[4] = Version1
	if _, err := Unmarshal(wire); err != ErrInvalidVersion {
		t.Fatalf("legacy version error = %v", err)
	}
	wire = pkt.Marshal()
	wire = append(wire, 0)
	if _, err := Unmarshal(wire); err == nil {
		t.Fatal("packet with trailing bytes was accepted")
	}
}

func TestPathHintEncoding(t *testing.T) {
	for _, want := range []string{PathHintLAN, PathHintRelay, PathHintPunch, PathHintDirect} {
		payload := EncodePathHint(want)
		if len(payload) == 0 {
			t.Fatalf("failed to encode %q", want)
		}
		if got, ok := DecodePathHint(payload); !ok || got != want {
			t.Fatalf("decoded hint = %q, ok=%v; want %q", got, ok, want)
		}
	}
	if EncodePathHint("unknown") != nil {
		t.Fatal("unknown path hint was encoded")
	}
	if _, ok := DecodePathHint([]byte("L4PATH:relay\x00")); ok {
		t.Fatal("malformed path hint was accepted")
	}
}
