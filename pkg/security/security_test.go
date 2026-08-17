package security

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"left4proxy/pkg/protocol"
)

func testKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestSecretCreateAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secret")
	key, err := LoadSecret(path, true)
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("key length = %d", len(key))
	}
	got, err := LoadSecret(path, false)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("reload secret mismatch: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("secret permissions are not owner-only: %v", err)
	}
}

func TestAuthenticatedHandshakeAndAEAD(t *testing.T) {
	key := testKey()
	reqPkt, pending, err := NewHandshakeRequest(key, 7)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req, err := VerifyHandshakeRequest(key, reqPkt, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	respPkt, serverSession, err := NewHandshakeResponse(key, req, 99, []byte("relay|meta"))
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	resp, clientSession, err := VerifyHandshakeResponse(key, respPkt, pending, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("verify response: %v", err)
	}
	if resp.SessionID != 99 {
		t.Fatalf("session ID = %d", resp.SessionID)
	}
	seq, _ := clientSession.NextSeq()
	pkt := protocol.NewPacket(protocol.CmdData, 99, seq, []byte("secret game payload"))
	wire, err := clientSession.Seal(pkt, ClientToServer)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(wire, []byte("secret game payload")) {
		t.Fatal("wire packet contains plaintext payload")
	}
	opened, err := serverSession.Open(wire, ClientToServer)
	if err != nil || !bytes.Equal(opened.Payload, pkt.Payload) {
		t.Fatalf("open: %v", err)
	}
	if _, err := serverSession.Open(wire, ClientToServer); err != ErrPacketReplay {
		t.Fatalf("duplicate packet error = %v, want replay", err)
	}
	wire[len(wire)-1] ^= 1
	if _, err := serverSession.Open(wire, ClientToServer); err == nil {
		t.Fatal("tampered packet was accepted")
	}
}

func TestHandshakeTamperRejected(t *testing.T) {
	key := testKey()
	pkt, _, err := NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Payload[len(pkt.Payload)-1] ^= 0x80
	if _, err := VerifyHandshakeRequest(key, pkt, time.Now().UnixNano()); err == nil {
		t.Fatal("tampered handshake accepted")
	}
}

func TestWrongKeyAndMismatchedResponseRejected(t *testing.T) {
	key := testKey()
	pkt, pending, err := NewHandshakeRequest(key, 11)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := bytes.Repeat([]byte{0xee}, KeySize)
	if _, err := VerifyHandshakeRequest(wrongKey, pkt, time.Now().UnixNano()); !errors.Is(err, ErrHandshakeAuth) {
		t.Fatalf("wrong-key request error = %v", err)
	}
	req, err := VerifyHandshakeRequest(key, pkt, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	// Construct a correctly authenticated server response that is not tied to
	// the client's pending sequence. The client must still reject it.
	req.Seq++
	resp, _, err := NewHandshakeResponse(key, req, 123, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyHandshakeResponse(key, resp, pending, time.Now().UnixNano()); !errors.Is(err, ErrHandshakeAuth) {
		t.Fatalf("mismatched response error = %v", err)
	}
}

func TestSequenceExhaustionIsPermanent(t *testing.T) {
	key := testKey()
	reqPkt, pending, err := NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	req, err := VerifyHandshakeRequest(key, reqPkt, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	respPkt, _, err := NewHandshakeResponse(key, req, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := VerifyHandshakeResponse(key, respPkt, pending, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	session.sendSeq.Store(math.MaxUint32)
	for i := 0; i < 2; i++ {
		if _, err := session.NextSeq(); !errors.Is(err, ErrSequenceExhausted) {
			t.Fatalf("NextSeq attempt %d error = %v", i, err)
		}
	}
}

func TestHandshakeMetadataRespectsUDPPayloadLimit(t *testing.T) {
	key := testKey()
	reqPkt, _, err := NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	req, err := VerifyHandshakeRequest(key, reqPkt, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	fixedBodyLen := len(HandshakeMagic) + HandshakeNonceSize*2 + HandshakePubSize + 2
	maxMetadata := protocol.MaxPacketPayloadSize - fixedBodyLen - HandshakeTagSize
	if _, _, err := NewHandshakeResponse(key, req, 123, make([]byte, maxMetadata+1)); err == nil {
		t.Fatal("handshake metadata exceeding the UDP payload limit was accepted")
	}
}

func TestSecretSymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlink permission test")
	}
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-secret")
	if err := os.WriteFile(realPath, []byte("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"), 0600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, ".secret")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadSecret(linkPath, false); !errors.Is(err, ErrSecretSymlink) {
		t.Fatalf("symlink error = %v", err)
	}
}
