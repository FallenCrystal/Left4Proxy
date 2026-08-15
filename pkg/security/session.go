package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"

	"left4proxy/pkg/protocol"
)

var randReader = rand.Reader

func readRandom(buf []byte) (int, error) { return io.ReadFull(randReader, buf) }

const (
	HandshakeNonceSize = 32
	HandshakePubSize   = 32
	HandshakeTagSize   = sha256.Size
	HandshakeMagic     = "L4H2"
	maxHandshakeSkew   = int64(120 * 1e9) // two minutes in nanoseconds
)

type Direction byte

const (
	ClientToServer Direction = 1
	ServerToClient Direction = 2
)

var (
	ErrHandshakeMalformed = errors.New("malformed authenticated handshake")
	ErrHandshakeAuth      = errors.New("handshake authentication failed")
	ErrHandshakeExpired   = errors.New("handshake timestamp outside accepted window")
	ErrSessionMismatch    = errors.New("packet session does not match secure session")
	ErrPacketReplay       = errors.New("replayed or out-of-window packet")
	ErrPacketAuth         = errors.New("packet authentication failed")
	ErrSequenceExhausted  = errors.New("secure packet sequence exhausted")
)

// PendingHandshake is the client-side state needed to validate one or more
// responses to the same handshake sent over multiple candidate sockets.
type PendingHandshake struct {
	ClientNonce   [HandshakeNonceSize]byte
	ClientPrivate *ecdh.PrivateKey
	ClientPublic  [HandshakePubSize]byte
	Seq           uint32
	Timestamp     int64
}

type HandshakeRequest struct {
	ClientNonce  [HandshakeNonceSize]byte
	ClientPublic *ecdh.PublicKey
	Seq          uint32
	Timestamp    int64
}

type HandshakeResponse struct {
	SessionID    uint64
	ClientNonce  [HandshakeNonceSize]byte
	ServerNonce  [HandshakeNonceSize]byte
	ServerPublic *ecdh.PublicKey
	Metadata     []byte
}

// NewHandshakeRequest creates a PSK-authenticated X25519 handshake request.
func NewHandshakeRequest(key []byte, seq uint32) (*protocol.Packet, *PendingHandshake, error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("invalid authentication key length %d", len(key))
	}
	if seq == 0 {
		return nil, nil, ErrHandshakeMalformed
	}
	private, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client ephemeral key: %w", err)
	}
	var nonce [HandshakeNonceSize]byte
	if _, err := readRandom(nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("generate client handshake nonce: %w", err)
	}
	var public [HandshakePubSize]byte
	copy(public[:], private.PublicKey().Bytes())
	pkt := protocol.NewPacket(protocol.CmdHandshakeReq, 0, seq, nil)
	body := make([]byte, 0, len(HandshakeMagic)+HandshakeNonceSize+HandshakePubSize)
	body = append(body, HandshakeMagic...)
	body = append(body, nonce[:]...)
	body = append(body, public[:]...)
	tag := handshakeMAC(key, "request", pkt, body, len(body)+HandshakeTagSize)
	pkt.Payload = append(body, tag...)
	return pkt, &PendingHandshake{
		ClientNonce:   nonce,
		ClientPrivate: private,
		ClientPublic:  public,
		Seq:           pkt.Seq,
		Timestamp:     pkt.Timestamp,
	}, nil
}

// VerifyHandshakeRequest authenticates and parses a client request before any
// server session or socket is allocated.
func VerifyHandshakeRequest(key []byte, pkt *protocol.Packet, now int64) (*HandshakeRequest, error) {
	if len(key) != KeySize || pkt == nil || pkt.Version != protocol.Version2 || pkt.Cmd != protocol.CmdHandshakeReq || pkt.SessionID != 0 || pkt.Seq == 0 {
		return nil, ErrHandshakeMalformed
	}
	if len(pkt.Payload) != len(HandshakeMagic)+HandshakeNonceSize+HandshakePubSize+HandshakeTagSize {
		return nil, ErrHandshakeMalformed
	}
	if abs64(now-pkt.Timestamp) > maxHandshakeSkew {
		return nil, ErrHandshakeExpired
	}
	body := pkt.Payload[:len(pkt.Payload)-HandshakeTagSize]
	gotTag := pkt.Payload[len(body):]
	wantTag := handshakeMAC(key, "request", pkt, body, len(pkt.Payload))
	if !hmac.Equal(gotTag, wantTag) {
		return nil, ErrHandshakeAuth
	}
	if string(body[:len(HandshakeMagic)]) != HandshakeMagic {
		return nil, ErrHandshakeMalformed
	}
	var nonce [HandshakeNonceSize]byte
	copy(nonce[:], body[len(HandshakeMagic):len(HandshakeMagic)+HandshakeNonceSize])
	pubBytes := body[len(HandshakeMagic)+HandshakeNonceSize:]
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client public key", ErrHandshakeMalformed)
	}
	return &HandshakeRequest{ClientNonce: nonce, ClientPublic: pub, Seq: pkt.Seq, Timestamp: pkt.Timestamp}, nil
}

// NewHandshakeResponse creates the authenticated server response and its
// derived secure session.  The metadata is covered by the HMAC and therefore
// cannot be forged to change advertised paths or endpoints.
func NewHandshakeResponse(key []byte, req *HandshakeRequest, sessionID uint64, metadata []byte) (*protocol.Packet, *Session, error) {
	if len(key) != KeySize || req == nil || req.ClientPublic == nil || sessionID == 0 || req.Seq == 0 {
		return nil, nil, ErrHandshakeMalformed
	}
	private, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server ephemeral key: %w", err)
	}
	shared, err := private.ECDH(req.ClientPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("derive handshake secret: %w", err)
	}
	var serverNonce [HandshakeNonceSize]byte
	if _, err := readRandom(serverNonce[:]); err != nil {
		return nil, nil, fmt.Errorf("generate server handshake nonce: %w", err)
	}
	serverPublic := private.PublicKey().Bytes()
	fixedBodyLen := len(HandshakeMagic) + HandshakeNonceSize*2 + HandshakePubSize + 2
	if len(metadata) > int(^uint16(0))-fixedBodyLen-HandshakeTagSize {
		return nil, nil, fmt.Errorf("handshake metadata too large")
	}
	pkt := &protocol.Packet{
		Version:   protocol.Version2,
		Cmd:       protocol.CmdHandshakeResp,
		SessionID: sessionID,
		Seq:       req.Seq,
		Timestamp: req.Timestamp,
	}
	body := make([]byte, 0, len(HandshakeMagic)+HandshakeNonceSize*2+HandshakePubSize+2+len(metadata))
	body = append(body, HandshakeMagic...)
	body = append(body, req.ClientNonce[:]...)
	body = append(body, serverNonce[:]...)
	body = append(body, serverPublic...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(metadata)))
	body = append(body, lenBuf[:]...)
	body = append(body, metadata...)
	tag := handshakeMAC(key, "response", pkt, body, len(body)+HandshakeTagSize)
	pkt.Payload = append(body, tag...)
	session := newSession(key, shared, req.ClientNonce, serverNonce, sessionID)
	return pkt, session, nil
}

// VerifyHandshakeResponse validates a response on the candidate that sent a
// request.  The caller may inspect metadata from every valid candidate but
// should adopt only the first session ID for the shared client route.
func VerifyHandshakeResponse(key []byte, pkt *protocol.Packet, pending *PendingHandshake, now int64) (*HandshakeResponse, *Session, error) {
	if len(key) != KeySize || pkt == nil || pending == nil || pending.ClientPrivate == nil || pending.Seq == 0 || pkt.Version != protocol.Version2 || pkt.Cmd != protocol.CmdHandshakeResp || pkt.SessionID == 0 {
		return nil, nil, ErrHandshakeMalformed
	}
	if pkt.Seq != pending.Seq || pkt.Timestamp != pending.Timestamp {
		return nil, nil, ErrHandshakeAuth
	}
	if abs64(now-pkt.Timestamp) > maxHandshakeSkew {
		return nil, nil, ErrHandshakeExpired
	}
	minLen := len(HandshakeMagic) + HandshakeNonceSize*2 + HandshakePubSize + 2 + HandshakeTagSize
	if len(pkt.Payload) < minLen {
		return nil, nil, ErrHandshakeMalformed
	}
	body := pkt.Payload[:len(pkt.Payload)-HandshakeTagSize]
	gotTag := pkt.Payload[len(body):]
	wantTag := handshakeMAC(key, "response", pkt, body, len(pkt.Payload))
	if !hmac.Equal(gotTag, wantTag) {
		return nil, nil, ErrHandshakeAuth
	}
	off := 0
	if string(body[off:off+len(HandshakeMagic)]) != HandshakeMagic {
		return nil, nil, ErrHandshakeMalformed
	}
	off += len(HandshakeMagic)
	var clientNonce [HandshakeNonceSize]byte
	copy(clientNonce[:], body[off:off+HandshakeNonceSize])
	off += HandshakeNonceSize
	if clientNonce != pending.ClientNonce {
		return nil, nil, ErrHandshakeAuth
	}
	var serverNonce [HandshakeNonceSize]byte
	copy(serverNonce[:], body[off:off+HandshakeNonceSize])
	off += HandshakeNonceSize
	serverPubBytes := body[off : off+HandshakePubSize]
	off += HandshakePubSize
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid server public key", ErrHandshakeMalformed)
	}
	if off+2 > len(body) {
		return nil, nil, ErrHandshakeMalformed
	}
	metadataLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if metadataLen != len(body)-off {
		return nil, nil, ErrHandshakeMalformed
	}
	metadata := append([]byte(nil), body[off:]...)
	shared, err := pending.ClientPrivate.ECDH(serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("derive response secret: %w", err)
	}
	resp := &HandshakeResponse{SessionID: pkt.SessionID, ClientNonce: clientNonce, ServerNonce: serverNonce, ServerPublic: serverPub, Metadata: metadata}
	return resp, newSession(key, shared, clientNonce, serverNonce, pkt.SessionID), nil
}

// Session provides authenticated encryption and replay protection for one
// Left4Proxy session.  It is safe for one reader and multiple writers.
type Session struct {
	ID        uint64
	clientKey []byte
	serverKey []byte
	sendSeq   atomic.Uint32
	recv      ReplayWindow
	mu        sync.RWMutex
	closed    bool
	exhausted bool
}

func newSession(psk, shared []byte, clientNonce, serverNonce [HandshakeNonceSize]byte, id uint64) *Session {
	ikm := make([]byte, 0, len(shared)+len(psk))
	ikm = append(ikm, shared...)
	ikm = append(ikm, psk...)
	salt := make([]byte, 0, HandshakeNonceSize*2)
	salt = append(salt, clientNonce[:]...)
	salt = append(salt, serverNonce[:]...)
	prk := hkdfExtract(salt, ikm)
	return &Session{
		ID:        id,
		clientKey: hkdfExpand(prk, []byte("Left4Proxy/v2/client-to-server"), KeySize),
		serverKey: hkdfExpand(prk, []byte("Left4Proxy/v2/server-to-client"), KeySize),
	}
}

func (s *Session) key(direction Direction) ([]byte, bool) {
	switch direction {
	case ClientToServer:
		return s.clientKey, true
	case ServerToClient:
		return s.serverKey, true
	default:
		return nil, false
	}
}

func (s *Session) NextSeq() (uint32, error) {
	if s == nil {
		return 0, errors.New("secure session is nil")
	}
	for {
		s.mu.RLock()
		closed, exhausted := s.closed, s.exhausted
		s.mu.RUnlock()
		if closed {
			return 0, errors.New("secure session is closed")
		}
		if exhausted {
			return 0, ErrSequenceExhausted
		}
		current := s.sendSeq.Load()
		if current == math.MaxUint32 {
			s.mu.Lock()
			s.exhausted = true
			s.mu.Unlock()
			return 0, ErrSequenceExhausted
		}
		if s.sendSeq.CompareAndSwap(current, current+1) {
			return current + 1, nil
		}
	}
}

// Seal encrypts a non-handshake packet.  The caller supplies a fresh sequence
// (normally from NextSeq); the returned bytes are ready for the production UDP
// data path.
func (s *Session) Seal(pkt *protocol.Packet, direction Direction) ([]byte, error) {
	if s == nil || pkt == nil || pkt.Version != protocol.Version2 || pkt.Seq == 0 || pkt.Cmd == protocol.CmdHandshakeReq || pkt.Cmd == protocol.CmdHandshakeResp {
		return nil, ErrPacketAuth
	}
	if pkt.SessionID != s.ID {
		return nil, ErrSessionMismatch
	}
	s.mu.RLock()
	closed := s.closed
	keyBytes, validDirection := s.key(direction)
	key := append([]byte(nil), keyBytes...)
	s.mu.RUnlock()
	if closed {
		return nil, errors.New("secure session is closed")
	}
	if !validDirection {
		return nil, ErrPacketAuth
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	nonce := makeNonce(s.ID, pkt.Seq)
	wirePayloadLen := len(pkt.Payload) + aead.Overhead()
	if wirePayloadLen > math.MaxUint16 {
		return nil, fmt.Errorf("packet payload exceeds wire limit")
	}
	aad := pkt.MarshalHeader(wirePayloadLen)
	ciphertext := aead.Seal(nil, nonce[:], pkt.Payload, aad)
	secured := *pkt
	secured.Payload = ciphertext
	return secured.Marshal(), nil
}

// Open authenticates and decrypts a wire packet, committing its sequence to
// the replay window only after the AEAD tag is valid.
func (s *Session) Open(data []byte, direction Direction) (*protocol.Packet, error) {
	if s == nil {
		return nil, ErrPacketAuth
	}
	pkt, err := protocol.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	if pkt.Version != protocol.Version2 || pkt.SessionID != s.ID || pkt.Seq == 0 || pkt.Cmd == protocol.CmdHandshakeReq || pkt.Cmd == protocol.CmdHandshakeResp {
		return nil, ErrSessionMismatch
	}
	s.mu.RLock()
	closed := s.closed
	keyBytes, validDirection := s.key(direction)
	key := append([]byte(nil), keyBytes...)
	s.mu.RUnlock()
	if closed {
		return nil, errors.New("secure session is closed")
	}
	if !validDirection {
		return nil, ErrPacketAuth
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	if len(pkt.Payload) < aead.Overhead() {
		return nil, ErrPacketAuth
	}
	nonce := makeNonce(s.ID, pkt.Seq)
	aad := pkt.MarshalHeader(len(pkt.Payload))
	plaintext, err := aead.Open(nil, nonce[:], pkt.Payload, aad)
	if err != nil {
		return nil, ErrPacketAuth
	}
	if !s.recv.Accept(pkt.Seq) {
		return nil, ErrPacketReplay
	}
	pkt.Payload = plaintext
	return pkt, nil
}

func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.closed {
		for i := range s.clientKey {
			s.clientKey[i] = 0
		}
		for i := range s.serverKey {
			s.serverKey[i] = 0
		}
		s.closed = true
	}
	s.mu.Unlock()
}

// IsClosed reports whether the session has been closed and its traffic keys
// have been wiped.
func (s *Session) IsClosed() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	return closed
}

// ReplayWindow is a 64-packet sliding replay filter.
type ReplayWindow struct {
	mu          sync.Mutex
	initialized bool
	max         uint32
	bits        uint64
}

func (w *ReplayWindow) Accept(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.initialized {
		w.initialized = true
		w.max = seq
		w.bits = 1
		return true
	}
	if seq > w.max {
		shift := seq - w.max
		if shift >= 64 {
			w.bits = 1
		} else {
			w.bits = (w.bits << shift) | 1
		}
		w.max = seq
		return true
	}
	delta := w.max - seq
	if delta >= 64 || (w.bits&(uint64(1)<<delta)) != 0 {
		return false
	}
	w.bits |= uint64(1) << delta
	return true
}

func makeNonce(sessionID uint64, seq uint32) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], sessionID)
	binary.BigEndian.PutUint32(nonce[8:], seq)
	return nonce
}

func handshakeMAC(key []byte, kind string, pkt *protocol.Packet, body []byte, payloadLen int) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("Left4Proxy/v2/" + kind))
	_, _ = h.Write(pkt.MarshalHeader(payloadLen))
	_, _ = h.Write(body)
	return h.Sum(nil)
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	_, _ = h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(out) < length; counter++ {
		h := hmac.New(sha256.New, prk)
		_, _ = h.Write(previous)
		_, _ = h.Write(info)
		_, _ = h.Write([]byte{counter})
		previous = h.Sum(nil)
		out = append(out, previous...)
	}
	return out[:length]
}

func abs64(v int64) int64 {
	if v < 0 {
		if v == math.MinInt64 {
			return math.MaxInt64
		}
		return -v
	}
	return v
}
