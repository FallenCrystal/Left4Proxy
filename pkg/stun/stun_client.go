package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
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

	stunHeaderLen    = 20
	transactionIDLen = 12
	transactionTTL   = 5 * time.Second
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
		if err == nil && addr != nil && addr.Port > 0 && addr.Port <= 65535 && addr.IP != nil {
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
	for _, addr := range addrs {
		if addr != nil {
			// This compatibility helper intentionally does not expose response
			// validation state. Production callers must use Validator; retain the
			// function only for users that merely need to emit discovery traffic.
			req := BuildBindingRequest()
			if len(req) > 0 {
				_, _ = conn.WriteToUDP(req, addr)
			}
		}
	}
}

// BindingTransaction records the destination and expiry of one outstanding
// request.  A response is trusted only when it carries this transaction ID
// and arrives from the exact destination address.
type BindingTransaction struct {
	ID        [transactionIDLen]byte
	Server    *net.UDPAddr
	ExpiresAt time.Time
}

type pendingTransaction struct {
	BindingTransaction
}

// ValidatedResponse is a Binding Response that passed transaction, source and
// structural validation.
type ValidatedResponse struct {
	TransactionID [transactionIDLen]byte
	Server        *net.UDPAddr
	Reflected     *net.UDPAddr
}

// Validator tracks Binding Requests sent from one UDP socket.  It is safe for
// a writer goroutine and the socket's reader goroutine to use concurrently.
type Validator struct {
	mu      sync.Mutex
	pending map[[transactionIDLen]byte]pendingTransaction
	ttl     time.Duration
}

func NewValidator() *Validator {
	return &Validator{pending: make(map[[transactionIDLen]byte]pendingTransaction), ttl: transactionTTL}
}

// SendBindingRequest sends a request with a fresh transaction ID and records
// the exact destination before any response can be accepted.
func (v *Validator) SendBindingRequest(conn *net.UDPConn, server *net.UDPAddr) error {
	if v == nil {
		return errors.New("stun: validator is nil")
	}
	if conn == nil || server == nil {
		return errors.New("stun: connection and server are required")
	}
	if !udpAddressFamilyCompatible(conn, server) {
		return errors.New("stun: server address family is incompatible with socket")
	}
	v.mu.Lock()
	v.pruneLocked(time.Now())
	var req []byte
	var id [transactionIDLen]byte
	var err error
	for {
		req, id, err = buildBindingRequest()
		if err != nil {
			v.mu.Unlock()
			return fmt.Errorf("stun: generate transaction ID: %w", err)
		}
		if _, exists := v.pending[id]; !exists {
			break
		}
	}
	v.pending[id] = pendingTransaction{BindingTransaction: BindingTransaction{ID: id, Server: cloneUDPAddr(server), ExpiresAt: time.Now().Add(v.ttl)}}
	v.mu.Unlock()
	if _, err := conn.WriteToUDP(req, server); err != nil {
		v.mu.Lock()
		delete(v.pending, id)
		v.mu.Unlock()
		return err
	}
	return nil
}

// SendMultiBindingRequests sends a distinct request to each destination.
func (v *Validator) SendMultiBindingRequests(conn *net.UDPConn, servers []*net.UDPAddr) error {
	var firstErr error
	sent := 0
	seen := make(map[string]struct{})
	for _, server := range servers {
		if server == nil {
			continue
		}
		if !udpAddressFamilyCompatible(conn, server) {
			if firstErr == nil {
				firstErr = errors.New("stun: no server destination matches socket address family")
			}
			continue
		}
		key := server.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if err := v.SendBindingRequest(conn, server); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			sent++
		}
	}
	if sent > 0 {
		return nil
	}
	if firstErr == nil {
		return errors.New("stun: no usable server destinations")
	}
	return firstErr
}

// udpAddressFamilyCompatible avoids noisy EINVAL writes when a v4-bound
// listener races a DNS result containing only IPv6 (or vice versa). An
// unspecified socket may be dual-stack, so both families remain eligible in
// that case and the kernel decides whether the individual write is supported.
func udpAddressFamilyCompatible(conn *net.UDPConn, server *net.UDPAddr) bool {
	if conn == nil || server == nil || server.IP == nil || server.Port <= 0 || server.Port > 65535 {
		return false
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil || local.IP == nil || local.IP.IsUnspecified() {
		return true
	}
	return (local.IP.To4() != nil) == (server.IP.To4() != nil)
}

// Accept validates and consumes one response.  Invalid, unsolicited, stale,
// or source-mismatched packets are never allowed to update endpoint state.
func (v *Validator) Accept(data []byte, source *net.UDPAddr) (*ValidatedResponse, error) {
	if v == nil {
		return nil, errors.New("stun: validator is nil")
	}
	if source == nil {
		return nil, errors.New("stun: response source is nil")
	}
	if !isBindingResponseShape(data) {
		return nil, errors.New("stun: not a binding response")
	}
	var id [transactionIDLen]byte
	copy(id[:], data[8:20])
	now := time.Now()
	v.mu.Lock()
	v.pruneLocked(now)
	pending, ok := v.pending[id]
	if !ok {
		v.mu.Unlock()
		return nil, errors.New("stun: unknown or expired transaction")
	}
	if !sameUDPAddr(source, pending.Server) {
		v.mu.Unlock()
		return nil, errors.New("stun: response source does not match request destination")
	}
	// Parse while holding the validator lock so two reader goroutines cannot
	// both accept the same transaction.  A structurally invalid packet leaves
	// the transaction pending until it expires, allowing a valid retransmission.
	reflected, err := ParseBindingResponseForTransaction(data, &id)
	if err != nil {
		v.mu.Unlock()
		return nil, err
	}
	delete(v.pending, id)
	v.mu.Unlock()
	return &ValidatedResponse{TransactionID: id, Server: cloneUDPAddr(pending.Server), Reflected: reflected}, nil
}

func (v *Validator) pruneLocked(now time.Time) {
	for id, p := range v.pending {
		if !now.Before(p.ExpiresAt) {
			delete(v.pending, id)
		}
	}
}

func buildBindingRequest() ([]byte, [transactionIDLen]byte, error) {
	buf := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	var id [transactionIDLen]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return nil, [transactionIDLen]byte{}, err
	}
	copy(buf[8:20], id[:])
	return buf, id, nil
}

// BuildBindingRequest builds a 20-byte STUN Binding Request with a random
// transaction ID. It carries no attributes.
func BuildBindingRequest() []byte {
	buf, _, _ := buildBindingRequest()
	return buf
}

// IsStunMessage reports whether data has a structurally plausible STUN header.
// It is only a classifier; callers must use Validator.Accept before trusting a
// response.
func IsStunMessage(data []byte) bool {
	if len(data) < stunHeaderLen || binary.BigEndian.Uint32(data[4:8]) != stunMagicCookie {
		return false
	}
	// RFC 5389 reserves the two most significant type bits as zero. Rejecting
	// them avoids classifying arbitrary reflected payloads as STUN frames.
	if binary.BigEndian.Uint16(data[0:2])&0xC000 != 0 {
		return false
	}
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	return msgLen <= len(data)-stunHeaderLen
}

// IsStunResponse reports whether data is a structurally plausible Binding
// Response. It intentionally does not claim authenticity.
func IsStunResponse(data []byte) bool {
	return IsStunMessage(data) && binary.BigEndian.Uint16(data[0:2]) == stunBindingResponse
}

// ParseBindingResponse extracts the XOR-MAPPED-ADDRESS from a successful STUN
// Binding Response and returns the reflected public endpoint (RFC 5389 §15.2).
func ParseBindingResponse(data []byte) (*net.UDPAddr, error) {
	return ParseBindingResponseForTransaction(data, nil)
}

// ParseBindingResponseForTransaction parses a response and, when expected is
// non-nil, verifies its transaction ID. Source-address validation belongs to
// Validator.Accept because the parser does not receive the UDP source.
func ParseBindingResponseForTransaction(data []byte, expected *[transactionIDLen]byte) (*net.UDPAddr, error) {
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
	if expected != nil {
		if !equalBytes(txid, expected[:]) {
			return nil, errors.New("stun: transaction ID mismatch")
		}
	}

	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	end := stunHeaderLen + msgLen
	if end != len(data) {
		return nil, errors.New("stun: message length mismatch")
	}

	// Walk every TLV attribute (values padded to a 4-byte boundary). Do not
	// return as soon as the mapped address is found: otherwise a forged response
	// could append malformed trailing bytes and still pass structural checks.
	var reflected *net.UDPAddr
	offset := stunHeaderLen
	for offset < end {
		if end-offset < 4 {
			return nil, errors.New("stun: truncated attribute header")
		}
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		val := offset + 4
		if val+attrLen > end {
			return nil, errors.New("stun: attribute overruns message")
		}
		padded := attrLen + (4-attrLen%4)%4
		if val+padded > end {
			return nil, errors.New("stun: attribute padding overruns message")
		}
		if attrType == attrXORMappedAddress {
			if reflected != nil {
				return nil, errors.New("stun: duplicate XOR-MAPPED-ADDRESS attribute")
			}
			parsed, err := parseXORMappedAddress(data[val:val+attrLen], txid)
			if err != nil {
				return nil, err
			}
			reflected = parsed
		}
		offset = val + padded
	}
	if reflected == nil {
		return nil, errors.New("stun: no XOR-MAPPED-ADDRESS attribute")
	}
	return reflected, nil
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isBindingResponseShape(data []byte) bool {
	return IsStunResponse(data) && int(binary.BigEndian.Uint16(data[2:4])) == len(data)-stunHeaderLen
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
	if len(v) < 4 || v[0] != 0 {
		return nil, errors.New("stun: short XOR-MAPPED-ADDRESS")
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4]) ^ (stunMagicCookie >> 16)
	if port == 0 {
		return nil, errors.New("stun: XOR-MAPPED-ADDRESS has an invalid port")
	}

	switch family {
	case 0x01: // IPv4
		if len(v) != 8 {
			return nil, errors.New("stun: short IPv4 XOR-MAPPED-ADDRESS")
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(v[4:8])^stunMagicCookie)
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	case 0x02: // IPv6
		if len(v) != 20 {
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
