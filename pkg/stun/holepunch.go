package stun

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ReflectAddress formats a net.Addr into an IP:Port string payload.
func ReflectAddress(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

// ParseReflectedAddress parses IP:Port string back into net.UDPAddr.
func ParseReflectedAddress(addrStr string) (*net.UDPAddr, error) {
	addrStr = strings.TrimSpace(addrStr)
	host, portText, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid reflected UDP endpoint %q: %w", addrStr, err)
	}
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if ip == nil || portErr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid reflected UDP endpoint %q", addrStr)
	}
	// STUN returns a numeric endpoint. Avoid hostname resolution here: this
	// parser runs in the server's single UDP receive loop, where a client-sent
	// DNS name could otherwise block every session while the resolver waits.
	return &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port}, nil
}

// HolePuncher manages UDP hole-punching probes and keepalives.
type HolePuncher struct {
	mu          sync.Mutex // Guards conn / sendTo / probeLogged so Retarget is safe while SendProbe runs.
	sessionID   uint64
	conn        *net.UDPConn
	sendTo      *net.UDPAddr // Non-nil for the unconnected punch socket; nil for connected candidate sockets.
	probeLogged bool         // First successful probe is logged for visibility; subsequent ones are silent.
	secureSend  func() error // Required authenticated sender supplied by the client.
	stopCh      chan struct{}
	lifecycleMu sync.Mutex // Serializes StartPunching with Stop.
	started     bool
	stopped     bool
	wg          sync.WaitGroup
}

// SetSecureSender installs the authenticated callback used for every probe.
// There is deliberately no raw packet fallback: a missing callback fails
// closed so hole punching cannot bypass the session AEAD layer.
func (hp *HolePuncher) SetSecureSender(sender func() error) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	hp.secureSend = sender
	hp.mu.Unlock()
}

// SetSessionID updates the identifier used only in probe diagnostics. The
// client creates its HolePuncher before the first handshake, so retaining the
// constructor's zero value would make otherwise useful logs look unauthenticated.
func (hp *HolePuncher) SetSessionID(sessionID uint64) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	hp.sessionID = sessionID
	hp.mu.Unlock()
}

// NewHolePuncher creates a hole puncher for a target UDP socket. For a
// connected (net.DialUDP) candidate socket sendTo must be nil (conn.Write
// reaches the peer); for the unconnected punch socket sendTo must be the
// server's public endpoint (conn.WriteToUDP).
func NewHolePuncher(sessionID uint64, conn *net.UDPConn, sendTo *net.UDPAddr) *HolePuncher {
	return &HolePuncher{
		sessionID: sessionID,
		conn:      conn,
		sendTo:    cloneUDPAddr(sendTo),
		stopCh:    make(chan struct{}),
	}
}

// SendBurst sends an immediate burst of N probes spaced by interval.
func (hp *HolePuncher) SendBurst(count int, interval time.Duration) {
	if hp == nil {
		return
	}
	for i := 0; i < count; i++ {
		select {
		case <-hp.stopCh:
			return
		default:
		}
		_ = hp.SendProbe()
		if i+1 < count && interval > 0 {
			time.Sleep(interval)
		}
	}
}

// StartPunching sends periodic UDP hole-punching probes to establish and maintain NAT mapping.
// It begins with an immediate fast burst (5 probes at 25ms intervals) to punch through the
// NAT state table within ~100ms, then transitions to periodic keepalives.
func (hp *HolePuncher) StartPunching(interval time.Duration) {
	if hp == nil {
		return
	}
	if interval <= 0 {
		interval = 3 * time.Second
	}
	hp.lifecycleMu.Lock()
	if hp.started || hp.stopped {
		hp.lifecycleMu.Unlock()
		return
	}
	// Add to the wait group while holding the same lock Stop uses before it
	// waits. This prevents Stop from observing a zero counter and returning
	// between the stop check and this goroutine's registration.
	hp.started = true
	hp.wg.Add(1)
	hp.lifecycleMu.Unlock()
	go func() {
		defer hp.wg.Done()
		// Fast burst to open hole immediately
		hp.SendBurst(5, 25*time.Millisecond)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-hp.stopCh:
				return
			case <-ticker.C:
				_ = hp.SendProbe()
			}
		}
	}()
}

// SendProbe transmits one probe through the authenticated client callback.
func (hp *HolePuncher) SendProbe() error {
	if hp == nil {
		return fmt.Errorf("hole puncher is nil")
	}
	hp.mu.Lock()
	secureSend := hp.secureSend
	sessionID := hp.sessionID
	hp.mu.Unlock()
	if secureSend == nil {
		return fmt.Errorf("hole puncher authenticated sender is not configured")
	}
	if err := secureSend(); err != nil {
		return err
	}
	hp.mu.Lock()
	first := !hp.probeLogged
	hp.probeLogged = true
	hp.mu.Unlock()
	if first {
		log.Printf("[Client] Authenticated STUN probe sent (sessionID=%d)", sessionID)
	}
	return nil
}

// Retarget points the puncher at the currently-active candidate socket, so the
// keepalives keep the NAT mapping of the path that actually carries data alive.
func (hp *HolePuncher) Retarget(conn *net.UDPConn, sendTo *net.UDPAddr) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	hp.conn = conn
	hp.sendTo = cloneUDPAddr(sendTo)
	hp.mu.Unlock()
}

// Stop halts the hole puncher.
func (hp *HolePuncher) Stop() {
	if hp == nil {
		return
	}
	hp.lifecycleMu.Lock()
	if hp.stopped {
		hp.lifecycleMu.Unlock()
		hp.wg.Wait()
		return
	}
	hp.stopped = true
	close(hp.stopCh)
	hp.lifecycleMu.Unlock()
	hp.wg.Wait()
}
