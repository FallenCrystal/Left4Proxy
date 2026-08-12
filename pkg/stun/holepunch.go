package stun

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"left4proxy/pkg/protocol"
)

// ReflectAddress formats a net.Addr into an IP:Port string payload.
func ReflectAddress(addr net.Addr) string {
	return addr.String()
}

// ParseReflectedAddress parses IP:Port string back into net.UDPAddr.
func ParseReflectedAddress(addrStr string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", addrStr)
}

// HolePuncher manages UDP hole-punching probes and keepalives.
type HolePuncher struct {
	mu          sync.Mutex // Guards conn / probeLogged so Retarget is safe while SendProbe runs.
	sessionID   uint64
	conn        *net.UDPConn
	probeLogged bool // First successful probe is logged for visibility; subsequent ones are silent.
	stopCh      chan struct{}
}

// NewHolePuncher creates a hole puncher for a target UDP address. The conn must
// be connected (net.DialUDP) to the target so that conn.Write reaches it.
func NewHolePuncher(sessionID uint64, conn *net.UDPConn) *HolePuncher {
	return &HolePuncher{
		sessionID: sessionID,
		conn:      conn,
		stopCh:    make(chan struct{}),
	}
}

// StartPunching sends periodic UDP hole-punching probes to establish and maintain NAT mapping.
func (hp *HolePuncher) StartPunching(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-hp.stopCh:
				return
			case <-ticker.C:
				hp.SendProbe()
			}
		}
	}()
	// Immediately send initial burst of probes
	for i := 0; i < 3; i++ {
		hp.SendProbe()
		time.Sleep(20 * time.Millisecond)
	}
}

// SendProbe transmits a single UDP STUN probe packet.
//
// The candidate socket is created with net.DialUDP, i.e. it is "connected", so
// we must use conn.Write (which sends to the connected peer) — calling
// conn.WriteToUDP on a connected socket fails with "use of WriteTo with
// pre-connected connection" and silently drops every probe.
func (hp *HolePuncher) SendProbe() error {
	hp.mu.Lock()
	conn := hp.conn
	first := !hp.probeLogged
	hp.probeLogged = true
	hp.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("hole puncher connection is nil")
	}

	pkt := protocol.NewPacket(protocol.CmdStunProbe, hp.sessionID, 0, []byte("PUNCH"))
	data := pkt.Marshal()
	if _, err := conn.Write(data); err != nil {
		log.Printf("[Client] STUN probe SEND FAILED from %s: %v", conn.LocalAddr(), err)
		return err
	}
	if first {
		log.Printf("[Client] STUN probe OK -> %s from %s (sessionID=%d)", conn.RemoteAddr(), conn.LocalAddr(), hp.sessionID)
	}
	return nil
}

// Retarget points the puncher at the currently-active candidate socket, so the
// keepalives keep the NAT mapping of the path that actually carries data alive.
func (hp *HolePuncher) Retarget(conn *net.UDPConn) {
	hp.mu.Lock()
	hp.conn = conn
	hp.mu.Unlock()
}

// Stop halts the hole puncher.
func (hp *HolePuncher) Stop() {
	select {
	case <-hp.stopCh:
	default:
		close(hp.stopCh)
	}
}
