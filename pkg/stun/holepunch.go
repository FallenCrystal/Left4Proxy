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
	mu          sync.Mutex // Guards conn / sendTo / probeLogged so Retarget is safe while SendProbe runs.
	sessionID   uint64
	conn        *net.UDPConn
	sendTo      *net.UDPAddr // Non-nil for the unconnected punch socket; nil for connected candidate sockets.
	probeLogged bool         // First successful probe is logged for visibility; subsequent ones are silent.
	stopCh      chan struct{}
}

// NewHolePuncher creates a hole puncher for a target UDP socket. For a
// connected (net.DialUDP) candidate socket sendTo must be nil (conn.Write
// reaches the peer); for the unconnected punch socket sendTo must be the
// server's public endpoint (conn.WriteToUDP).
func NewHolePuncher(sessionID uint64, conn *net.UDPConn, sendTo *net.UDPAddr) *HolePuncher {
	return &HolePuncher{
		sessionID: sessionID,
		conn:      conn,
		sendTo:    sendTo,
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
// The candidate socket is created with net.DialUDP (connected), so we must use
// conn.Write (which sends to the connected peer) — calling conn.WriteToUDP on a
// connected socket fails with "use of WriteTo with pre-connected connection"
// and silently drops every probe. The punch socket is the opposite: it is
// unconnected (net.ListenUDP) and must use WriteToUDP to reach the server's
// public endpoint.
func (hp *HolePuncher) SendProbe() error {
	hp.mu.Lock()
	conn := hp.conn
	sendTo := hp.sendTo
	first := !hp.probeLogged
	hp.probeLogged = true
	hp.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("hole puncher connection is nil")
	}

	pkt := protocol.NewPacket(protocol.CmdStunProbe, hp.sessionID, 0, []byte("PUNCH"))
	data := pkt.Marshal()
	var err error
	if sendTo != nil {
		_, err = conn.WriteToUDP(data, sendTo)
	} else {
		_, err = conn.Write(data)
	}
	if err != nil {
		log.Printf("[Client] STUN probe SEND FAILED from %s: %v", conn.LocalAddr(), err)
		return err
	}
	if first {
		target := "?"
		if sendTo != nil {
			target = sendTo.String()
		} else if conn.RemoteAddr() != nil {
			target = conn.RemoteAddr().String()
		}
		log.Printf("[Client] STUN probe OK -> %s from %s (sessionID=%d)", target, conn.LocalAddr(), hp.sessionID)
	}
	return nil
}

// Retarget points the puncher at the currently-active candidate socket, so the
// keepalives keep the NAT mapping of the path that actually carries data alive.
func (hp *HolePuncher) Retarget(conn *net.UDPConn, sendTo *net.UDPAddr) {
	hp.mu.Lock()
	hp.conn = conn
	hp.sendTo = sendTo
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
