package stun

import (
	"fmt"
	"net"
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
	sessionID  uint64
	conn       *net.UDPConn
	targetAddr *net.UDPAddr
	stopCh     chan struct{}
}

// NewHolePuncher creates a hole puncher for a target UDP address.
func NewHolePuncher(sessionID uint64, conn *net.UDPConn, targetAddr *net.UDPAddr) *HolePuncher {
	return &HolePuncher{
		sessionID:  sessionID,
		conn:       conn,
		targetAddr: targetAddr,
		stopCh:     make(chan struct{}),
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
func (hp *HolePuncher) SendProbe() error {
	if hp.conn == nil || hp.targetAddr == nil {
		return fmt.Errorf("hole puncher connection or target address is nil")
	}
	pkt := protocol.NewPacket(protocol.CmdStunProbe, hp.sessionID, 0, []byte("PUNCH"))
	data := pkt.Marshal()
	_, err := hp.conn.WriteToUDP(data, hp.targetAddr)
	return err
}

// Stop halts the hole puncher.
func (hp *HolePuncher) Stop() {
	select {
	case <-hp.stopCh:
	default:
		close(hp.stopCh)
	}
}
