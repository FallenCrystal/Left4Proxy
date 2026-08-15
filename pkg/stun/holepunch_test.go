package stun

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestHolePuncherSendBurstAndStop(t *testing.T) {
	var receivedCount atomic.Int32
	hp := NewHolePuncher(12345, nil, nil)
	hp.SetSecureSender(func() error {
		receivedCount.Add(1)
		return nil
	})
	hp.SendBurst(5, 10*time.Millisecond)
	if count := receivedCount.Load(); count < 5 {
		t.Fatalf("expected at least 5 burst probes, got %d", count)
	}

	hp.Stop()
}

func TestHolePuncherFailsClosedWithoutSecureSender(t *testing.T) {
	hp := NewHolePuncher(9999, nil, nil)
	if err := hp.SendProbe(); err == nil {
		t.Fatal("hole puncher sent without an authenticated callback")
	}
}
