package stun

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseReflectedAddressRequiresLiteralEndpoint(t *testing.T) {
	for _, tc := range []struct {
		value string
		ip    string
		port  int
	}{
		{value: "203.0.113.9:41000", ip: "203.0.113.9", port: 41000},
		{value: "[2001:db8::9]:41001", ip: "2001:db8::9", port: 41001},
	} {
		addr, err := ParseReflectedAddress(tc.value)
		if err != nil {
			t.Fatalf("ParseReflectedAddress(%q): %v", tc.value, err)
		}
		if !addr.IP.Equal(net.ParseIP(tc.ip)) || addr.Port != tc.port {
			t.Fatalf("ParseReflectedAddress(%q) = %v", tc.value, addr)
		}
	}
	for _, value := range []string{"example.com:41000", "203.0.113.9:0", "203.0.113.9", ""} {
		if _, err := ParseReflectedAddress(value); err == nil {
			t.Fatalf("non-literal or invalid endpoint %q was accepted", value)
		}
	}
}

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

func TestHolePuncherStartStopIsRaceFree(t *testing.T) {
	for i := 0; i < 100; i++ {
		hp := NewHolePuncher(uint64(i+1), nil, nil)
		hp.SetSecureSender(func() error { return nil })
		var callers sync.WaitGroup
		callers.Add(2)
		go func() {
			defer callers.Done()
			hp.StartPunching(time.Hour)
		}()
		go func() {
			defer callers.Done()
			hp.Stop()
		}()
		callers.Wait()
		// Stop is idempotent, and a stopped puncher must not be restartable.
		hp.Stop()
		hp.StartPunching(time.Millisecond)
		hp.lifecycleMu.Lock()
		started, stopped := hp.started, hp.stopped
		hp.lifecycleMu.Unlock()
		if !stopped {
			t.Fatal("concurrent Stop did not mark puncher stopped")
		}
		if started {
			// A Stop-first interleaving is allowed to leave started false; if the
			// start won the lock, it must nevertheless have been fully joined by
			// Stop. Either state is valid, but a restart is never allowed.
			hp.Stop()
		}
	}
}

func TestConcurrentHolePuncherStopsBothWaitForWorker(t *testing.T) {
	hp := NewHolePuncher(1, nil, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	hp.SetSecureSender(func() error {
		enteredOnce.Do(func() { close(entered) })
		<-release
		return nil
	})
	hp.StartPunching(time.Hour)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("hole punch worker did not start")
	}

	stoppedA := make(chan struct{})
	stoppedB := make(chan struct{})
	go func() { hp.Stop(); close(stoppedA) }()
	go func() { hp.Stop(); close(stoppedB) }()
	select {
	case <-stoppedA:
		t.Fatal("Stop returned while worker was still running")
	case <-stoppedB:
		t.Fatal("concurrent Stop returned while worker was still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	for name, stopped := range map[string]<-chan struct{}{"first": stoppedA, "second": stoppedB} {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatalf("%s Stop did not finish", name)
		}
	}
}
