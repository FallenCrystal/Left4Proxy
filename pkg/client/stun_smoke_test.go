package client

import (
	"net"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/server"
)

// TestStunReflectionRoundTrip verifies the STUN probe/ack round-trip works
// locally (no frp). Regression test: SendProbe used to call conn.WriteToUDP on
// a net.DialUDP (connected) socket, which fails with "use of WriteTo with
// pre-connected connection" — so no probe was ever sent.
func TestStunReflectionRoundTrip(t *testing.T) {
	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = "127.0.0.1:28115"
	serverCfg.TargetAddr = "127.0.0.1:28116" // dummy upstream, never used
	serverCfg.AuthKey = integrationKey()
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	clientCfg := config.DefaultClientConfig()
	clientCfg.ServerAddrs = []string{"127.0.0.1:28115"}
	clientCfg.ListenAddr = "127.0.0.1:28117"
	clientCfg.EnablePunch = true
	clientCfg.AuthKey = serverCfg.AuthKey
	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer cli.Stop()

	time.Sleep(1200 * time.Millisecond)

	cli.candidateMu.RLock()
	defer cli.candidateMu.RUnlock()
	for _, c := range cli.candidates {
		c.mu.RLock()
		refl := c.lastReflected
		online := c.online
		c.mu.RUnlock()
		t.Logf("candidate %s -> online=%v lastReflected=%q", c.addrStr, online, refl)
		if refl == "" {
			t.Errorf("candidate %s: STUN reflection never arrived", c.addrStr)
		}
		if _, _, err := net.SplitHostPort(refl); err != nil {
			t.Errorf("candidate %s: reflected %q is not ip:port: %v", c.addrStr, refl, err)
		}
	}
}
