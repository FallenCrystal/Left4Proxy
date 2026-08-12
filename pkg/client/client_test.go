package client

import (
	"net"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/server"
)

func TestClientServerIntegration(t *testing.T) {
	// 1. Setup mock upstream L4D2 server
	upstreamConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 27015})
	if err != nil {
		t.Fatalf("failed to listen on mock upstream 127.0.0.1:27015: %v", err)
	}
	defer upstreamConn.Close()

	// 2. Start Left4Proxy Server on :27014 with advertised public_ips
	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = "127.0.0.1:27014"
	serverCfg.TargetAddr = "127.0.0.1:27015"
	serverCfg.PublicIPs = []string{"127.0.0.1:27014"}

	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// 3. Start Left4Proxy Client on 127.0.0.2:27015 -> 127.0.0.1:27014
	clientCfg := config.DefaultClientConfig()
	clientCfg.ServerAddrs = []string{"127.0.0.1:27014"}
	clientCfg.ListenAddr = "127.0.0.2:27015"
	clientCfg.EnableLAN = true

	cli, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer cli.Stop()

	time.Sleep(500 * time.Millisecond)

	// 4. Send Source Engine A2S_INFO query UDP packet from mock game client to 127.0.0.2:27015
	mockGameConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 27015})
	if err != nil {
		t.Fatalf("failed to dial local client 127.0.0.2:27015: %v", err)
	}
	defer mockGameConn.Close()

	a2sQuery := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'T', 'S', 'o', 'u', 'r', 'c', 'e', ' ', 'E', 'n', 'g', 'i', 'n', 'e', ' ', 'Q', 'u', 'e', 'r', 'y', 0x00}
	_, err = mockGameConn.Write(a2sQuery)
	if err != nil {
		t.Fatalf("failed to write A2S_INFO packet to client listener: %v", err)
	}

	// 5. Verify upstream server receives packet
	buf := make([]byte, 1024)
	_ = upstreamConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, srcAddr, err := upstreamConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("upstream server failed to receive proxied L4D2 packet: %v", err)
	}

	if n < len(a2sQuery) {
		t.Fatalf("expected packet size >= %d, got %d", len(a2sQuery), n)
	}
	t.Logf("Successfully proxied L4D2 packet through Left4Proxy! Received %d bytes from %s", n, srcAddr.String())
}
