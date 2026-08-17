package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"left4proxy/pkg/protocol"
	"left4proxy/pkg/security"
)

func transportSessions(t *testing.T) (*security.Session, *security.Session) {
	t.Helper()
	key := bytes.Repeat([]byte{0x5a}, security.KeySize)
	reqPkt, pending, err := security.NewHandshakeRequest(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	req, err := security.VerifyHandshakeRequest(key, reqPkt, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	respPkt, server, err := security.NewHandshakeResponse(key, req, 77, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, client, err := security.VerifyHandshakeResponse(key, respPkt, pending, time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	} else {
		return client, server
	}
	return nil, nil
}

func TestSecureUDPTransportEncryptsAndAuthenticates(t *testing.T) {
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	clientSession, serverSession := transportSessions(t)
	client, err := NewSecureUDPTransport(clientConn, serverConn.LocalAddr().(*net.UDPAddr), clientSession, security.ClientToServer, security.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSecureUDPTransport(serverConn, clientConn.LocalAddr().(*net.UDPAddr), serverSession, security.ServerToClient, security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	payload := []byte("private game bytes")
	if err := client.Send(protocol.NewPacket(protocol.CmdData, 0, 0, payload)); err != nil {
		t.Fatal(err)
	}
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	opened, err := server.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Payload, payload) || opened.SessionID != serverSession.ID || opened.Seq == 0 {
		t.Fatalf("unexpected opened packet: %#v", opened)
	}
}

func TestSecureUDPTransportUsesConnectedPeerAsTarget(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	clientSession, serverSession := transportSessions(t)
	defer serverSession.Close()
	transport, err := NewSecureUDPTransport(conn, nil, clientSession, security.ClientToServer, security.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	remote, ok := transport.RemoteAddr().(*net.UDPAddr)
	if !ok || !sameUDPAddr(remote, peer.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("RemoteAddr = %v, want connected peer %v", remote, peer.LocalAddr())
	}
	payload := []byte("connected socket payload")
	if err := transport.Send(protocol.NewPacket(protocol.CmdData, 0, 0, payload)); err != nil {
		t.Fatalf("Send on connected UDP socket failed: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("connected peer did not receive packet: %v", err)
	}
	opened, err := serverSession.Open(buf[:n], security.ClientToServer)
	if err != nil {
		t.Fatalf("connected peer could not authenticate packet: %v", err)
	}
	if !bytes.Equal(opened.Payload, payload) {
		t.Fatalf("opened payload = %q, want %q", opened.Payload, payload)
	}
}

func TestSecureUDPTransportRejectsTargetDifferentFromConnectedPeer(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	clientSession, serverSession := transportSessions(t)
	defer clientSession.Close()
	defer serverSession.Close()

	peerPort := peer.LocalAddr().(*net.UDPAddr).Port
	wrongPort := peerPort + 1
	if wrongPort > 65535 {
		wrongPort = peerPort - 1
	}
	wrongTarget := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: wrongPort}
	if _, err := NewSecureUDPTransport(conn, wrongTarget, clientSession, security.ClientToServer, security.ServerToClient); err == nil {
		t.Fatal("connected UDP socket accepted a target different from its peer")
	}
}

func TestSecureUDPTransportOwnsSequenceNumbers(t *testing.T) {
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	clientSession, serverSession := transportSessions(t)
	client, err := NewSecureUDPTransport(clientConn, serverConn.LocalAddr().(*net.UDPAddr), clientSession, security.ClientToServer, security.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := NewSecureUDPTransport(serverConn, clientConn.LocalAddr().(*net.UDPAddr), serverSession, security.ServerToClient, security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if err := client.Send(protocol.NewPacket(protocol.CmdPing, 0, 12345, []byte("one"))); err != nil {
		t.Fatal(err)
	}
	if err := client.Send(protocol.NewPacket(protocol.CmdPing, 0, 12345, []byte("two"))); err != nil {
		t.Fatal(err)
	}
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	first, err := server.Receive()
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq == second.Seq {
		t.Fatalf("transport reused caller-supplied sequence %d", first.Seq)
	}
}

func TestSecureUDPTransportDoesNotBindToUnauthenticatedFirstDatagram(t *testing.T) {
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	attacker, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	clientSession, serverSession := transportSessions(t)
	server, err := NewSecureUDPTransport(serverConn, nil, serverSession, security.ServerToClient, security.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if _, err := attacker.WriteToUDP([]byte("forged"), serverConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	// Let the forged datagram enter the receive queue first so the test checks
	// the exact first-packet binding order rather than scheduler timing.
	time.Sleep(10 * time.Millisecond)
	if err := (&SecureUDPTransport{conn: clientConn, targetAddr: serverConn.LocalAddr().(*net.UDPAddr), session: clientSession, sendDirection: security.ClientToServer, recvDirection: security.ServerToClient}).Send(protocol.NewPacket(protocol.CmdPing, 0, 0, []byte("valid"))); err != nil {
		t.Fatal(err)
	}
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Receive(); err == nil {
		t.Fatal("forged first datagram was accepted")
	}
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	opened, err := server.Receive()
	if err != nil {
		t.Fatalf("valid packet after forged first datagram was rejected: %v", err)
	}
	if string(opened.Payload) != "valid" {
		t.Fatalf("opened payload = %q", opened.Payload)
	}
}
