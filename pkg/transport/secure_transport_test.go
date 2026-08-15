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
