package config

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"left4proxy/pkg/security"
)

func TestServerCreatesSecretAndClientLoadsSameKey(t *testing.T) {
	dir := t.TempDir()
	serverPath := filepath.Join(dir, "server.yaml")
	serverCfg, err := LoadServerConfig(serverPath)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	if len(serverCfg.AuthKey) != security.KeySize {
		t.Fatalf("server key length = %d", len(serverCfg.AuthKey))
	}

	clientPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(clientPath, []byte("server_addrs: [127.0.0.1:27014]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	clientCfg, err := LoadClientConfig(clientPath)
	if err != nil {
		t.Fatalf("load client config: %v", err)
	}
	if !bytes.Equal(clientCfg.AuthKey, serverCfg.AuthKey) {
		t.Fatal("client did not load the server's shared key")
	}
	if want := filepath.Join(dir, ".secret"); clientCfg.SecretPath != want {
		t.Fatalf("secret path = %q, want %q", clientCfg.SecretPath, want)
	}
}

func TestLegacyStringSecretRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("secret: old-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("legacy string secret was accepted")
	}
}

func TestConcurrentSecretCreationDoesNotReplaceWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".secret")
	keys := make([][]byte, 8)
	errs := make([]error, len(keys))
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = security.LoadSecret(path, true)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("creator %d: %v", i, err)
		}
		if !bytes.Equal(keys[0], keys[i]) {
			t.Fatalf("creator %d observed a different key", i)
		}
	}
}
