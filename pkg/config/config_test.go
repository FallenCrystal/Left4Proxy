package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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
	if serverCfg.EnableUPnP {
		t.Fatal("UPnP should be opt-in in the default server configuration")
	}
	if want := filepath.Join(dir, ".secret"); clientCfg.SecretPath != want {
		t.Fatalf("secret path = %q, want %q", clientCfg.SecretPath, want)
	}
}

func TestServerUPnPConfigCanBeEnabledExplicitly(t *testing.T) {
	dir := t.TempDir()
	serverPath := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(serverPath, []byte("enable_upnp: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The loader creates/loads the shared key next to the config; this test is
	// about the explicit boolean rather than secret provisioning.
	if _, err := LoadServerConfig(serverPath); err != nil {
		t.Fatalf("load server config: %v", err)
	}
	cfg, err := LoadServerConfig(serverPath)
	if err != nil {
		t.Fatalf("reload server config: %v", err)
	}
	if !cfg.EnableUPnP {
		t.Fatal("explicit enable_upnp=true was not preserved")
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

func TestUnknownConfigFieldsRejected(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		contents string
		load     func(string) error
	}{
		{
			name:     "client",
			filename: "client.yaml",
			contents: "server_adrs: [127.0.0.1:27014]\n",
			load: func(path string) error {
				_, err := LoadClientConfig(path)
				return err
			},
		},
		{
			name:     "server",
			filename: "server.yaml",
			contents: "listen_adrr: :27014\n",
			load: func(path string) error {
				_, err := LoadServerConfig(path)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.filename)
			if err := os.WriteFile(path, []byte(tt.contents), 0600); err != nil {
				t.Fatal(err)
			}
			err := tt.load(path)
			if err == nil {
				t.Fatal("unknown configuration field was accepted")
			}
			if !strings.Contains(err.Error(), "field") || !strings.Contains(err.Error(), "not found") {
				t.Fatalf("unexpected error for unknown field: %v", err)
			}
		})
	}
}

func TestEmptyServerConfigUsesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("empty config should use defaults: %v", err)
	}
	if cfg.ListenAddr != ":27014" || cfg.TargetAddr != "127.0.0.1:27015" {
		t.Fatalf("empty config defaults were not preserved: %#v", cfg)
	}
	if len(cfg.ProxyTrustedAddrs) != 1 || cfg.ProxyTrustedAddrs[0] != "127.0.0.1" {
		t.Fatalf("default proxy trusted addrs = %#v, want only 127.0.0.1", cfg.ProxyTrustedAddrs)
	}
}

func TestServerConfigLoadsProxyProtocolSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	data := []byte("proxy_protocol_v2: true\nproxy_protocol_trusted_addrs:\n  - 127.0.0.1\n  - 10.0.0.0/8\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	if !cfg.ProxyProtocolV2 {
		t.Fatal("proxy_protocol_v2=true was not loaded")
	}
	want := []string{"127.0.0.1", "10.0.0.0/8"}
	if strings.Join(cfg.ProxyTrustedAddrs, ",") != strings.Join(want, ",") {
		t.Fatalf("proxy trusted addrs = %#v, want %#v", cfg.ProxyTrustedAddrs, want)
	}

	emptyPath := filepath.Join(t.TempDir(), "empty-proxy-whitelist.yaml")
	if err := os.WriteFile(emptyPath, []byte("proxy_protocol_v2: true\nproxy_protocol_trusted_addrs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	emptyCfg, err := LoadServerConfig(emptyPath)
	if err != nil {
		t.Fatalf("load explicit empty proxy whitelist: %v", err)
	}
	if emptyCfg.ProxyTrustedAddrs == nil || len(emptyCfg.ProxyTrustedAddrs) != 0 {
		t.Fatalf("explicit empty proxy whitelist became %#v", emptyCfg.ProxyTrustedAddrs)
	}
}

func TestMultipleYAMLDocumentsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	data := []byte("listen_addr: :27014\n---\ntarget_addr: 127.0.0.1:27016\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadServerConfig(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("multiple YAML documents error = %v", err)
	}
}

func TestGetServerAddrsTrimsAndDeduplicates(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerAddrs = []string{"  example.com:27014  ", "example.com:27014", "   "}
	got := cfg.GetServerAddrs()
	if len(got) != 1 || got[0] != "example.com:27014" {
		t.Fatalf("GetServerAddrs() = %#v", got)
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
