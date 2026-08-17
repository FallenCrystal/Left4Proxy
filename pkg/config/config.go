package config

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"left4proxy/pkg/security"
)

const DefaultServerConfigPath = "config.server.yaml"
const DefaultClientConfigPath = "config.client.yaml"

// DefaultPublicStunServer is used when no stun_server is configured. It must
// be reachable over outbound UDP 3478.
const DefaultPublicStunServer = "stun.cloudflare.com:3478"

// ClientConfig holds settings for the Left4Proxy client.
type ClientConfig struct {
	ServerAddrs  []string `yaml:"server_addrs"`  // Server external IPs/domains
	ListenAddr   string   `yaml:"listen_addr"`   // Local listen address for L4D2 client (default: 127.0.0.2:27015)
	Mode         string   `yaml:"mode"`          // Mode: auto, direct-only, relay-only
	AuthKey      []byte   `yaml:"-"`             // Shared key loaded from .secret.
	SecretPath   string   `yaml:"-"`             // Resolved alongside the YAML file.
	EnableLAN    bool     `yaml:"enable_lan"`    // Enable LAN detection (default: true)
	EnablePunch  bool     `yaml:"enable_punch"`  // Enable UDP hole punching (default: true)
	PingInterval int      `yaml:"ping_interval"` // Ping probe interval in seconds (default: 3)
	StunServer   string   `yaml:"stun_server"`   // Public STUN server for punch-socket reflection (default: stun.cloudflare.com:3478)
}

// ServerConfig holds settings for the Left4Proxy server.
type ServerConfig struct {
	ListenAddr string   `yaml:"listen_addr"` // Listen address for clients (default: :27014)
	TargetAddr string   `yaml:"target_addr"` // Upstream L4D2 server address (default: 127.0.0.1:27015)
	EnableUPnP bool     `yaml:"enable_upnp"` // Enable automatic UPnP port mapping (default: false)
	AuthKey    []byte   `yaml:"-"`           // Shared key loaded from .secret.
	SecretPath string   `yaml:"-"`           // Resolved alongside the YAML file.
	PublicIPs  []string `yaml:"public_ips"`  // Direct server IPs/domains announced to clients.
	StunServer string   `yaml:"stun_server"` // Public STUN server used to discover the server's own public endpoint (default: stun.cloudflare.com:3478)
	PunchAddr  string   `yaml:"punch_addr"`  // Manual override for the server's public punch endpoint (ip:port); empty = auto STUN discovery
}

// DefaultClientConfig returns default client settings.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerAddrs:  []string{"127.0.0.1:27014"},
		ListenAddr:   "127.0.0.2:27015",
		Mode:         "auto",
		EnableLAN:    true,
		EnablePunch:  true,
		PingInterval: 3,
		StunServer:   DefaultPublicStunServer,
	}
}

// DefaultServerConfig returns default server settings.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr: ":27014",
		TargetAddr: "127.0.0.1:27015",
		// UPnP changes router state and can expose a UDP port.  Keep it opt-in;
		// operators who want automatic mapping can enable it explicitly.
		EnableUPnP: false,
		PublicIPs:  []string{},
		StunServer: DefaultPublicStunServer,
		PunchAddr:  "",
	}
}

// GetServerAddrs returns a deduplicated list of all configured server addresses.
func (c *ClientConfig) GetServerAddrs() []string {
	res := []string{}
	seen := make(map[string]bool)

	for _, addr := range c.ServerAddrs {
		addr = strings.TrimSpace(addr)
		if addr != "" && !seen[addr] {
			res = append(res, addr)
			seen[addr] = true
		}
	}
	if len(res) == 0 {
		res = append(res, "127.0.0.1:27014")
	}
	return res
}

// LoadClientConfig loads client configuration and requires a shared .secret
// next to the YAML file.  A client never creates a key because doing so would
// silently produce a key that cannot match the server.
func LoadClientConfig(path string) (*ClientConfig, error) {
	path = normalizedConfigPath(path, DefaultClientConfigPath)
	cfg := DefaultClientConfig()
	data, created, err := readOrCreateConfig(path, cfg, "# Left4Proxy Client Configuration\n\n")
	if err != nil {
		return nil, err
	}
	if created {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read newly created client config %s: %w", path, err)
		}
	}

	type rawClientConfig struct {
		ServerAddr   string   `yaml:"server_addr"`
		ServerAddrs  []string `yaml:"server_addrs"`
		ListenAddr   string   `yaml:"listen_addr"`
		Mode         string   `yaml:"mode"`
		LegacySecret string   `yaml:"secret"`
		EnableLAN    *bool    `yaml:"enable_lan"`
		EnablePunch  *bool    `yaml:"enable_punch"`
		PingInterval int      `yaml:"ping_interval"`
		StunServer   string   `yaml:"stun_server"`
	}
	var raw rawClientConfig
	if err := decodeConfigYAML(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse client config YAML %s: %w", path, err)
	}
	if err := rejectLegacySecret(raw.LegacySecret, path); err != nil {
		return nil, err
	}
	cfg.ListenAddr = raw.ListenAddr
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.2:27015"
	}
	cfg.Mode = raw.Mode
	if cfg.Mode == "" {
		cfg.Mode = "auto"
	}
	if raw.EnableLAN != nil {
		cfg.EnableLAN = *raw.EnableLAN
	}
	if raw.EnablePunch != nil {
		cfg.EnablePunch = *raw.EnablePunch
	}
	if raw.PingInterval > 0 {
		cfg.PingInterval = raw.PingInterval
	}
	if raw.StunServer != "" {
		cfg.StunServer = raw.StunServer
	}
	if len(raw.ServerAddrs) > 0 {
		cfg.ServerAddrs = raw.ServerAddrs
	} else if raw.ServerAddr != "" {
		cfg.ServerAddrs = []string{raw.ServerAddr}
	}
	cfg.SecretPath = filepath.Join(filepath.Dir(path), ".secret")
	cfg.AuthKey, err = security.LoadSecret(cfg.SecretPath, false)
	if err != nil {
		return nil, fmt.Errorf("load client authentication key: %w", err)
	}
	log.Printf("[Config] Loaded client configuration from: %s", path)
	return cfg, nil
}

// LoadServerConfig loads server configuration.  The server creates the shared
// .secret on first start so the operator can copy it to clients.
func LoadServerConfig(path string) (*ServerConfig, error) {
	path = normalizedConfigPath(path, DefaultServerConfigPath)
	cfg := DefaultServerConfig()
	data, created, err := readOrCreateConfig(path, cfg, "# Left4Proxy Server Configuration\n\n")
	if err != nil {
		return nil, err
	}
	if created {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read newly created server config %s: %w", path, err)
		}
	}

	type rawServerConfig struct {
		ListenAddr   string   `yaml:"listen_addr"`
		TargetAddr   string   `yaml:"target_addr"`
		TargetAddrs  string   `yaml:"target_addrs"`
		EnableUPnP   *bool    `yaml:"enable_upnp"`
		LegacySecret string   `yaml:"secret"`
		PublicIPs    []string `yaml:"public_ips"`
		StunServer   string   `yaml:"stun_server"`
		PunchAddr    string   `yaml:"punch_addr"`
	}
	var raw rawServerConfig
	if err := decodeConfigYAML(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse server config YAML %s: %w", path, err)
	}
	if err := rejectLegacySecret(raw.LegacySecret, path); err != nil {
		return nil, err
	}
	if raw.ListenAddr != "" {
		cfg.ListenAddr = raw.ListenAddr
	}
	if raw.TargetAddrs != "" {
		cfg.TargetAddr = raw.TargetAddrs
	} else if raw.TargetAddr != "" {
		cfg.TargetAddr = raw.TargetAddr
	}
	if raw.EnableUPnP != nil {
		cfg.EnableUPnP = *raw.EnableUPnP
	}
	cfg.PublicIPs = raw.PublicIPs
	if raw.StunServer != "" {
		cfg.StunServer = raw.StunServer
	}
	cfg.PunchAddr = raw.PunchAddr
	cfg.SecretPath = filepath.Join(filepath.Dir(path), ".secret")
	cfg.AuthKey, err = security.LoadSecret(cfg.SecretPath, true)
	if err != nil {
		return nil, fmt.Errorf("load server authentication key: %w", err)
	}
	log.Printf("[Config] Loaded server configuration from: %s", path)
	return cfg, nil
}

func decodeConfigYAML(data []byte, out any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("multiple YAML documents are not supported")
	}
	return nil
}

func normalizedConfigPath(path, fallback string) string {
	if strings.TrimSpace(path) == "" {
		path = fallback
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		return abs
	}
	return path
}

func readOrCreateConfig(path string, cfg any, header string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	outData, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("marshal default config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, false, fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(path, append([]byte(header), outData...), 0600); err != nil {
		return nil, false, fmt.Errorf("create default config file %s: %w", path, err)
	}
	log.Printf("[Config] Created default configuration file: %s", path)
	return nil, true, nil
}

func rejectLegacySecret(value, path string) error {
	if strings.TrimSpace(value) != "" {
		return fmt.Errorf("config %s contains legacy string secret; remove it and provision the shared .secret file", path)
	}
	if value != "" {
		log.Printf("[Config] Ignoring empty legacy secret field in %s; use .secret instead", path)
	}
	return nil
}
