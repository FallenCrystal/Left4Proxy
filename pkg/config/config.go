package config

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
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
	Secret       string   `yaml:"secret"`        // Shared secret / token for authentication (optional)
	EnableLAN    bool     `yaml:"enable_lan"`    // Enable LAN detection (default: true)
	EnablePunch  bool     `yaml:"enable_punch"`  // Enable UDP hole punching (default: true)
	PingInterval int      `yaml:"ping_interval"` // Ping probe interval in seconds (default: 3)
	StunServer   string   `yaml:"stun_server"`   // Public STUN server for punch-socket reflection (default: stun.cloudflare.com:3478)
}

// ServerConfig holds settings for the Left4Proxy server.
type ServerConfig struct {
	ListenAddr      string   `yaml:"listen_addr"`       // Listen address for clients (default: :27014)
	TargetAddr      string   `yaml:"target_addr"`       // Upstream L4D2 server address (default: 127.0.0.1:27015)
	ProxyProtocolV2 bool     `yaml:"proxy_protocol_v2"` // Enable PROXY Protocol v1/v2 parsing from frp/HAProxy
	Secret          string   `yaml:"secret"`            // Shared secret / token for authentication (optional)
	PublicIPs       []string `yaml:"public_ips"`        // List of server public IPs/domains to announce
	DirectPortRange string   `yaml:"direct_port_range"` // Direct STUN / hole-punch port range or explicit port
	NAT             string   `yaml:"nat"`               // "auto" (default) | "true" | "false" — whether the server sits behind NAT (no public IP)
	StunServer      string   `yaml:"stun_server"`       // Public STUN server used to discover the server's own public endpoint (default: stun.cloudflare.com:3478)
	PunchAddr       string   `yaml:"punch_addr"`        // Manual override for the server's public punch endpoint (ip:port); empty = auto STUN discovery
}

// DefaultClientConfig returns default client settings.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerAddrs:  []string{"127.0.0.1:27014"},
		ListenAddr:   "127.0.0.2:27015",
		Mode:         "auto",
		Secret:       "",
		EnableLAN:    true,
		EnablePunch:  true,
		PingInterval: 3,
		StunServer:   DefaultPublicStunServer,
	}
}

// DefaultServerConfig returns default server settings.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:      ":27014",
		TargetAddr:      "127.0.0.1:27015",
		ProxyProtocolV2: false,
		Secret:          "",
		PublicIPs:       []string{},
		DirectPortRange: "27015",
		StunServer:      DefaultPublicStunServer,
		PunchAddr:       "",
	}
}

// GetServerAddrs returns a deduplicated list of all configured server addresses.
func (c *ClientConfig) GetServerAddrs() []string {
	res := []string{}
	seen := make(map[string]bool)

	for _, addr := range c.ServerAddrs {
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

// LoadClientConfig loads client configuration from YAML file, creating a default file if missing.
func LoadClientConfig(path string) (*ClientConfig, error) {
	if path == "" {
		path = DefaultClientConfigPath
	}

	cfg := DefaultClientConfig()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		outData, mErr := yaml.Marshal(cfg)
		if mErr == nil {
			commentHeader := "# Left4Proxy Client Configuration\n\n"
			_ = os.WriteFile(path, append([]byte(commentHeader), outData...), 0644)
			log.Printf("[Config] Created default client configuration file: %s", path)
		}
		return cfg, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read client config file %s: %w", path, err)
	}

	type rawClientConfig struct {
		ServerAddr   string   `yaml:"server_addr"`
		ServerAddrs  []string `yaml:"server_addrs"`
		ListenAddr   string   `yaml:"listen_addr"`
		Mode         string   `yaml:"mode"`
		Secret       string   `yaml:"secret"`
		EnableLAN    bool     `yaml:"enable_lan"`
		EnablePunch  bool     `yaml:"enable_punch"`
		PingInterval int      `yaml:"ping_interval"`
		StunServer   string   `yaml:"stun_server"`
	}

	var raw rawClientConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse client config YAML %s: %w", path, err)
	}

	cfg.ListenAddr = raw.ListenAddr
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.2:27015"
	}
	cfg.Mode = raw.Mode
	if cfg.Mode == "" {
		cfg.Mode = "auto"
	}
	cfg.Secret = raw.Secret
	cfg.EnableLAN = raw.EnableLAN
	cfg.EnablePunch = raw.EnablePunch
	if raw.PingInterval > 0 {
		cfg.PingInterval = raw.PingInterval
	}
	if raw.StunServer != "" {
		cfg.StunServer = raw.StunServer
	}

	cfg.ServerAddrs = []string{}
	if len(raw.ServerAddrs) > 0 {
		cfg.ServerAddrs = raw.ServerAddrs
	} else if raw.ServerAddr != "" {
		cfg.ServerAddrs = []string{raw.ServerAddr}
	} else {
		cfg.ServerAddrs = []string{"127.0.0.1:27014"}
	}

	log.Printf("[Config] Loaded client configuration from: %s", path)
	return cfg, nil
}

// LoadServerConfig loads server configuration from YAML file, creating a default file if missing.
func LoadServerConfig(path string) (*ServerConfig, error) {
	if path == "" {
		path = DefaultServerConfigPath
	}

	cfg := DefaultServerConfig()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		outData, mErr := yaml.Marshal(cfg)
		if mErr == nil {
			commentHeader := "# Left4Proxy Server Configuration\n\n"
			_ = os.WriteFile(path, append([]byte(commentHeader), outData...), 0644)
			log.Printf("[Config] Created default server configuration file: %s", path)
		}
		return cfg, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read server config file %s: %w", path, err)
	}

	type rawServerConfig struct {
		ListenAddr      string   `yaml:"listen_addr"`
		TargetAddr      string   `yaml:"target_addr"`
		TargetAddrs     string   `yaml:"target_addrs"`
		ProxyProtocolV2 bool     `yaml:"proxy_protocol_v2"`
		Secret          string   `yaml:"secret"`
		PublicIPs       []string `yaml:"public_ips"`
		DirectPortRange string   `yaml:"direct_port_range"`
		NAT             string   `yaml:"nat"`
		StunServer      string   `yaml:"stun_server"`
		PunchAddr       string   `yaml:"punch_addr"`
	}

	var raw rawServerConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse server config YAML %s: %w", path, err)
	}

	if raw.ListenAddr != "" {
		cfg.ListenAddr = raw.ListenAddr
	}
	if raw.TargetAddrs != "" {
		cfg.TargetAddr = raw.TargetAddrs
	} else if raw.TargetAddr != "" {
		cfg.TargetAddr = raw.TargetAddr
	}
	cfg.ProxyProtocolV2 = raw.ProxyProtocolV2
	cfg.Secret = raw.Secret
	cfg.PublicIPs = raw.PublicIPs
	cfg.DirectPortRange = raw.DirectPortRange
	cfg.NAT = raw.NAT
	if raw.StunServer != "" {
		cfg.StunServer = raw.StunServer
	}
	cfg.PunchAddr = raw.PunchAddr

	log.Printf("[Config] Loaded server configuration from: %s", path)
	return cfg, nil
}
