package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"left4proxy/pkg/client"
	"left4proxy/pkg/config"
)

const Version = "1.0.0"

func main() {
	var (
		configFile  string
		serverAddr  string
		listenAddr  string
		mode        string
		stunServer  string
		showVersion bool
	)

	flag.StringVar(&configFile, "c", "", "Path to YAML configuration file")
	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.StringVar(&serverAddr, "s", "", "Remote Left4Proxy server address override (e.g. 1.2.3.4:27014)")
	flag.StringVar(&serverAddr, "server", "", "Remote Left4Proxy server address override (e.g. 1.2.3.4:27014)")
	flag.StringVar(&listenAddr, "l", "", "Local listen address override (default: 127.0.0.2:27015)")
	flag.StringVar(&listenAddr, "listen", "", "Local listen address override (default: 127.0.0.2:27015)")
	flag.StringVar(&mode, "m", "", "Route mode override: auto, direct-only, relay-only")
	flag.StringVar(&mode, "mode", "", "Route mode override: auto, direct-only, relay-only")
	flag.StringVar(&stunServer, "stun-server", "", "Public STUN server for punch-socket reflection")
	flag.BoolVar(&showVersion, "v", false, "Show version")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Parse()

	if showVersion {
		fmt.Printf("Left4Proxy Client v%s\n", Version)
		os.Exit(0)
	}

	setFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	cfg, err := config.LoadClientConfig(configFile)
	if err != nil {
		log.Fatalf("Error loading client config: %v", err)
	}

	// CLI flags override config file values ONLY if explicitly specified on command line
	if setFlags["s"] || setFlags["server"] {
		cfg.ServerAddrs = []string{serverAddr}
	}
	if setFlags["l"] || setFlags["listen"] {
		cfg.ListenAddr = listenAddr
	}
	if setFlags["m"] || setFlags["mode"] {
		cfg.Mode = mode
	}
	if setFlags["stun-server"] {
		cfg.StunServer = stunServer
	}

	cli, err := client.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	if err := cli.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	log.Println("[Client] Shutting down...")
	cli.Stop()
}
