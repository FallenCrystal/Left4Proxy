package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"left4proxy/pkg/config"
	"left4proxy/pkg/server"
)

const Version = "1.0.0"

func main() {
	var (
		configFile      string
		listenAddr      string
		targetAddr      string
		proxyProtocolV2 bool
		showVersion     bool
	)

	flag.StringVar(&configFile, "c", "", "Path to YAML configuration file")
	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.StringVar(&listenAddr, "l", "", "Listen address override (e.g. :27014)")
	flag.StringVar(&listenAddr, "listen", "", "Listen address override (e.g. :27014)")
	flag.StringVar(&targetAddr, "u", "", "Upstream L4D2 server target override (e.g. 127.0.0.1:27015)")
	flag.StringVar(&targetAddr, "target", "", "Upstream L4D2 server target override (e.g. 127.0.0.1:27015)")
	flag.BoolVar(&proxyProtocolV2, "proxy-protocol", false, "Enable PROXY protocol v1/v2 parsing from frp/HAProxy")
	flag.BoolVar(&showVersion, "v", false, "Show version")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Parse()

	if showVersion {
		fmt.Printf("Left4Proxy Server v%s\n", Version)
		os.Exit(0)
	}

	setFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	cfg, err := config.LoadServerConfig(configFile)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// CLI flags override config file values ONLY if explicitly specified on command line
	if setFlags["l"] || setFlags["listen"] {
		cfg.ListenAddr = listenAddr
	}
	if setFlags["u"] || setFlags["target"] {
		cfg.TargetAddr = targetAddr
	}
	if setFlags["proxy-protocol"] {
		cfg.ProxyProtocolV2 = proxyProtocolV2
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	log.Println("[Server] Shutting down...")
	srv.Stop()
}
