package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"left4proxy/pkg/stun"
)

// CLI provides an interactive command line interface to control and inspect the Client.
type CLI struct {
	client  *Client
	in      io.Reader
	out     io.Writer
	onQuit  func()
	version string
}

// NewCLI creates a new interactive CLI handler.
func NewCLI(client *Client, in io.Reader, out io.Writer, onQuit func(), version string) *CLI {
	return &CLI{
		client:  client,
		in:      in,
		out:     out,
		onQuit:  onQuit,
		version: version,
	}
}

// Run executes the command reading loop until context is canceled, EOF is encountered, or quit is triggered.
func (c *CLI) Run(ctx context.Context) {
	scanner := bufio.NewScanner(c.in)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !scanner.Scan() {
			// Stdin closed (EOF) or reading error: exit CLI loop quietly without terminating the whole program.
			return
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		c.Execute(line)
	}
}

// Execute parses and runs a single command string.
func (c *CLI) Execute(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "status", "st", "s", "info":
		fmt.Fprintln(c.out, c.client.FormatStatus())

	case "ping", "probe", "p", "refresh":
		fmt.Fprintln(c.out, "[CLI] Probing all server candidates...")
		c.client.Probe()
		fmt.Fprintln(c.out, c.client.FormatStatus())

	case "mode", "m":
		if len(args) == 0 {
			fmt.Fprintf(c.out, "Current routing mode: %s (Available: auto, direct-only, relay-only)\n", c.client.GetMode())
		} else {
			targetMode := strings.ToLower(args[0])
			if err := c.client.SetMode(targetMode); err != nil {
				fmt.Fprintf(c.out, "Error: %v\n", err)
			} else {
				fmt.Fprintf(c.out, "Routing mode set to: %s\n", c.client.GetMode())
			}
		}

	case "nat":
		fmt.Fprintln(c.out, "[CLI] Detecting STUN NAT mapping behavior...")
		info := c.client.DetectNAT()
		if info != nil {
			fmt.Fprintf(c.out, "NAT Summary       : %s\n", stun.FormatNATSummary(info))
			fmt.Fprintf(c.out, "Mapping Behavior  : %s\n", info.Behavior)
			if info.PrimaryAddr != nil {
				fmt.Fprintf(c.out, "Primary Reflected : %s\n", info.PrimaryAddr)
			}
			if info.SecondaryAddr != nil {
				fmt.Fprintf(c.out, "Secondary Reflect : %s\n", info.SecondaryAddr)
			}
			if info.PortDelta != 0 {
				fmt.Fprintf(c.out, "Port Delta        : %+d\n", info.PortDelta)
			}
		} else {
			fmt.Fprintln(c.out, "NAT Detection failed (STUN servers unreachable)")
		}

	case "candidates", "list", "ls":
		c.printCandidates()

	case "version", "ver", "v":
		fmt.Fprintf(c.out, "Left4Proxy Client v%s\n", c.version)

	case "help", "h", "?":
		c.printHelp()

	case "quit", "exit", "q":
		fmt.Fprintln(c.out, "[CLI] Exiting Left4Proxy Client...")
		if c.onQuit != nil {
			c.onQuit()
		}

	default:
		fmt.Fprintf(c.out, "Unknown command: %q. Type 'help' for available commands.\n", line)
	}
}

func (c *CLI) printCandidates() {
	st := c.client.Status()
	fmt.Fprintf(c.out, "\nServer Candidates (%d):\n", len(st.Candidates))
	for i, cand := range st.Candidates {
		activeTag := " "
		if cand.IsActive {
			activeTag = "*"
		}
		status := "Offline"
		rtt := "N/A"
		if cand.Online {
			status = "Online"
			if cand.RTT > 0 && cand.RTT < 900*time.Millisecond {
				rtt = fmt.Sprintf("%.1fms", float64(cand.RTT)/float64(time.Millisecond))
			}
		}
		fmt.Fprintf(c.out, " %s [%d] %-7s %-25s | Status: %-7s | RTT: %s\n",
			activeTag, i+1, fmt.Sprintf("[%s]", cand.PathType), cand.Addr, status, rtt)
	}
	fmt.Fprintln(c.out)
}

func (c *CLI) printHelp() {
	helpText := `
Left4Proxy Client Commands:
  status, st, s, info         Display full connection, routing, NAT type, and candidates status
  ping, probe, p, refresh     Proactively probe all candidate endpoints and update routes
  nat                         Run STUN NAT type detection and show detailed mapping behavior
  mode [auto|direct|relay]    View current mode or switch route mode dynamically
  candidates, list, ls        List all known server candidates
  version, ver, v             Show client version
  help, h, ?                  Show this help menu
  quit, exit, q               Gracefully shutdown and exit
`
	fmt.Fprintln(c.out, strings.TrimSpace(helpText))
}
