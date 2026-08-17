package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"left4proxy/pkg/router"
	"left4proxy/pkg/stun"
	"left4proxy/pkg/termui"
)

const (
	pingHistorySize = 60
	pingGraphWidth  = 60
	pingGraphHeight = 8
)

// CLI provides an interactive command line interface to control and inspect the Client.
type CLI struct {
	client  *Client
	in      io.Reader
	out     io.Writer
	onQuit  func()
	version string

	outputMu    sync.Mutex
	graphMu     sync.Mutex
	graphCtx    context.Context
	graphCancel context.CancelFunc
	graphDone   chan struct{}
	graphColor  bool
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
	if ctx == nil {
		ctx = context.Background()
	}
	c.graphMu.Lock()
	c.graphCtx = ctx
	c.graphMu.Unlock()
	defer c.stopPingGraph(false)

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
		c.write(c.client.FormatStatus())

	case "ping":
		if len(args) > 0 && (strings.EqualFold(args[0], "stop") || strings.EqualFold(args[0], "off")) {
			c.stopPingGraph(true)
		} else {
			c.togglePingGraph()
		}

	case "probe", "p", "refresh":
		c.write("[CLI] Probing all server candidates...\n")
		c.client.Probe()
		c.write(c.client.FormatStatus())

	case "mode", "m":
		if len(args) == 0 {
			c.writef("Current routing mode: %s (Available: auto, direct-only, relay-only)\n", c.client.GetMode())
		} else {
			targetMode := strings.ToLower(args[0])
			if err := c.client.SetMode(targetMode); err != nil {
				c.writef("Error: %v\n", err)
			} else {
				c.writef("Routing mode set to: %s\n", c.client.GetMode())
			}
		}

	case "nat":
		c.write("[CLI] Detecting STUN NAT mapping behavior...\n")
		info := c.client.DetectNAT()
		if info != nil {
			c.writef("NAT Summary       : %s\n", stun.FormatNATSummary(info))
			c.writef("Mapping Behavior  : %s\n", info.Behavior)
			if info.PrimaryAddr != nil {
				c.writef("Primary Reflected : %s\n", info.PrimaryAddr)
			}
			if info.SecondaryAddr != nil {
				c.writef("Secondary Reflect : %s\n", info.SecondaryAddr)
			}
			if info.PortDelta != 0 {
				c.writef("Port Delta        : %+d\n", info.PortDelta)
			}
		} else {
			c.write("NAT Detection failed (STUN servers unreachable)\n")
		}

	case "candidates", "list", "ls":
		c.printCandidates()

	case "version", "ver", "v":
		c.writef("Left4Proxy Client v%s\n", c.version)

	case "help", "h", "?":
		c.printHelp()

	case "quit", "exit", "q":
		c.stopPingGraph(false)
		c.write("[CLI] Exiting Left4Proxy Client...\n")
		if c.onQuit != nil {
			c.onQuit()
		}

	default:
		c.writef("Unknown command: %q. Type 'help' for available commands.\n", line)
	}
}

func (c *CLI) write(text string) {
	if c == nil || c.out == nil || text == "" {
		return
	}
	c.outputMu.Lock()
	defer c.outputMu.Unlock()
	_, _ = io.WriteString(c.out, termui.ColorizeCLI(text, termui.Enabled(c.out)))
}

func (c *CLI) writef(format string, args ...any) {
	c.write(fmt.Sprintf(format, args...))
}

func (c *CLI) writeRaw(text string) {
	if c == nil || c.out == nil || text == "" {
		return
	}
	c.outputMu.Lock()
	defer c.outputMu.Unlock()
	_, _ = io.WriteString(c.out, text)
}

func (c *CLI) printCandidates() {
	st := c.client.Status()
	var b strings.Builder
	fmt.Fprintf(&b, "\nServer Candidates (%d):\n", len(st.Candidates))
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
		fmt.Fprintf(&b, " %s [%d] %-7s %-25s | Status: %-7s | RTT: %-8s | Loss: %.1f%%\n",
			activeTag, i+1, fmt.Sprintf("[%s]", cand.PathType), cand.Addr, status, rtt, cand.LossRate*100)
	}
	fmt.Fprintln(&b)
	c.write(b.String())
}

func (c *CLI) printHelp() {
	helpText := `
Left4Proxy Client Commands:
  status, st, s, info         Display full connection, route, NAT, game, and candidate status
  ping [stop]                 Live RTT graph, game/L4P rates, route health, and game connection
  probe, p, refresh           Proactively probe all candidate endpoints and update routes
  nat                         Run STUN NAT type detection and show detailed mapping behavior
  mode [auto|direct|relay]    View current mode or switch route mode dynamically
  candidates, list, ls        List all known server candidates
  version, ver, v             Show client version
  help, h, ?                  Show this help menu
  quit, exit, q               Gracefully shutdown and exit

The ping view refreshes once per second. Type 'ping' again or 'ping stop' to leave it.
`
	c.write(strings.TrimSpace(helpText) + "\n")
}

type trafficRates struct {
	GameUpload   float64
	GameDownload float64
	L4PUpload    float64
	L4PDownload  float64
}

type pingSample struct {
	At            time.Time
	RTT           time.Duration
	LossRate      float64
	Online        bool
	GameConnected bool
	ActivePath    router.PathType
	ActiveTarget  string
	Rates         trafficRates
}

func (c *CLI) togglePingGraph() {
	c.graphMu.Lock()
	active := c.graphCancel != nil
	c.graphMu.Unlock()
	if active {
		c.stopPingGraph(true)
		return
	}
	c.startPingGraph()
}

func (c *CLI) startPingGraph() {
	if c == nil || c.client == nil {
		return
	}
	c.graphMu.Lock()
	if c.graphCancel != nil {
		c.graphMu.Unlock()
		return
	}
	parent := c.graphCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	c.graphCancel = cancel
	c.graphDone = done
	c.graphColor = termui.Enabled(c.out)
	graphColor := c.graphColor
	c.graphMu.Unlock()

	// A graph command is an active diagnostic: issue the first probe now and
	// let the one-second renderer continue refreshing it independently of the
	// background ping interval.
	c.client.ProbeCandidates()
	now := time.Now()
	previous := c.client.Traffic()
	initial := c.makePingSample(now, previous, previous, 0)
	history := []pingSample{initial}
	if graphColor {
		c.writeRaw("\x1b[?25l")
	}
	c.renderPingGraph(history, initial, graphColor)

	go c.runPingGraph(ctx, done, previous, now, history)
}

func (c *CLI) stopPingGraph(printMessage bool) {
	if c == nil {
		return
	}
	c.graphMu.Lock()
	cancel := c.graphCancel
	done := c.graphDone
	c.graphMu.Unlock()
	if cancel == nil {
		if printMessage {
			c.write("Ping graph is not running.\n")
		}
		return
	}
	cancel()
	if done != nil {
		<-done
	}

	c.graphMu.Lock()
	graphColor := c.graphColor
	if c.graphDone == done {
		c.graphCancel = nil
		c.graphDone = nil
		c.graphColor = false
	}
	c.graphMu.Unlock()
	if graphColor {
		c.writeRaw("\x1b[?25h\x1b[0m\n")
	}
	if printMessage {
		c.write("Ping graph stopped.\n")
	}
}

func (c *CLI) runPingGraph(ctx context.Context, done chan struct{}, previous TrafficSnapshot, previousAt time.Time, history []pingSample) {
	defer close(done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.client.ProbeCandidates()
			now := time.Now()
			current := c.client.Traffic()
			sample := c.makePingSample(now, current, previous, now.Sub(previousAt))
			previous = current
			previousAt = now
			history = append(history, sample)
			if len(history) > pingHistorySize {
				history = history[len(history)-pingHistorySize:]
			}
			c.renderPingGraph(history, sample, c.currentGraphColor())
		}
	}
}

func (c *CLI) currentGraphColor() bool {
	c.graphMu.Lock()
	defer c.graphMu.Unlock()
	return c.graphColor
}

func (c *CLI) makePingSample(now time.Time, current, previous TrafficSnapshot, elapsed time.Duration) pingSample {
	st := c.client.Status()
	return pingSample{
		At:            now,
		RTT:           st.ActiveRTT,
		LossRate:      st.ActiveLossRate,
		Online:        st.ActiveCandidate != "",
		GameConnected: st.GameConnected,
		ActivePath:    st.ActivePath,
		ActiveTarget:  st.ActiveCandidate,
		Rates:         trafficRatesFor(current, previous, elapsed),
	}
}

func trafficRatesFor(current, previous TrafficSnapshot, elapsed time.Duration) trafficRates {
	if elapsed <= 0 {
		return trafficRates{}
	}
	seconds := elapsed.Seconds()
	return trafficRates{
		GameUpload:   byteRate(current.GameUploadBytes, previous.GameUploadBytes, seconds),
		GameDownload: byteRate(current.GameDownloadBytes, previous.GameDownloadBytes, seconds),
		L4PUpload:    byteRate(current.L4PUploadBytes, previous.L4PUploadBytes, seconds),
		L4PDownload:  byteRate(current.L4PDownloadBytes, previous.L4PDownloadBytes, seconds),
	}
}

func byteRate(current, previous uint64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	if current < previous {
		return float64(current) / seconds
	}
	return float64(current-previous) / seconds
}

func (c *CLI) renderPingGraph(history []pingSample, current pingSample, color bool) {
	var b strings.Builder
	if color {
		b.WriteString("\x1b[H\x1b[2J")
	}
	b.WriteString(termui.Paint(termui.Bold+termui.Cyan, "╭─ Left4Proxy ping ─ live network quality ─────────────────────────────╮", color))
	b.WriteByte('\n')

	route := "offline"
	if current.Online {
		route = fmt.Sprintf("[%s] %s", current.ActivePath, current.ActiveTarget)
	}
	routeStyle := termui.Yellow
	if current.Online {
		routeStyle = termui.Green
	}
	fmt.Fprintf(&b, "│ Route   : %s\n", termui.Paint(routeStyle, route, color))

	connection := "idle / no game socket"
	if current.GameConnected {
		connection = "connected"
	}
	connectionStyle := termui.Yellow
	if current.GameConnected {
		connectionStyle = termui.Green
	}
	fmt.Fprintf(&b, "│ Game    : %s    RTT: %s    Loss: %s\n",
		termui.Paint(connectionStyle, connection, color),
		termui.Paint(rttStyle(current.RTT), formatRTT(current.RTT), color),
		termui.Paint(lossStyle(current.LossRate, current.Online), formatLoss(current.LossRate, current.Online), color))
	b.WriteString("│\n")
	b.WriteString("│ RTT graph (last 60s)\n")
	for _, line := range renderLatencyGraph(history, pingGraphWidth, pingGraphHeight, color) {
		fmt.Fprintf(&b, "│ %s\n", line)
	}
	b.WriteString("│\n")
	b.WriteString("│ Throughput (actual one-second rate)\n")
	maxRate := maxTrafficRate(current.Rates)
	writeRateLine(&b, "Game ↑", current.Rates.GameUpload, maxRate, color, termui.Cyan)
	writeRateLine(&b, "Game ↓", current.Rates.GameDownload, maxRate, color, termui.Blue)
	writeRateLine(&b, "L4P  ↑", current.Rates.L4PUpload, maxRate, color, termui.Magenta)
	writeRateLine(&b, "L4P  ↓", current.Rates.L4PDownload, maxRate, color, termui.Green)
	b.WriteString("│\n")
	b.WriteString("│ ")
	b.WriteString(termui.Paint(termui.Dim, "Game = payload at the local game socket; L4P = wire bytes across all candidate sockets.", color))
	b.WriteString("\n")
	b.WriteString("│ ")
	b.WriteString(termui.Paint(termui.Dim, "Type 'ping' again or 'ping stop' to leave this view.", color))
	b.WriteString("\n")
	b.WriteString(termui.Paint(termui.Bold+termui.Cyan, "╰──────────────────────────────────────────────────────────────────────╯", color))
	b.WriteByte('\n')
	if !color {
		b.WriteByte('\n')
	}
	c.writeRaw(b.String())
}

func renderLatencyGraph(history []pingSample, width, height int, color bool) []string {
	if width < 1 {
		width = 1
	}
	if height < 2 {
		height = 2
	}
	points := history
	if len(points) > width {
		points = points[len(points)-width:]
	}
	maxRTT := 100 * time.Millisecond
	for _, point := range points {
		if point.RTT > maxRTT {
			maxRTT = point.RTT
		}
	}
	// Keep the scale stable while values are below a 100ms boundary, then
	// expand it without clipping a spike at the top row.
	if maxRTT > 100*time.Millisecond {
		maxRTT = time.Duration(math.Ceil(float64(maxRTT)/float64(50*time.Millisecond))) * 50 * time.Millisecond
		if maxRTT == pointsMaxRTT(points) {
			maxRTT += 50 * time.Millisecond
		}
	}

	// One Braille cell contains a 2x4 pixel matrix. Mapping the history to
	// this higher-resolution canvas makes short, sharp RTT spikes visible as
	// actual pulses instead of a row of oversized text glyphs.
	pixelWidth := width * 2
	pixelHeight := height * 4
	masks := make([][]uint8, height)
	cellRTT := make([][]time.Duration, height)
	for row := 0; row < height; row++ {
		masks[row] = make([]uint8, width)
		cellRTT[row] = make([]time.Duration, width)
	}

	setPixel := func(x, y int, rtt time.Duration) {
		if x < 0 || x >= pixelWidth || y < 0 || y >= pixelHeight {
			return
		}
		cellX, cellY := x/2, y/4
		masks[cellY][cellX] |= brailleDotMask(x%2, y%4)
		if rtt > cellRTT[cellY][cellX] {
			cellRTT[cellY][cellX] = rtt
		}
	}

	drawLine := func(x0, y0, x1, y1 int, rtt time.Duration) {
		dx := int(math.Abs(float64(x1 - x0)))
		dy := -int(math.Abs(float64(y1 - y0)))
		sx, sy := -1, -1
		if x0 < x1 {
			sx = 1
		}
		if y0 < y1 {
			sy = 1
		}
		err := dx + dy
		for {
			setPixel(x0, y0, rtt)
			if x0 == x1 && y0 == y1 {
				return
			}
			e2 := 2 * err
			if e2 >= dy {
				err += dy
				x0 += sx
			}
			if e2 <= dx {
				err += dx
				y0 += sy
			}
		}
	}

	var previousX, previousY int
	var havePrevious bool
	for i, point := range points {
		if !point.Online || point.RTT <= 0 {
			havePrevious = false
			continue
		}
		x := pixelWidth - 1
		if len(points) > 1 {
			x = int(math.Round(float64(i) * float64(pixelWidth-1) / float64(len(points)-1)))
		}
		y := pixelHeight - 1 - int(math.Round(float64(point.RTT)/float64(maxRTT)*float64(pixelHeight-1)))
		if havePrevious {
			drawLine(previousX, previousY, x, y, point.RTT)
		}
		setPixel(x, y, point.RTT)
		previousX, previousY, havePrevious = x, y, true
	}

	rows := make([]string, 0, height+1)
	for row := 0; row < height; row++ {
		value := float64(maxRTT) * float64(height-1-row) / float64(height-1)
		label := fmt.Sprintf("%4.0fms", value/float64(time.Millisecond))
		var line strings.Builder
		line.WriteString(label)
		line.WriteString(" ┤")
		for column := 0; column < width; column++ {
			mask := masks[row][column]
			if mask == 0 {
				line.WriteByte(' ')
				continue
			}
			cell := string(rune(0x2800) + rune(mask))
			line.WriteString(termui.Paint(rttStyle(cellRTT[row][column]), cell, color))
		}
		rows = append(rows, line.String())
	}
	axis := strings.Repeat("─", max(0, width-1))
	rows = append(rows, fmt.Sprintf("       └%s┘ 60s ago → now", axis))
	return rows
}

// brailleDotMask maps a local 2x4 pixel position to the Unicode Braille dot
// numbering. A single terminal cell therefore carries eight graph pixels.
func brailleDotMask(x, y int) uint8 {
	if x == 0 {
		switch y {
		case 0:
			return 1 << 0
		case 1:
			return 1 << 1
		case 2:
			return 1 << 2
		case 3:
			return 1 << 6
		}
	} else if x == 1 {
		switch y {
		case 0:
			return 1 << 3
		case 1:
			return 1 << 4
		case 2:
			return 1 << 5
		case 3:
			return 1 << 7
		}
	}
	return 0
}

func pointsMaxRTT(points []pingSample) time.Duration {
	var maxRTT time.Duration
	for _, point := range points {
		if point.RTT > maxRTT {
			maxRTT = point.RTT
		}
	}
	return maxRTT
}

func maxTrafficRate(r trafficRates) float64 {
	return math.Max(math.Max(r.GameUpload, r.GameDownload), math.Max(r.L4PUpload, r.L4PDownload))
}

func writeRateLine(b *strings.Builder, label string, rate, maxRate float64, color bool, style string) {
	const barWidth = 18
	filled := 0
	if maxRate > 0 && rate > 0 {
		filled = int(math.Round(rate / maxRate * barWidth))
		if filled < 1 {
			filled = 1
		}
		if filled > barWidth {
			filled = barWidth
		}
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Fprintf(b, "│ %-6s %s %10s\n", label, termui.Paint(style, bar, color), formatRate(rate))
}

func formatRate(rate float64) string {
	switch {
	case rate >= 1024*1024:
		return fmt.Sprintf("%.1f MiB/s", rate/(1024*1024))
	case rate >= 1024:
		return fmt.Sprintf("%.1f KiB/s", rate/1024)
	default:
		return fmt.Sprintf("%.0f B/s", rate)
	}
}

func formatRTT(rtt time.Duration) string {
	if rtt <= 0 || rtt >= 900*time.Millisecond {
		return "N/A"
	}
	return fmt.Sprintf("%.1f ms", float64(rtt)/float64(time.Millisecond))
}

func formatLoss(loss float64, online bool) string {
	if !online {
		return "N/A"
	}
	return fmt.Sprintf("%.1f%%", loss*100)
}

func rttStyle(rtt time.Duration) string {
	switch {
	case rtt <= 0 || rtt >= 120*time.Millisecond:
		return termui.Red
	case rtt >= 50*time.Millisecond:
		return termui.Yellow
	default:
		return termui.Green
	}
}

func lossStyle(loss float64, online bool) string {
	if !online || loss >= 0.2 {
		return termui.Red
	}
	if loss >= 0.05 {
		return termui.Yellow
	}
	return termui.Green
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
