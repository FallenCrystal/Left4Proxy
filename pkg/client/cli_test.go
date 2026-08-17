package client

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"left4proxy/pkg/config"
	"left4proxy/pkg/router"
)

func newTestClient() *Client {
	cfg := config.DefaultClientConfig()
	cfg.ListenAddr = "127.0.0.2:27015"
	cfg.Mode = "auto"
	cfg.EnablePunch = true

	c := &Client{
		cfg:    cfg,
		router: router.NewRouter(cfg.Mode),
	}
	c.sessionID.Store(123456789)

	c1 := mkCand("192.168.1.10:27014", 2*time.Millisecond, true, true)
	c1.pathClass = "lan"

	c2 := mkCand("1.2.3.4:27014", 35*time.Millisecond, true, false)
	c2.pathClass = "relay"
	c2.lastReflected = "114.240.1.2:45678"

	c.candidates = []*serverCandidate{c1, c2}
	c.bestCandidate = c1
	return c
}

func TestCLIExecuteStatus(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	cli := NewCLI(c, nil, &out, nil, "1.0.0")

	cli.Execute("status")
	result := out.String()

	if !strings.Contains(result, "Left4Proxy Status") {
		t.Errorf("expected status header, got: %s", result)
	}
	if !strings.Contains(result, "123456789") {
		t.Errorf("expected session ID, got: %s", result)
	}
	if !strings.Contains(result, "127.0.0.2:27015") {
		t.Errorf("expected listen address, got: %s", result)
	}
	if !strings.Contains(result, "192.168.1.10:27014") {
		t.Errorf("expected candidate in output, got: %s", result)
	}
}

func TestCLIExecutePing(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	cli := NewCLI(c, nil, &out, nil, "1.0.0")

	cli.Execute("ping")
	result := out.String()

	if !strings.Contains(result, "Left4Proxy ping") {
		t.Errorf("expected ping graph, got: %s", result)
	}
	if !strings.Contains(result, "Throughput") || !strings.Contains(result, "Game") || !strings.Contains(result, "L4P") {
		t.Errorf("expected graph traffic sections, got: %s", result)
	}
	cli.Execute("ping stop")
	if !strings.Contains(out.String(), "Ping graph stopped") {
		t.Errorf("expected graph stop message, got: %s", out.String())
	}
}

func TestCLIExecuteMode(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	cli := NewCLI(c, nil, &out, nil, "1.0.0")

	// View mode
	cli.Execute("mode")
	if !strings.Contains(out.String(), "Current routing mode: auto") {
		t.Errorf("expected auto mode, got: %s", out.String())
	}
	out.Reset()

	// Switch mode to direct
	cli.Execute("mode direct")
	if !strings.Contains(out.String(), "Routing mode set to: direct-only") {
		t.Errorf("expected direct-only switch, got: %s", out.String())
	}
	if c.GetMode() != "direct-only" {
		t.Errorf("client mode expected direct-only, got: %s", c.GetMode())
	}
	out.Reset()

	// Switch mode to relay
	cli.Execute("mode relay")
	if !strings.Contains(out.String(), "Routing mode set to: relay-only") {
		t.Errorf("expected relay-only switch, got: %s", out.String())
	}
	if c.GetMode() != "relay-only" {
		t.Errorf("client mode expected relay-only, got: %s", c.GetMode())
	}
	out.Reset()

	// Switch mode with invalid value
	cli.Execute("mode invalid_mode")
	if !strings.Contains(out.String(), "Error:") {
		t.Errorf("expected error message for invalid mode, got: %s", out.String())
	}
}

func TestCLIExecuteCandidates(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	cli := NewCLI(c, nil, &out, nil, "1.0.0")

	cli.Execute("candidates")
	result := out.String()

	if !strings.Contains(result, "Server Candidates (2):") {
		t.Errorf("expected candidate count, got: %s", result)
	}
	if !strings.Contains(result, "192.168.1.10:27014") {
		t.Errorf("expected cand1, got: %s", result)
	}
	if !strings.Contains(result, "1.2.3.4:27014") {
		t.Errorf("expected cand2, got: %s", result)
	}
}

func TestCLIExecuteVersion(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	cli := NewCLI(c, nil, &out, nil, "1.2.3")

	cli.Execute("version")
	if !strings.Contains(out.String(), "v1.2.3") {
		t.Errorf("expected version v1.2.3, got: %s", out.String())
	}
}

func TestCLIExecuteHelp(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	cli := NewCLI(c, nil, &out, nil, "1.0.0")

	cli.Execute("help")
	result := out.String()

	if !strings.Contains(result, "Left4Proxy Client Commands:") {
		t.Errorf("expected help header, got: %s", result)
	}
	if !strings.Contains(result, "status") || !strings.Contains(result, "quit") {
		t.Errorf("expected status and quit in help text, got: %s", result)
	}
}

func TestCLIExecuteQuit(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	quitCalled := false
	cli := NewCLI(c, nil, &out, func() {
		quitCalled = true
	}, "1.0.0")

	cli.Execute("quit")
	if !quitCalled {
		t.Errorf("expected quit callback to be invoked")
	}
	if !strings.Contains(out.String(), "Exiting Left4Proxy Client") {
		t.Errorf("expected exiting message, got: %s", out.String())
	}
}

func TestTrafficRatesFor(t *testing.T) {
	current := TrafficSnapshot{
		GameUploadBytes:   2_000,
		GameDownloadBytes: 4_000,
		L4PUploadBytes:    6_000,
		L4PDownloadBytes:  8_000,
	}
	previous := TrafficSnapshot{
		GameUploadBytes:   1_000,
		GameDownloadBytes: 2_000,
		L4PUploadBytes:    3_000,
		L4PDownloadBytes:  4_000,
	}
	rates := trafficRatesFor(current, previous, 2*time.Second)
	if rates.GameUpload != 500 || rates.GameDownload != 1_000 || rates.L4PUpload != 1_500 || rates.L4PDownload != 2_000 {
		t.Fatalf("unexpected rates: %+v", rates)
	}

	reset := trafficRatesFor(TrafficSnapshot{GameUploadBytes: 100}, current, time.Second)
	if reset.GameUpload != 100 {
		t.Fatalf("counter reset should use current total, got %.0f", reset.GameUpload)
	}
}

func TestRenderLatencyGraph(t *testing.T) {
	rows := renderLatencyGraph([]pingSample{
		{RTT: 20 * time.Millisecond, Online: true},
		{RTT: 80 * time.Millisecond, Online: true},
	}, 12, 5, false)
	if len(rows) != 6 {
		t.Fatalf("expected graph rows plus timeline, got %d", len(rows))
	}
	joined := strings.Join(rows, "\n")
	hasBraille := false
	for _, r := range joined {
		if r >= '\u2800' && r <= '\u28ff' {
			hasBraille = true
			break
		}
	}
	if !hasBraille || !strings.Contains(joined, "100ms") {
		t.Fatalf("graph did not contain plotted RTT data: %s", joined)
	}
}

func TestPingLossRate(t *testing.T) {
	if got := pingLossRate(0, 0); got != 0 {
		t.Fatalf("zero probes loss = %v", got)
	}
	if got := pingLossRate(10, 8); got != 0.2 {
		t.Fatalf("loss = %v, want 0.2", got)
	}
	if got := pingLossRate(8, 10); got != 0 {
		t.Fatalf("received more than sent loss = %v", got)
	}
}

func TestCLIRunLoop(t *testing.T) {
	c := newTestClient()
	input := "status\nmode relay\nquit\n"
	in := strings.NewReader(input)
	var out bytes.Buffer
	quitCalled := false

	cli := NewCLI(c, in, &out, func() {
		quitCalled = true
	}, "1.0.0")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cli.Run(ctx)

	if !quitCalled {
		t.Errorf("expected quit to be called from input stream")
	}
	output := out.String()
	if !strings.Contains(output, "Left4Proxy Status") {
		t.Errorf("expected status in run output, got: %s", output)
	}
	if !strings.Contains(output, "Routing mode set to: relay-only") {
		t.Errorf("expected mode set in run output, got: %s", output)
	}
}

func TestCLIRunEOF(t *testing.T) {
	c := newTestClient()
	in := strings.NewReader("") // Empty stream simulating EOF
	var out bytes.Buffer

	cli := NewCLI(c, in, &out, nil, "1.0.0")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		cli.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Succeeded immediately on EOF
	case <-time.After(500 * time.Millisecond):
		t.Errorf("CLI.Run did not return on EOF")
	}
}

func TestCLIExecuteNAT(t *testing.T) {
	c := newTestClient()
	var out bytes.Buffer
	cli := NewCLI(c, nil, &out, nil, "1.0.0")

	cli.Execute("nat")
	result := out.String()

	if !strings.Contains(result, "STUN NAT mapping behavior") {
		t.Errorf("expected NAT detection prompt, got: %s", result)
	}
}
