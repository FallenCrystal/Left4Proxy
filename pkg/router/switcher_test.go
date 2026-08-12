package router

import (
	"testing"
	"time"
)

func TestRouterAutoSelection(t *testing.T) {
	r := NewRouter("auto")

	// Default path should be Relay
	if r.CurrentPath() != PathRelay {
		t.Fatalf("expected initial path Relay, got %s", r.CurrentPath())
	}

	// Update Direct path with lower latency
	r.UpdateMetrics(PathDirect, 30*time.Millisecond, 0.0)
	if r.CurrentPath() != PathDirect {
		t.Errorf("expected path Direct after update, got %s", r.CurrentPath())
	}

	// Update Relay path with much better latency (e.g. 5ms vs Direct 80ms)
	r.UpdateMetrics(PathDirect, 80*time.Millisecond, 0.0)
	r.UpdateMetrics(PathRelay, 5*time.Millisecond, 0.0)
	if r.CurrentPath() != PathRelay {
		t.Errorf("expected path fallback to Relay due to better RTT, got %s", r.CurrentPath())
	}

	// Activate LAN probe
	r.UpdateMetrics(PathLAN, 1*time.Millisecond, 0.0)
	if r.CurrentPath() != PathLAN {
		t.Errorf("expected path LAN when LAN is active, got %s", r.CurrentPath())
	}
}

func TestRouterPunch(t *testing.T) {
	r := NewRouter("auto")

	// Punch is a direct-tier path and should be selected when it is the best one.
	r.UpdateMetrics(PathPunch, 20*time.Millisecond, 0.0)
	if r.CurrentPath() != PathPunch {
		t.Errorf("expected PathPunch when Punch is the best direct-tier path, got %s", r.CurrentPath())
	}

	// Relay with much better RTT should win over Punch.
	r.UpdateMetrics(PathPunch, 80*time.Millisecond, 0.0)
	r.UpdateMetrics(PathRelay, 5*time.Millisecond, 0.0)
	if r.CurrentPath() != PathRelay {
		t.Errorf("expected Relay when its RTT beats Punch, got %s", r.CurrentPath())
	}

	// LAN still outranks Punch.
	r.UpdateMetrics(PathLAN, 1*time.Millisecond, 0.0)
	if r.CurrentPath() != PathLAN {
		t.Errorf("expected LAN when active, got %s", r.CurrentPath())
	}
}

func TestRouterModes(t *testing.T) {
	rRelay := NewRouter("relay-only")
	rRelay.UpdateMetrics(PathDirect, 5*time.Millisecond, 0.0)
	if rRelay.CurrentPath() != PathRelay {
		t.Errorf("expected relay-only mode to stay on Relay, got %s", rRelay.CurrentPath())
	}

	rDirect := NewRouter("direct-only")
	rDirect.UpdateMetrics(PathDirect, 50*time.Millisecond, 0.0)
	if rDirect.CurrentPath() != PathDirect {
		t.Errorf("expected direct-only mode to select Direct, got %s", rDirect.CurrentPath())
	}
}
