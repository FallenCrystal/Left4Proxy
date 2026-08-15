package router

import (
	"fmt"
	"sync"
	"time"
)

type PathType string

const (
	PathNone   PathType = ""
	PathLAN    PathType = "LAN"
	PathDirect PathType = "Direct"
	PathPunch  PathType = "Punch"
	PathRelay  PathType = "Relay"
)

type PathStats struct {
	RTT        time.Duration
	LossRate   float64
	LastActive time.Time
	Active     bool
}

// Router chooses the best available network path dynamically.
type Router struct {
	mu        sync.RWMutex
	mode      string        // "auto", "direct-only", "relay-only"
	threshold time.Duration // Latency hysteresis threshold (default: 15ms)
	stats     map[PathType]*PathStats
	current   PathType
}

// NewRouter initializes a new route selection manager.
func NewRouter(mode string) *Router {
	if mode == "" {
		mode = "auto"
	}
	r := &Router{
		mode:      mode,
		threshold: 15 * time.Millisecond,
		stats: map[PathType]*PathStats{
			PathLAN:    {RTT: 1 * time.Millisecond, LossRate: 0, Active: false},
			PathDirect: {RTT: 999 * time.Millisecond, LossRate: 0, Active: false},
			PathPunch:  {RTT: 999 * time.Millisecond, LossRate: 0, Active: false},
			PathRelay:  {RTT: 999 * time.Millisecond, LossRate: 0, Active: true}, // Relay is always available as fallback
		},
		current: PathNone,
	}
	r.evaluatePath()
	return r
}

// Score returns the quality-weighted effective latency. Higher loss rate significantly penalizes the path.
func (st *PathStats) Score() time.Duration {
	if st == nil || !st.Active {
		return 999 * time.Second
	}
	// Formula: Score = RTT * (1 + LossRate * 4.0)
	score := float64(st.RTT) * (1.0 + st.LossRate*4.0)
	return time.Duration(score)
}

// UpdateMetrics updates RTT and loss rate for a specific path using EWMA smoothing.
func (r *Router) UpdateMetrics(pt PathType, rtt time.Duration, loss float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, exists := r.stats[pt]
	if !exists {
		st = &PathStats{}
		r.stats[pt] = st
	}
	if !st.Active || st.RTT >= 900*time.Millisecond {
		st.RTT = rtt
		st.LossRate = loss
	} else {
		// EWMA smoothing
		st.RTT = time.Duration(float64(st.RTT)*0.75 + float64(rtt)*0.25)
		st.LossRate = st.LossRate*0.75 + loss*0.25
	}
	st.LastActive = time.Now()
	st.Active = true

	r.evaluatePath()
}

// SetInactive marks a path as inactive/unreachable.
func (r *Router) SetInactive(pt PathType) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if st, exists := r.stats[pt]; exists {
		st.Active = false
	}
	r.evaluatePath()
}

// evaluatePath determines the best path based on metrics.
func (r *Router) evaluatePath() {
	now := time.Now()
	const maxAge = 15 * time.Second // Increased to 15s to prevent premature ping timeouts

	// Invalidate stale paths (except Relay which defaults to active)
	for pt, st := range r.stats {
		if pt != PathRelay && st.Active && now.Sub(st.LastActive) > maxAge {
			st.Active = false
		}
	}

	switch r.mode {
	case "direct-only":
		if stLAN, ok := r.stats[PathLAN]; ok && stLAN.Active {
			r.current = PathLAN
			return
		}
		// Direct-tier paths (Direct or Punch) — pick the lower Score.
		stDir, okDir := r.stats[PathDirect]
		stPunch, okPunch := r.stats[PathPunch]
		switch {
		case okPunch && stPunch.Active && (!okDir || !stDir.Active || stPunch.Score() <= stDir.Score()):
			r.current = PathPunch
		case okDir && stDir.Active:
			r.current = PathDirect
		default:
			r.current = PathNone
		}
		return

	case "relay-only":
		if stRelay, ok := r.stats[PathRelay]; ok && stRelay.Active {
			r.current = PathRelay
		} else {
			r.current = PathNone
		}
		return

	case "auto":
		fallthrough
	default:
		// Priority 1: LAN (Local Area Network)
		if stLAN, ok := r.stats[PathLAN]; ok && stLAN.Active {
			r.current = PathLAN
			return
		}

		// Priority 2: direct-tier paths (Direct or Punch), pick the lower Score.
		stDirect, okDirect := r.stats[PathDirect]
		stPunch, okPunch := r.stats[PathPunch]
		stRelay, okRelay := r.stats[PathRelay]

		var bestDirect PathType
		var bestDirectScore time.Duration
		haveDirect := false
		if okDirect && stDirect.Active && stDirect.LossRate < 0.20 {
			bestDirect, bestDirectScore, haveDirect = PathDirect, stDirect.Score(), true
		}
		if okPunch && stPunch.Active && stPunch.LossRate < 0.20 {
			punchScore := stPunch.Score()
			if !haveDirect || punchScore < bestDirectScore {
				bestDirect, bestDirectScore, haveDirect = PathPunch, punchScore, true
			}
		}

		if haveDirect {
			relayScore := 999 * time.Second
			if okRelay && stRelay.Active {
				relayScore = stRelay.Score()
			}
			if !okRelay || !stRelay.Active || bestDirectScore <= relayScore+r.threshold {
				r.current = bestDirect
				return
			}
		}

		// Priority 3: Fallback to Server Relay. If the relay is also down, expose
		// an empty path so callers can fail closed instead of displaying a route
		// that cannot carry traffic.
		if okRelay && stRelay.Active {
			r.current = PathRelay
		} else {
			r.current = PathNone
		}
	}
}

// CurrentPath returns the currently active best path.
func (r *Router) CurrentPath() PathType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// SetMode dynamically changes the routing mode and re-evaluates the active path.
func (r *Router) SetMode(mode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = mode
	r.evaluatePath()
}

// Mode returns the current configured route mode.
func (r *Router) Mode() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mode
}

// GetStatusString returns human-readable path status.
func (r *Router) GetStatusString() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stLAN := r.stats[PathLAN]
	stDirect := r.stats[PathDirect]
	stPunch := r.stats[PathPunch]
	stRelay := r.stats[PathRelay]

	return fmt.Sprintf("ActivePath: [%s] | LAN: (Active=%v, RTT=%v) | Direct: (Active=%v, RTT=%v) | Punch: (Active=%v, RTT=%v) | Relay: (Active=%v, RTT=%v)",
		r.current, stLAN.Active, stLAN.RTT, stDirect.Active, stDirect.RTT, stPunch.Active, stPunch.RTT, stRelay.Active, stRelay.RTT)
}
