package router

import (
	"fmt"
	"sync"
	"time"
)

type PathType string

const (
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
		current: PathRelay,
	}
	return r
}

// UpdateMetrics updates RTT and loss rate for a specific path.
func (r *Router) UpdateMetrics(pt PathType, rtt time.Duration, loss float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, exists := r.stats[pt]
	if !exists {
		st = &PathStats{}
		r.stats[pt] = st
	}
	st.RTT = rtt
	st.LossRate = loss
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
		// Direct-tier paths (Direct or Punch) — pick the lower RTT.
		stDir, okDir := r.stats[PathDirect]
		stPunch, okPunch := r.stats[PathPunch]
		switch {
		case okPunch && stPunch.Active && (!okDir || !stDir.Active || stPunch.RTT <= stDir.RTT):
			r.current = PathPunch
		default:
			r.current = PathDirect
		}
		return

	case "relay-only":
		r.current = PathRelay
		return

	case "auto":
		fallthrough
	default:
		// Priority 1: LAN (Local Area Network)
		if stLAN, ok := r.stats[PathLAN]; ok && stLAN.Active {
			r.current = PathLAN
			return
		}

		// Priority 2: direct-tier paths (Direct or Punch), pick the lower RTT.
		stDirect, okDirect := r.stats[PathDirect]
		stPunch, okPunch := r.stats[PathPunch]
		stRelay, okRelay := r.stats[PathRelay]

		var bestDirect PathType
		var bestDirectRTT time.Duration
		haveDirect := false
		if okDirect && stDirect.Active && stDirect.LossRate < 0.15 {
			bestDirect, bestDirectRTT, haveDirect = PathDirect, stDirect.RTT, true
		}
		if okPunch && stPunch.Active && stPunch.LossRate < 0.15 {
			if !haveDirect || stPunch.RTT < bestDirectRTT {
				bestDirect, bestDirectRTT, haveDirect = PathPunch, stPunch.RTT, true
			}
		}

		if haveDirect {
			if !okRelay || !stRelay.Active || bestDirectRTT <= stRelay.RTT+r.threshold {
				r.current = bestDirect
				return
			}
		}

		// Priority 3: Fallback to Server Relay
		r.current = PathRelay
	}
}

// CurrentPath returns the currently active best path.
func (r *Router) CurrentPath() PathType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
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
