// Package track keeps a rolling per-source threat score and quarantine
// state. M0 state is in-memory; persistence (survive restarts, share across
// replicas) is a later milestone.
package track

import (
	"sort"
	"sync"
	"time"
)

type scored struct {
	ts    time.Time
	score int
}

type source struct {
	hits         int
	events       []scored
	blockedUntil time.Time
}

// State is the result of recording one scored interaction.
type State struct {
	IP           string
	Score        int // windowed score
	Hits         int
	Blocked      bool
	NewlyBlocked bool
}

// Tracker scores sources over a rolling window and auto-quarantines past a
// threshold. Thread-safe.
type Tracker struct {
	mu          sync.Mutex
	threshold   int
	window      time.Duration
	ttl         time.Duration
	sources     map[string]*source
	blocksTotal int
}

func New(threshold int, window, ttl time.Duration) *Tracker {
	return &Tracker{
		threshold: threshold,
		window:    window,
		ttl:       ttl,
		sources:   map[string]*source{},
	}
}

// Record adds a score for the source and auto-quarantines past the
// threshold. Quiet sources cool off as events leave the window.
func (t *Tracker) Record(ip string, score int) State {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	src := t.sources[ip]
	if src == nil {
		src = &source{}
		t.sources[ip] = src
	}
	src.hits++
	src.events = append(src.events, scored{ts: now, score: score})

	cutoff := now.Add(-t.window)
	kept := src.events[:0]
	windowScore := 0
	for _, ev := range src.events {
		if ev.ts.Before(cutoff) {
			continue
		}
		kept = append(kept, ev)
		windowScore += ev.score
	}
	src.events = kept

	blocked := now.Before(src.blockedUntil)
	newlyBlocked := false
	if score > 0 && windowScore >= t.threshold {
		if !blocked {
			newlyBlocked = true
			t.blocksTotal++
		}
		// Start — or extend, while the window stays hot — the quarantine clock.
		src.blockedUntil = now.Add(t.ttl)
		blocked = true
	}
	return State{IP: ip, Score: windowScore, Hits: src.hits, Blocked: blocked, NewlyBlocked: newlyBlocked}
}

// IsBlocked reports whether the source is currently quarantined.
func (t *Tracker) IsBlocked(ip string) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	src := t.sources[ip]
	return src != nil && now.Before(src.blockedUntil)
}

// Snapshot is the operator view for stats/debug endpoints.
func (t *Tracker) Snapshot() map[string]any {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	type row struct {
		ip    string
		score int
		hits  int
	}
	rows := make([]row, 0, len(t.sources))
	blockedNow := 0
	for ip, src := range t.sources {
		windowScore := 0
		for _, ev := range src.events {
			if !ev.ts.Before(now.Add(-t.window)) {
				windowScore += ev.score
			}
		}
		if now.Before(src.blockedUntil) {
			blockedNow++
		}
		rows = append(rows, row{ip, windowScore, src.hits})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].score > rows[j].score })
	if len(rows) > 10 {
		rows = rows[:10]
	}
	top := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		top = append(top, map[string]any{"ip": r.ip, "score": r.score, "hits": r.hits})
	}
	return map[string]any{
		"tracked_sources": len(t.sources),
		"blocked_now":     blockedNow,
		"blocks_total":    t.blocksTotal,
		"threshold":       t.threshold,
		"top_sources":     top,
	}
}
