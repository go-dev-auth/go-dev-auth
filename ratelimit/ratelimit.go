// Package ratelimit implements fixed-window rate limiting for
// go-dev-auth endpoints.
package ratelimit

import (
	"sync"
	"time"
)

// Rule is a rate limit rule: at most Max requests per Window.
type Rule struct {
	Window time.Duration
	Max    int
}

// Store persists rate limit windows. Implementations must be safe for
// concurrent use. A Redis-backed store can be plugged in for multi-node
// deployments.
type Store interface {
	// Hit records a hit for key in a window of the given duration and
	// returns the number of hits in the current window.
	Hit(key string, window time.Duration) (int, error)
}

// MemoryStore is the default in-memory store.
type MemoryStore struct {
	mu      sync.Mutex
	windows map[string]*windowState
	lastGC  time.Time
}

type windowState struct {
	start time.Time
	count int
	// window is the rule window this state was created under. GC
	// evicts each key relative to its OWN window: judging every key by
	// the calling hit's window let a 10-second-window hit evict live
	// counters for long-window rules, silently capping any custom rule
	// longer than ~10x the shortest window in use.
	window time.Duration
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{windows: map[string]*windowState{}, lastGC: time.Now()}
}

// Hit implements Store.
func (m *MemoryStore) Hit(key string, window time.Duration) (int, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Sub(m.lastGC) > time.Minute {
		for k, w := range m.windows {
			if now.Sub(w.start) > 10*w.window {
				delete(m.windows, k)
			}
		}
		m.lastGC = now
	}
	w, ok := m.windows[key]
	if !ok || now.Sub(w.start) >= window {
		m.windows[key] = &windowState{start: now, count: 1, window: window}
		return 1, nil
	}
	w.count++
	return w.count, nil
}

// Limiter applies rules against a store.
type Limiter struct {
	store Store
}

// NewLimiter builds a Limiter. A nil store defaults to an in-memory
// store.
func NewLimiter(store Store) *Limiter {
	if store == nil {
		store = NewMemoryStore()
	}
	return &Limiter{store: store}
}

// Allow reports whether the request identified by key passes rule.
func (l *Limiter) Allow(key string, rule Rule) (bool, error) {
	if rule.Max <= 0 || rule.Window <= 0 {
		return true, nil
	}
	n, err := l.store.Hit(key, rule.Window)
	if err != nil {
		return true, err
	}
	return n <= rule.Max, nil
}
