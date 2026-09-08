package ratelimit

import (
	"testing"
	"time"
)

// Regression test for M1: garbage collection used the calling hit's
// window for every key, so one short-window hit evicted live counters
// belonging to long-window rules, silently capping any custom rule
// longer than ~10x the shortest window in use.
func TestGCUsesEachKeysOwnWindow(t *testing.T) {
	store := NewMemoryStore()
	long := 24 * time.Hour
	short := 10 * time.Second

	if n, _ := store.Hit("long-key", long); n != 1 {
		t.Fatalf("long-key first hit = %d", n)
	}
	// Age the long key and the GC clock so the next hit runs a sweep.
	store.mu.Lock()
	store.windows["long-key"].start = time.Now().Add(-5 * time.Minute)
	store.lastGC = time.Now().Add(-2 * time.Minute)
	store.mu.Unlock()

	// A short-window hit triggers GC. Under the bug, "older than
	// 10*shortWindow" (100s) evicted the 5-minute-old 24h counter.
	if _, err := store.Hit("short-key", short); err != nil {
		t.Fatal(err)
	}

	if n, _ := store.Hit("long-key", long); n != 2 {
		t.Fatalf("long-key hit after short-window GC = %d, want 2 (counter was evicted)", n)
	}
}
