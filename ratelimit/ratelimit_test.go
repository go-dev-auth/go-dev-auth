package ratelimit_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/ratelimit"
)

func TestAllowWithinWindow(t *testing.T) {
	limiter := ratelimit.NewLimiter(nil)
	rule := ratelimit.Rule{Window: time.Minute, Max: 3}

	for i := 1; i <= 3; i++ {
		ok, err := limiter.Allow("key", rule)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("request %d of 3 was rejected", i)
		}
	}
	// The fourth exceeds the budget.
	ok, err := limiter.Allow("key", rule)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a request beyond the limit was allowed")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	// Budgets are per key (in practice, per IP and path). One caller
	// exhausting theirs must not lock everyone else out.
	limiter := ratelimit.NewLimiter(nil)
	rule := ratelimit.Rule{Window: time.Minute, Max: 1}

	if ok, _ := limiter.Allow("a", rule); !ok {
		t.Fatal("first request for key a rejected")
	}
	if ok, _ := limiter.Allow("a", rule); ok {
		t.Fatal("second request for key a should be rejected")
	}
	if ok, _ := limiter.Allow("b", rule); !ok {
		t.Fatal("key b was affected by key a's budget")
	}
}

func TestWindowResets(t *testing.T) {
	limiter := ratelimit.NewLimiter(nil)
	rule := ratelimit.Rule{Window: 40 * time.Millisecond, Max: 1}

	if ok, _ := limiter.Allow("key", rule); !ok {
		t.Fatal("first request rejected")
	}
	if ok, _ := limiter.Allow("key", rule); ok {
		t.Fatal("second request within the window allowed")
	}
	time.Sleep(60 * time.Millisecond)
	if ok, _ := limiter.Allow("key", rule); !ok {
		t.Fatal("the budget did not reset after the window elapsed")
	}
}

func TestZeroRuleDisablesLimiting(t *testing.T) {
	// A zero rule means "no limit configured"; it must not reject
	// everything, which would take an endpoint offline.
	limiter := ratelimit.NewLimiter(nil)
	for _, rule := range []ratelimit.Rule{
		{},
		{Window: time.Minute, Max: 0},
		{Window: 0, Max: 10},
	} {
		for i := 0; i < 5; i++ {
			if ok, err := limiter.Allow("key", rule); !ok || err != nil {
				t.Fatalf("rule %+v rejected a request (ok=%v err=%v)", rule, ok, err)
			}
		}
	}
}

func TestConcurrentAllowCountsExactly(t *testing.T) {
	// The counter must not lose increments under concurrency: an
	// undercount is a brute-force window.
	limiter := ratelimit.NewLimiter(nil)
	const max = 50
	rule := ratelimit.Rule{Window: time.Minute, Max: max}

	const callers = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := limiter.Allow("shared", rule); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if allowed != max {
		t.Fatalf("%d requests allowed, want exactly %d", allowed, max)
	}
}

func TestMemoryStoreHitCountsPerWindow(t *testing.T) {
	store := ratelimit.NewMemoryStore()
	for i := 1; i <= 3; i++ {
		n, err := store.Hit("k", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if n != i {
			t.Fatalf("hit %d reported count %d", i, n)
		}
	}
	// A different window key starts its own count.
	n, err := store.Hit("other", time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("independent key reported %d (err %v)", n, err)
	}
}

// failingStore models a shared store (Redis, say) that is unreachable.
type failingStore struct{ err error }

func (f failingStore) Hit(string, time.Duration) (int, error) { return 0, f.err }

func TestStoreErrorIsReportedNotSwallowed(t *testing.T) {
	// The caller decides whether to fail open or closed, so the error
	// must reach it. Swallowing it here would silently disable rate
	// limiting during an outage.
	wantErr := errors.New("store unavailable")
	limiter := ratelimit.NewLimiter(failingStore{err: wantErr})

	_, err := limiter.Allow("key", ratelimit.Rule{Window: time.Minute, Max: 5})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want the store's error", err)
	}
}

func BenchmarkAllow(b *testing.B) {
	limiter := ratelimit.NewLimiter(nil)
	rule := ratelimit.Rule{Window: time.Minute, Max: 1 << 30}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = limiter.Allow("bench", rule)
		}
	})
}
