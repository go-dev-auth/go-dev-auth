package ratelimit_test

import (
	"fmt"
	"log"
	"sync"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/ratelimit"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// countingStore is a Store that counts hits per key and window, and
// records how many it saw. It stands in for the store a multi-instance
// deployment actually needs: the default MemoryStore lives in one
// process, so N replicas quietly multiply every configured limit by N.
//
// A Redis implementation is the same shape — INCR the key, EXPIRE it to
// the window on the first hit, return the new counter — and an error
// from it makes the limiter fail closed unless RateLimit.FailOpen is
// set.
type countingStore struct {
	mu     sync.Mutex
	hits   map[string]int
	frames map[string]time.Time
}

func newCountingStore() *countingStore {
	return &countingStore{hits: map[string]int{}, frames: map[string]time.Time{}}
}

// Hit records one request against key and returns how many have landed
// in the current window. Implementations must be safe for concurrent
// use: this is called on every request.
func (s *countingStore) Hit(key string, window time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if start, ok := s.frames[key]; !ok || now.Sub(start) >= window {
		s.frames[key] = now
		s.hits[key] = 0
	}
	s.hits[key]++
	return s.hits[key], nil
}

func ExampleStore() {
	store := newCountingStore()

	// The limiter the library uses internally, shown here on its own.
	limiter := ratelimit.NewLimiter(store)
	rule := ratelimit.Rule{Window: time.Minute, Max: 3}
	for i := 0; i < 4; i++ {
		ok, err := limiter.Allow("198.51.100.7:/sign-in/email", rule)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("attempt %d allowed: %t\n", i+1, ok)
	}

	// In an application you hand the store to the configuration and
	// never touch the limiter yourself.
	if _, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		RateLimit: godevauth.RateLimitConfig{Storage: store},
	}); err != nil {
		log.Fatal(err)
	}

	// Output:
	// attempt 1 allowed: true
	// attempt 2 allowed: true
	// attempt 3 allowed: true
	// attempt 4 allowed: false
}
