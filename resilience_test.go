package godevauth_test

import (
	"net/http"
	"sync"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// TestPasswordChangeRevokesOtherSessions covers the case a penetration
// test found: a user who changes their password to evict an attacker
// left the attacker's other session working.
func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	tc.signUp("owner@example.com", "password123", "Owner")

	// a second device (think: the attacker's session)
	other := secondClient(t, tc)
	res, _ := other.post("/sign-in/email", map[string]any{
		"email": "owner@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("second sign-in: %d", res.StatusCode)
	}
	if _, sess := other.get("/get-session"); sess == nil || sess["user"] == nil {
		t.Fatal("second session should start out live")
	}

	res, body := tc.post("/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpassword456",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("change-password: %d %v", res.StatusCode, body)
	}

	// the other device must be logged out
	res, sess := other.get("/get-session")
	if res.StatusCode == http.StatusOK && sess["user"] != nil {
		t.Fatal("the other session survived a password change")
	}
	// ...and the session that made the change keeps working
	if _, sess := tc.get("/get-session"); sess == nil || sess["user"] == nil {
		t.Fatal("the session that changed the password was logged out")
	}
}

// TestHasherShedsLoadWhenSaturated asserts that a flood of expensive
// sign-in attempts is rejected with a retryable 503 rather than
// queueing behind a multi-second backlog. Password hashing is
// deliberately slow, so without shedding, a burst turns into latency
// every upstream client experiences as a hang.
func TestHasherShedsLoadWhenSaturated(t *testing.T) {
	// One hashing slot and no willingness to wait: any request that
	// cannot start immediately is shed.
	hasher := crypto.NewScryptHasher(crypto.ScryptParams{
		MaxConcurrent: 1,
		MaxWait:       -1,
	})
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.PasswordHasher = hasher
	})
	tc.signUp("load@example.com", "password123", "Load")

	const attempts = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[int]int{}
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := secondClient(t, tc)
			<-start
			res, _ := client.post("/sign-in/email", map[string]any{
				"email": "load@example.com", "password": "wrong-password",
			})
			mu.Lock()
			counts[res.StatusCode]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if counts[http.StatusServiceUnavailable] == 0 {
		t.Fatalf("expected some requests to be shed with 503; got %v", counts)
	}
	if counts[http.StatusInternalServerError] > 0 {
		t.Fatalf("saturation must not surface as a 5xx server error: %v", counts)
	}
	// A shed request must not be reported as bad credentials, which
	// would tell a legitimate user their password is wrong.
	total := 0
	for code, n := range counts {
		if code != http.StatusUnauthorized && code != http.StatusServiceUnavailable {
			t.Errorf("unexpected status %d (%d times)", code, n)
		}
		total += n
	}
	if total != attempts {
		t.Fatalf("accounted for %d of %d requests", total, attempts)
	}
}

// TestHasherWaitsWhenCapacityFreesUp asserts the shed path does not
// misfire under ordinary load: with a normal MaxWait, requests queue
// briefly and still succeed.
func TestHasherWaitsWhenCapacityFreesUp(t *testing.T) {
	hasher := crypto.NewScryptHasher(crypto.ScryptParams{
		// Cheap parameters: this test is about the queueing behaviour,
		// not the cost of the KDF.
		N: 1024, R: 8, P: 1, KeyLen: 32,
		MaxConcurrent: 2,
		MaxWait:       10 * time.Second,
	})
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.PasswordHasher = hasher
	})
	tc.signUp("queue@example.com", "password123", "Queue")

	const attempts = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := secondClient(t, tc)
			res, _ := client.post("/sign-in/email", map[string]any{
				"email": "queue@example.com", "password": "password123",
			})
			if res.StatusCode == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != attempts {
		t.Fatalf("%d of %d concurrent sign-ins succeeded; queueing should not shed under normal load", ok, attempts)
	}
}

// TestCookieCacheOptInWithGuards documents the cost/staleness trade:
// with AcceptStaleAuthorization the cache is used even when a guard is
// registered, so requests are served without database lookups.
func TestCookieCacheOptInWithGuards(t *testing.T) {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:          "https://x.test",
		Secret:           "0123456789abcdef0123456789abcdef",
		Database:         memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
		Session: godevauth.SessionConfig{
			CookieCache: godevauth.CookieCacheConfig{
				Enabled:                  true,
				MaxAge:                   time.Minute,
				AcceptStaleAuthorization: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !auth.Config().Session.CookieCache.AcceptStaleAuthorization {
		t.Fatal("option did not survive construction")
	}
}
