package godevauth_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Client-IP resolution and the rate-limit bucket key.
//
// Both of the obvious configurations are dangerous, in opposite
// directions: ignoring forwarded headers behind a load balancer puts
// every client in one bucket (a self-inflicted outage, since the
// limiter fails closed), and trusting them from anywhere lets every
// client pick its own bucket (no limit at all). Neither may be reachable
// by accident.

func TestNewRejectsUnsafeProxyConfigurations(t *testing.T) {
	base := func() godevauth.Config {
		return godevauth.Config{
			BaseURL: "https://x.test", Secret: "0123456789abcdef0123456789abcdef",
			Database: memory.New(),
		}
	}
	cases := map[string]func(*godevauth.Config){
		"trusting headers from any peer": func(c *godevauth.Config) {
			c.Advanced.TrustProxyHeaders = true
		},
		"custom headers from any peer": func(c *godevauth.Config) {
			c.Advanced.IPAddressHeaders = []string{"CF-Connecting-IP"}
		},
		"a proxy list that is never consulted": func(c *godevauth.Config) {
			c.Advanced.TrustedProxies = []string{"10.0.0.0/8"}
		},
		"an unparseable proxy entry": func(c *godevauth.Config) {
			c.Advanced.TrustProxyHeaders = true
			c.Advanced.TrustedProxies = []string{"not-an-address"}
		},
		"an unparseable proxy CIDR": func(c *godevauth.Config) {
			c.Advanced.TrustProxyHeaders = true
			c.Advanced.TrustedProxies = []string{"10.0.0.0/99"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(&cfg)
			if _, err := godevauth.New(cfg); err == nil {
				t.Fatal("expected New to refuse the configuration")
			}
		})
	}
}

func TestNewAcceptsAnExplicitProxyConfiguration(t *testing.T) {
	for _, proxies := range [][]string{
		{"10.0.0.0/8"}, {"192.0.2.7"}, {"::1/128"}, {"*"},
	} {
		if _, err := godevauth.New(godevauth.Config{
			BaseURL: "https://x.test", Secret: "0123456789abcdef0123456789abcdef",
			Database: memory.New(),
			Advanced: godevauth.AdvancedConfig{
				TrustProxyHeaders: true, TrustedProxies: proxies,
			},
		}); err != nil {
			t.Fatalf("TrustedProxies %v: %v", proxies, err)
		}
	}
}

// clientIPFor resolves the client IP the way the router would.
func clientIPFor(t *testing.T, cfg godevauth.AdvancedConfig, remoteAddr string, headers map[string]string) string {
	t.Helper()
	auth, err := godevauth.New(godevauth.Config{
		BaseURL: "https://x.test", Secret: "0123456789abcdef0123456789abcdef",
		Database: memory.New(), Advanced: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/auth/ok", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return auth.NewCtx(httptest.NewRecorder(), r).ClientIP()
}

func TestClientIPIgnoresForwardedHeadersByDefault(t *testing.T) {
	got := clientIPFor(t, godevauth.AdvancedConfig{}, "10.0.0.5:1234",
		map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if got != "10.0.0.5" {
		t.Fatalf("ClientIP = %q, want the peer address", got)
	}
}

func TestClientIPUsesForwardedHeadersFromATrustedProxy(t *testing.T) {
	cfg := godevauth.AdvancedConfig{
		TrustProxyHeaders: true, TrustedProxies: []string{"10.0.0.0/8"},
	}
	got := clientIPFor(t, cfg, "10.0.0.5:1234",
		map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want the forwarded client", got)
	}
}

// The attack the right-to-left walk exists to stop: a client prepends
// addresses of its choosing, the proxy appends the address it really
// saw, and a naive "first entry" reader hands the client a fresh
// rate-limit bucket on every request.
func TestClientIPIgnoresAddressesPrependedByTheClient(t *testing.T) {
	cfg := godevauth.AdvancedConfig{
		TrustProxyHeaders: true, TrustedProxies: []string{"10.0.0.0/8"},
	}
	got := clientIPFor(t, cfg, "10.0.0.5:1234", map[string]string{
		"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 203.0.113.9",
	})
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want the address appended by the proxy", got)
	}
}

// Chained proxies: hops that are ours are skipped, the first that is not
// is the client.
func TestClientIPWalksPastTrustedHops(t *testing.T) {
	cfg := godevauth.AdvancedConfig{
		TrustProxyHeaders: true, TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
	}
	got := clientIPFor(t, cfg, "10.0.0.5:1234", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 172.16.4.4, 10.0.0.9",
	})
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q", got)
	}
}

// Headers arriving straight from the internet are not honoured even
// when proxy support is switched on.
func TestClientIPIgnoresForwardedHeadersFromAnUntrustedPeer(t *testing.T) {
	cfg := godevauth.AdvancedConfig{
		TrustProxyHeaders: true, TrustedProxies: []string{"10.0.0.0/8"},
	}
	got := clientIPFor(t, cfg, "198.51.100.4:5555",
		map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if got != "198.51.100.4" {
		t.Fatalf("ClientIP = %q, want the untrusted peer's own address", got)
	}
}

// "*" is the old behaviour, kept as an explicit opt-in for deployments
// where the network guarantees the proxy is the only way in.
func TestWildcardTrustRestoresTheOldBehaviour(t *testing.T) {
	cfg := godevauth.AdvancedConfig{
		TrustProxyHeaders: true, TrustedProxies: []string{"*"},
	}
	got := clientIPFor(t, cfg, "198.51.100.4:5555",
		map[string]string{"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q", got)
	}
}

// The misconfiguration that cannot be caught at startup — running behind
// a balancer with no proxy configuration — is caught the first time the
// traffic shows it.
func TestUnexpectedForwardedHeadersAreReported(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Logger = slog.New(slog.NewTextHandler(&syncWriter{w: &buf, mu: &mu}, nil))
		// The limiter is what resolves the client IP on every request.
		cfg.RateLimit = godevauth.RateLimitConfig{}
	})
	tc.do(http.MethodGet, "/ok", nil, "X-Forwarded-For", "203.0.113.9")

	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if !strings.Contains(out, "X-Forwarded-For") || !strings.Contains(out, "TrustedProxies") {
		t.Fatalf("the ignored proxy header was not reported:\n%s", out)
	}
}

// The rate-limit key used to include path parameters, so every request
// to /reset-password/<token> landed in a bucket of its own and the
// endpoint an attacker guesses tokens against was never limited.
func TestRateLimitBucketsByRoutePatternNotResolvedPath(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.RateLimit = godevauth.RateLimitConfig{}
	})
	var limited bool
	for i := 0; i < 10; i++ {
		res, _ := tc.get(fmt.Sprintf("/reset-password/token-%d", i))
		if res.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("a parameterised route was never rate limited: each token got its own bucket")
	}
}

// Two clients must not share a bucket when the proxy configuration says
// how to tell them apart.
func TestRateLimitSeparatesClientsBehindATrustedProxy(t *testing.T) {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL: "http://127.0.0.1", Secret: "0123456789abcdef0123456789abcdef",
		Database:         memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
		Advanced: godevauth.AdvancedConfig{
			TrustProxyHeaders: true, TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		},
		Events: godevauth.EventsConfig{DisableDefaultLogging: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	attempt := func(clientIP string) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/auth/sign-in/email",
			strings.NewReader(`{"email":"a@example.com","password":"password123"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", clientIP)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		return res.StatusCode
	}

	// Exhaust the strict 3-per-10s budget for one client.
	var exhausted bool
	for i := 0; i < 6; i++ {
		if attempt("203.0.113.1") == http.StatusTooManyRequests {
			exhausted = true
			break
		}
	}
	if !exhausted {
		t.Fatal("the first client was never rate limited")
	}
	// A different client must still be served: without per-client
	// resolution this is the fleet-wide outage.
	if got := attempt("203.0.113.2"); got == http.StatusTooManyRequests {
		t.Fatal("a second client shared the first client's bucket")
	}
}

// Regression test for L20: with TrustedProxies "*", a front proxy on a
// unix socket (empty RemoteAddr) must still be trusted, so its
// forwarded header is honoured. The nil-IP guard used to reject it even
// for the wildcard.
func TestClientIPTrustsWildcardOverUnixSocket(t *testing.T) {
	cfg := godevauth.AdvancedConfig{
		TrustProxyHeaders: true, TrustedProxies: []string{"*"},
	}
	got := clientIPFor(t, cfg, "", // unix socket: no RemoteAddr
		map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want the forwarded client (wildcard should trust a unix-socket peer)", got)
	}
}
