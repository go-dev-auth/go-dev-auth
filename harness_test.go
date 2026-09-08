package godevauth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Shared test fixture for the package's integration tests.
//
// newTestAuth builds an Auth instance wired to an httptest server and
// returns a client that carries cookies between calls, so tests read as
// a sequence of HTTP exchanges rather than plumbing.

// testClient wraps an httptest server with cookie handling.
type testClient struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
}

func newTestAuth(t *testing.T, mutate func(*godevauth.Config)) (*godevauth.Auth, *testClient) {
	t.Helper()
	// The listener is opened before Auth is built so the real base URL
	// is known at construction time. Patching auth.Config().BaseURL
	// after the server was already serving used to be how this worked;
	// it wrote to the live configuration from the test goroutine while
	// request goroutines read it, which is a data race on the values
	// that decide origin checks and redirect targets.
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	cfg := godevauth.Config{
		BaseURL:  "http://" + server.Listener.Addr().String(),
		Secret:   "test-secret-please-change",
		Database: memory.New(),
		// Rate limiting is on by default; most tests replay the same
		// endpoint many times from one IP, so it is disabled except in
		// the test that asserts on it.
		RateLimit: godevauth.RateLimitConfig{Disabled: true},
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		// Auth events log to the configured logger by default, which is
		// right in production and pure noise in a test run.
		Events: godevauth.EventsConfig{DisableDefaultLogging: true},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	auth, err := godevauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	server.Config.Handler = mux
	server.Start()
	jar := &cookieJar{cookies: map[string]*http.Cookie{}}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return auth, &testClient{t: t, server: server, client: client}
}

// markEmailVerified flips a user's stored emailVerified flag, standing
// in for a completed verification flow.
func markEmailVerified(t *testing.T, auth *godevauth.Auth, email string) {
	t.Helper()
	user, err := auth.FindUserByEmail(t.Context(), email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Storage().Update(t.Context(), storage.ModelUser,
		[]storage.Where{storage.W("id", user.ID)}, map[string]any{"emailVerified": true}); err != nil {
		t.Fatal(err)
	}
}

type cookieJar struct {
	mu      sync.Mutex
	cookies map[string]*http.Cookie
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		if c.MaxAge < 0 {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []*http.Cookie
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}

func (tc *testClient) do(method, path string, body any, headers ...string) (*http.Response, map[string]any) {
	tc.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			tc.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, tc.server.URL+"/api/auth"+path, reader)
	if err != nil {
		tc.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := tc.client.Do(req)
	if err != nil {
		tc.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func (tc *testClient) post(path string, body any) (*http.Response, map[string]any) {
	return tc.do(http.MethodPost, path, body)
}

func (tc *testClient) get(path string) (*http.Response, map[string]any) {
	return tc.do(http.MethodGet, path, nil)
}

func (tc *testClient) signUp(email, password, name string) map[string]any {
	tc.t.Helper()
	res, body := tc.post("/sign-up/email", map[string]any{
		"email": email, "password": password, "name": name,
	})
	if res.StatusCode != http.StatusOK {
		tc.t.Fatalf("sign-up failed: %d %v", res.StatusCode, body)
	}
	return body
}
