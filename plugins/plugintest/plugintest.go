// Package plugintest provides a test fixture for plugin authors.
//
// Plugins are HTTP surfaces over an Auth instance, so testing one means
// standing up a server, signing a user in, and exchanging JSON with
// cookies attached. Doing that by hand in every plugin package is the
// reason plugins historically had no tests of their own: the setup cost
// exceeded the test.
//
//	func TestMyPlugin(t *testing.T) {
//		env := plugintest.New(t, myplugin.New())
//		env.SignUp("user@example.com", "password123")
//
//		res, body := env.POST("/my-plugin/do-thing", map[string]any{"x": 1})
//		if res.StatusCode != http.StatusOK {
//			t.Fatalf("status %d: %v", res.StatusCode, body)
//		}
//	}
//
// Env.Auth is the live instance, so tests can reach past HTTP to assert
// on stored state or to arrange a precondition the API does not expose.
package plugintest

import (
	"bytes"
	"context"
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

// Env is a running Auth instance with an HTTP client attached.
type Env struct {
	T      *testing.T
	Auth   *godevauth.Auth
	Server *httptest.Server

	client *http.Client
}

// New starts an Auth instance with the given plugins, email/password
// authentication enabled and an in-memory store.
func New(t *testing.T, plugins ...godevauth.Plugin) *Env {
	t.Helper()
	return NewWith(t, func(cfg *godevauth.Config) {
		cfg.Plugins = plugins
	})
}

// NewWith starts an Auth instance, letting the caller adjust the
// configuration first. Use it when a plugin needs specific options.
func NewWith(t *testing.T, configure func(*godevauth.Config)) *Env {
	t.Helper()
	cfg := godevauth.Config{
		BaseURL:  "http://127.0.0.1",
		Secret:   "plugintest-secret-0123456789abcdef",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
			// Hashing dominates test runtime; these parameters keep the
			// algorithm exercised without the production cost.
			PasswordHasher: fastHasher(),
		},
		// Tests replay the same endpoint from one address; the limiter
		// has its own tests.
		RateLimit: godevauth.RateLimitConfig{Disabled: true},
	}
	if configure != nil {
		configure(&cfg)
	}
	auth, err := godevauth.New(cfg)
	if err != nil {
		t.Fatalf("plugintest: building Auth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.BasePath+"/", auth.Handler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	// Redirects and origin checks resolve against the real address.
	auth.Config().BaseURL = server.URL

	return &Env{T: t, Auth: auth, Server: server, client: newClient()}
}

// Client returns a second, independent client: a different browser or
// device for the same server. Use it to test one user acting on
// another's data, which is where authorization bugs hide.
func (e *Env) Client() *Env {
	return &Env{T: e.T, Auth: e.Auth, Server: e.Server, client: newClient()}
}

// Do performs a request against the auth handler and decodes the JSON
// response. A non-JSON body decodes to a nil map, which is fine for
// redirect and HTML responses.
func (e *Env) Do(method, path string, body any, headers ...string) (*http.Response, map[string]any) {
	e.T.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			e.T.Fatalf("plugintest: encoding request body: %v", err)
		}
	}
	req, err := http.NewRequest(method, e.Server.URL+e.Auth.Config().BasePath+path, bytes.NewReader(payload))
	if err != nil {
		e.T.Fatalf("plugintest: building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := e.client.Do(req)
	if err != nil {
		e.T.Fatalf("plugintest: %s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(res.Body).Decode(&decoded)
	return res, decoded
}

// GET performs a GET request.
func (e *Env) GET(path string, headers ...string) (*http.Response, map[string]any) {
	e.T.Helper()
	return e.Do(http.MethodGet, path, nil, headers...)
}

// POST performs a POST request with a JSON body.
func (e *Env) POST(path string, body any, headers ...string) (*http.Response, map[string]any) {
	e.T.Helper()
	return e.Do(http.MethodPost, path, body, headers...)
}

// SignUp registers a user and leaves the client signed in, returning
// the created user. It fails the test if registration does not succeed.
func (e *Env) SignUp(email, password string) *storage.User {
	e.T.Helper()
	res, body := e.POST("/sign-up/email", map[string]any{
		"email": email, "password": password, "name": email,
	})
	if res.StatusCode != http.StatusOK {
		e.T.Fatalf("plugintest: sign-up %s: status %d: %v", email, res.StatusCode, body)
	}
	raw, _ := body["user"].(map[string]any)
	id, _ := raw["id"].(string)
	user, err := e.Auth.FindUserByID(context.Background(), id)
	if err != nil {
		e.T.Fatalf("plugintest: loading the user just created: %v", err)
	}
	return user
}

// SignIn authenticates an existing user on this client.
func (e *Env) SignIn(email, password string) (*http.Response, map[string]any) {
	e.T.Helper()
	return e.POST("/sign-in/email", map[string]any{"email": email, "password": password})
}

// SignOut ends the current session.
func (e *Env) SignOut() {
	e.T.Helper()
	e.POST("/sign-out", map[string]any{})
}

// Session returns the current session payload, or nil when the client
// is not authenticated.
func (e *Env) Session() map[string]any {
	e.T.Helper()
	res, body := e.GET("/get-session")
	if res.StatusCode != http.StatusOK || body["user"] == nil {
		return nil
	}
	return body
}

// Signed reports whether this client currently holds a session.
func (e *Env) Signed() bool { return e.Session() != nil }

// RequireStatus fails the test unless the response has the expected
// status, reporting the body so the failure explains itself.
func (e *Env) RequireStatus(res *http.Response, body map[string]any, want int) {
	e.T.Helper()
	if res.StatusCode != want {
		e.T.Fatalf("status = %d, want %d: %v", res.StatusCode, want, body)
	}
}

// RequireErrorCode fails the test unless the response carries the
// expected status and machine-readable error code. Asserting on the
// code rather than the message keeps tests stable when wording changes.
func (e *Env) RequireErrorCode(res *http.Response, body map[string]any, status int, code string) {
	e.T.Helper()
	if res.StatusCode != status || body["code"] != code {
		e.T.Fatalf("got %d/%v, want %d/%s", res.StatusCode, body["code"], status, code)
	}
}

// Count returns how many records of a model are stored.
func (e *Env) Count(model string, where ...storage.Where) int64 {
	e.T.Helper()
	n, err := e.Auth.Storage().Count(context.Background(), model, where)
	if err != nil {
		e.T.Fatalf("plugintest: counting %s: %v", model, err)
	}
	return n
}

func newClient() *http.Client {
	return &http.Client{
		Jar: &jar{cookies: map[string]*http.Cookie{}},
		// Redirects are assertions in these tests, not something to
		// follow silently.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// jar is a minimal cookie store. net/http/cookiejar rejects cookies for
// bare IP hosts, which is what httptest serves.
type jar struct {
	mu      sync.Mutex
	cookies map[string]*http.Cookie
}

func (j *jar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
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

func (j *jar) Cookies(*url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}
