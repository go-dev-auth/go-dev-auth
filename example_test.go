package godevauth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/providers"
	"github.com/go-dev-auth/go-dev-auth/ratelimit"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// The thirty-second start: an in-memory store, email/password sign-in,
// and the handler mounted on a standard-library mux.
//
// New validates the configuration and returns an error rather than
// starting in an unsafe state, so a mistake shows up at boot instead of
// during someone's sign-in.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		AppName: "Example App",
		BaseURL: "https://example.com",
		// Read this from the environment in production. Generate one
		// with `openssl rand -base64 32`.
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	// The trailing slash matters: every endpoint lives below BasePath.
	mux.Handle("/api/auth/", auth.Handler())

	fmt.Println("mounted at", auth.Config().BasePath)
	// Output: mounted at /api/auth
}

// GetSession is what an application calls after wiring auth up: it
// resolves the session cookie the auth endpoints set, and returns
// ErrNoSession when the request is not authenticated.
func ExampleAuth_GetSession() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// One of your own handlers, outside the auth base path.
	me := func(w http.ResponseWriter, r *http.Request) {
		sd, err := auth.GetSession(r)
		switch {
		case errors.Is(err, godevauth.ErrNoSession):
			http.Error(w, "not signed in", http.StatusUnauthorized)
		case err != nil:
			// A storage failure is not the client's fault.
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			fmt.Fprintf(w, "signed in as %s (fresh: %t)\n",
				sd.User.Email, auth.IsFresh(sd.Session))
		}
	}

	// Sign a user up so there is a session cookie to read. In a real
	// application the browser does this.
	rec := httptest.NewRecorder()
	signUp := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email",
		strings.NewReader(`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`))
	signUp.Header.Set("Content-Type", "application/json")
	auth.Handler().ServeHTTP(rec, signUp)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	out := httptest.NewRecorder()
	me(out, req)
	fmt.Print(out.Body.String())

	// Output: signed in as ada@example.com (fresh: true)
}

// Protecting your own routes: a middleware built on GetSession that
// resolves the session once and hands the user to the handler through
// the request context.
func Example_middleware() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// An unexported key type keeps the context value private to this
	// package, as context.WithValue requires.
	type userKey struct{}

	requireUser := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sd, err := auth.GetSession(r)
			if err != nil {
				status := http.StatusInternalServerError
				if errors.Is(err, godevauth.ErrNoSession) {
					status = http.StatusUnauthorized
				}
				http.Error(w, http.StatusText(status), status)
				return
			}
			ctx := context.WithValue(r.Context(), userKey{}, sd.User)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	profile := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(userKey{}).(*storage.User)
		fmt.Fprintf(w, "profile of %s\n", user.Email)
	})

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	mux.Handle("/profile", requireUser(profile))

	// Anonymous request.
	anon := httptest.NewRecorder()
	mux.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/profile", nil))
	fmt.Println("anonymous:", anon.Code)

	// Same route with a session.
	signedUp := httptest.NewRecorder()
	signUp := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email",
		strings.NewReader(`{"email":"grace@example.com","password":"correct-horse","name":"Grace"}`))
	signUp.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(signedUp, signUp)

	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	for _, cookie := range signedUp.Result().Cookies() {
		req.AddCookie(cookie)
	}
	authed := httptest.NewRecorder()
	mux.ServeHTTP(authed, req)
	fmt.Print("authenticated: ", authed.Body.String())

	// Output:
	// anonymous: 401
	// authenticated: profile of grace@example.com
}

// Social sign-on: register providers and point them at the callback
// URL this library serves.
func Example_socialSignOn() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		SocialProviders: []oauth2.Provider{
			providers.Google(providers.Credentials{
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret",
			}),
			providers.GitHub(providers.Credentials{
				ClientID:     "github-client-id",
				ClientSecret: "github-client-secret",
				// Appended to the provider's default scopes.
				Scopes: []string{"read:org"},
			}),
		},
		Account: godevauth.AccountConfig{
			AccountLinking: godevauth.AccountLinkingConfig{
				// A verified email from these providers may attach
				// itself to an existing account with the same address.
				TrustedProviders: []string{"google"},
			},
			// Access and refresh tokens are stored encrypted with
			// Config.Secret rather than in the clear.
			EncryptOAuthTokens: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Register this as the redirect URI with each provider. Clients
	// start the flow by POSTing {"provider":"google"} to
	// /api/auth/sign-in/social.
	cfg := auth.Config()
	for _, id := range []string{"google", "github"} {
		fmt.Printf("%s -> %s%s/callback/%s\n", auth.SocialProvider(id).ID(),
			cfg.BaseURL, cfg.BasePath, id)
	}

	// Output:
	// google -> https://example.com/api/auth/callback/google
	// github -> https://example.com/api/auth/callback/github
}

// CORS is needed when the frontend is served from a different origin
// than the API. Credentialed requests cannot use a wildcard, so the
// allowed origins come from Config.TrustedOrigins — the same list the
// CSRF check uses.
func ExampleAuth_CORS() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://api.example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		// The single-page app that talks to this API.
		TrustedOrigins: []string{"https://app.example.com"},
		Advanced: godevauth.AdvancedConfig{
			// A cookie sent on a cross-origin request needs
			// SameSite=None, which browsers only honour on a Secure
			// cookie — hence the https BaseURL above.
			SameSite: "none",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.CORS(auth.Handler()))

	// What the browser sends before a credentialed POST.
	req := httptest.NewRequest(http.MethodOptions,
		"https://api.example.com/api/auth/sign-in/email", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	res := rec.Result()
	fmt.Println(res.StatusCode)
	fmt.Println(res.Header.Get("Access-Control-Allow-Origin"))
	fmt.Println(res.Header.Get("Access-Control-Allow-Credentials"))

	// Output:
	// 204
	// https://app.example.com
	// true
}

// Every security-relevant event is emitted as a typed Event. Route them
// wherever your retention policy requires.
func ExampleEventsConfig() {
	var trail []string

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Events: godevauth.EventsConfig{
			// Handler runs synchronously on the request path, so it
			// must be quick: append to a queue, do not call the network.
			Handler: func(ctx context.Context, e *godevauth.Event) {
				trail = append(trail, fmt.Sprintf("%s %s %s", e.Type, e.Outcome, e.Email))
			},
			// Events also go to Config.Logger by default. Switch that
			// off once you have somewhere better for them: they carry
			// the subject's email address.
			DisableDefaultLogging: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	post := func(path, body string) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		auth.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	post("/api/auth/sign-up/email",
		`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`)
	post("/api/auth/sign-in/email",
		`{"email":"ada@example.com","password":"wrong-password"}`)

	for _, line := range trail {
		fmt.Println(line)
	}

	// Output:
	// sign_up success ada@example.com
	// session.created success ada@example.com
	// sign_in success ada@example.com
	// sign_in failure ada@example.com
}

// Custom columns on the user table. Only fields marked Input are
// writable from a request body; everything else is yours to set from
// the server.
func ExampleUserConfig() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		User: godevauth.UserConfig{
			AdditionalFields: []storage.Field{
				// Input:true accepts this from /sign-up/email and
				// /update-user bodies.
				{Name: "nickname", Type: storage.FieldString, Input: true},
				// No Input: the client cannot set it, but the server
				// and the schema default can.
				{Name: "plan", Type: storage.FieldString, Default: "free"},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	rec := httptest.NewRecorder()
	// "plan":"enterprise" in the body is ignored: the field is not
	// declared Input, so it cannot be self-assigned.
	body := `{"email":"ada@example.com","password":"correct-horse",` +
		`"name":"Ada","nickname":"countess","plan":"enterprise"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth.Handler().ServeHTTP(rec, req)

	user, err := auth.FindUserByEmail(context.Background(), "ada@example.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("nickname:", user.Extra["nickname"])
	fmt.Println("plan:", user.Extra["plan"])

	// Output:
	// nickname: countess
	// plan: free
}

// Behind a reverse proxy the client IP has to be resolved from
// forwarded headers, or every client shares one rate-limit bucket.
// TrustProxyHeaders without TrustedProxies is refused at startup,
// because a forwarded header from an arbitrary peer is client-supplied
// data.
func ExampleAdvancedConfig() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Advanced: godevauth.AdvancedConfig{
			TrustProxyHeaders: true,
			// The addresses or CIDRs of your load balancers. The peer
			// must be in this list before any forwarded header is read.
			TrustedProxies: []string{"10.0.0.0/8"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// A request that came through the load balancer at 10.1.2.3. The
	// chain is walked from the right, skipping trusted hops, so the
	// address a client prepended cannot be mistaken for the client.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/ok", nil)
	req.RemoteAddr = "10.1.2.3:41000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9, 10.1.2.3")

	c := auth.NewCtx(httptest.NewRecorder(), req)
	fmt.Println("client:", c.ClientIP())

	// Output: client: 203.0.113.9
}

// The password reset flow. ResetPasswordURL is mandatory whenever
// SendResetPassword is set: the emailed link points at this library,
// which validates the token and then has to send the user somewhere to
// type a new password.
func ExampleEmailPasswordConfig() {
	var emailed string

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled:           true,
			MinPasswordLength: 12,
			SendResetPassword: func(ctx context.Context, user *storage.User, url, token string) error {
				// Put url in the email verbatim. token is the same
				// value, for clients that render their own link.
				emailed = url
				return nil
			},
			// A path is resolved against BaseURL. An absolute URL also
			// works but must be same-origin with BaseURL or listed in
			// TrustedOrigins — the redirect carries the reset token.
			ResetPasswordURL:            "/choose-password",
			ResetPasswordTokenExpiresIn: 30 * time.Minute,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	post := func(path, body string) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		auth.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	post("/api/auth/sign-up/email",
		`{"email":"ada@example.com","password":"correct-horse-battery","name":"Ada"}`)
	post("/api/auth/forget-password", `{"email":"ada@example.com"}`)

	fmt.Println(strings.HasPrefix(emailed, "https://example.com/api/auth/reset-password/"))

	// Output: true
}

// Rate limiting is on by default and fails closed. Tighten the
// endpoints an attacker would guess against, and share a store between
// processes — the default one only limits per process.
func ExampleRateLimitConfig() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		RateLimit: godevauth.RateLimitConfig{
			Window: 10 * time.Second,
			Max:    100,
			// Keyed by path relative to BasePath.
			CustomRules: map[string]ratelimit.Rule{
				"/sign-in/email": {Window: time.Minute, Max: 5},
			},
			// Replace with a Redis-backed Store when running more than
			// one instance.
			Storage: ratelimit.NewMemoryStore(),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	body := `{"email":"nobody@example.com","password":"correct-horse"}`
	var last int
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		auth.Handler().ServeHTTP(rec, req)
		last = rec.Code
	}
	fmt.Println("sixth attempt:", last)

	// Output: sixth attempt: 429
}

// Expired verification rows and sessions are swept in the background;
// without it the verification table grows forever.
func ExampleAuth_StartCleanup() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	stop := auth.StartCleanup(context.Background(), time.Hour)
	defer stop()

	// Or run a single pass yourself, from a cron job or a test.
	n, err := auth.CleanupExpired(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("rows swept:", n)

	// Output: rows swept: 0
}

// Routes reports every endpoint the instance serves, core plus plugins.
// It is the answer to "what did enabling that plugin actually add?".
func ExampleAuth_Routes() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, rt := range auth.Routes() {
		if rt.Path == "/sign-in/email" || rt.Path == "/get-session" {
			fmt.Println(rt.Method, auth.Config().BasePath+rt.Path)
		}
	}

	// Output:
	// GET /api/auth/get-session
	// POST /api/auth/sign-in/email
}
