package magiclink_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/magiclink"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// mailbox captures the links the plugin "sends". Delivery happens on the
// server goroutine while assertions run on the test goroutine, so the
// mutex is what makes reading them safe rather than merely lucky.
type mailbox struct {
	mu       sync.Mutex
	sent     []sentLink
	failWith error
}

type sentLink struct{ email, url, token string }

func (m *mailbox) send(_ context.Context, email, link, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWith != nil {
		return m.failWith
	}
	m.sent = append(m.sent, sentLink{email, link, token})
	return nil
}

func (m *mailbox) last(t *testing.T) sentLink {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no magic link was sent")
	}
	return m.sent[len(m.sent)-1]
}

func (m *mailbox) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// newEnv mounts the plugin with a capturing mail sender.
func newEnv(t *testing.T, opts ...magiclink.Options) (*plugintest.Env, *mailbox) {
	t.Helper()
	box := &mailbox{}
	var o magiclink.Options
	if len(opts) > 0 {
		o = opts[0]
	}
	o.SendMagicLink = box.send
	return plugintest.New(t, magiclink.New(o)), box
}

// requestLink asks for a link and returns the token that was emailed.
func requestLink(t *testing.T, env *plugintest.Env, box *mailbox, body map[string]any) string {
	t.Helper()
	res, out := env.POST("/sign-in/magic-link", body)
	env.RequireStatus(res, out, http.StatusOK)
	return box.last(t).token
}

func TestRoutesAreOpenButYieldNothingWithoutAToken(t *testing.T) {
	env, box := newEnv(t)

	// Both endpoints are anonymous by design: the whole point is signing
	// in without a credential to present up front.
	t.Run("/sign-in/magic-link", func(t *testing.T) {
		anon := env.Client()
		res, body := anon.POST("/sign-in/magic-link", map[string]any{"email": "new@example.com"})
		env.RequireStatus(res, body, http.StatusOK)
		// The response must not contain the token: it is a secret that
		// only the mailbox owner may learn.
		if _, leaked := body["token"]; leaked {
			t.Fatalf("the request response carried the token: %v", body)
		}
		if box.count() != 1 {
			t.Fatalf("emails sent = %d, want 1", box.count())
		}
	})

	t.Run("/magic-link/verify without a token", func(t *testing.T) {
		anon := env.Client()
		res, body := anon.GET("/magic-link/verify")
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_TOKEN")
		if anon.Signed() {
			t.Fatal("a tokenless verify produced a session")
		}
	})
}

func TestEmailedTokenSignsInAndVerifiesTheAddress(t *testing.T) {
	env, box := newEnv(t)
	token := requestLink(t, env, box, map[string]any{
		"email": "magic@example.com", "name": "Magic User",
	})

	link := box.last(t)
	if link.email != "magic@example.com" {
		t.Fatalf("link sent to %q", link.email)
	}
	// The link has to be usable as-is; a link missing its own token is
	// an email nobody can act on.
	if !strings.Contains(link.url, url.QueryEscape(token)) {
		t.Fatalf("link %q does not carry the token", link.url)
	}
	if !strings.Contains(link.url, env.Auth.Config().BasePath+"/magic-link/verify") {
		t.Fatalf("link %q does not point at the verify endpoint", link.url)
	}

	res, body := env.GET("/magic-link/verify?token=" + url.QueryEscape(token))
	env.RequireStatus(res, body, http.StatusOK)

	session := env.Session()
	if session == nil {
		t.Fatal("no session after following the link")
	}
	user, _ := session["user"].(map[string]any)
	if user["email"] != "magic@example.com" || user["name"] != "Magic User" {
		t.Fatalf("session user = %v", user)
	}
	// Clicking the link proves control of the mailbox, so the address is
	// verified; leaving it unverified would demand a second round trip
	// that proves exactly the same thing.
	if user["emailVerified"] != true {
		t.Fatalf("emailVerified = %v, want true", user["emailVerified"])
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	env, box := newEnv(t)
	token := requestLink(t, env, box, map[string]any{"email": "once@example.com"})

	res, body := env.GET("/magic-link/verify?token=" + url.QueryEscape(token))
	env.RequireStatus(res, body, http.StatusOK)

	// A replayed link is the one an attacker finds in a forwarded email
	// or a proxy log, so redeeming it twice must fail.
	second := env.Client()
	res, body = second.GET("/magic-link/verify?token=" + url.QueryEscape(token))
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_TOKEN")
	if second.Signed() {
		t.Fatal("a reused token produced a second session")
	}
	if n := env.Count(storage.ModelUser); n != 1 {
		t.Fatalf("users = %d, want the replay to create nobody", n)
	}
}

func TestUnknownAndExpiredTokensAreRejected(t *testing.T) {
	t.Run("unknown token", func(t *testing.T) {
		env, _ := newEnv(t)
		res, body := env.GET("/magic-link/verify?token=not-a-real-token")
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_TOKEN")
		if env.Signed() {
			t.Fatal("an unknown token produced a session")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		// A negative lifetime stores a token that is already past its
		// expiry, which is what an old email in an inbox looks like.
		env, box := newEnv(t, magiclink.Options{ExpiresIn: -time.Second})
		token := requestLink(t, env, box, map[string]any{"email": "stale@example.com"})

		res, body := env.GET("/magic-link/verify?token=" + url.QueryEscape(token))
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_TOKEN")
		if env.Signed() {
			t.Fatal("an expired token produced a session")
		}
	})
}

func TestDisableSignUpRejectsUnknownAddresses(t *testing.T) {
	env, box := newEnv(t, magiclink.Options{DisableSignUp: true})

	// An address with no account must be refused before any mail goes
	// out, otherwise the endpoint is a way to register anyone.
	res, body := env.POST("/sign-in/magic-link", map[string]any{"email": "stranger@example.com"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "USER_NOT_FOUND")
	if box.count() != 0 {
		t.Fatalf("emails sent = %d, want none", box.count())
	}
	if n := env.Count(storage.ModelUser); n != 0 {
		t.Fatalf("users = %d, want none created", n)
	}

	// An existing account still works.
	env.SignUp("known@example.com", "password123")
	env.SignOut()
	token := requestLink(t, env, box, map[string]any{"email": "known@example.com"})
	res, body = env.GET("/magic-link/verify?token=" + url.QueryEscape(token))
	env.RequireStatus(res, body, http.StatusOK)
	if !env.Signed() {
		t.Fatal("an existing user could not sign in with a magic link")
	}
}

func TestRequestBodyValidation(t *testing.T) {
	env, box := newEnv(t)

	cases := []struct {
		name   string
		body   any
		status int
		code   string
	}{
		{"missing body", nil, http.StatusBadRequest, "INVALID_BODY"},
		{"non-object body", "just-a-string", http.StatusBadRequest, "INVALID_BODY"},
		{"no email", map[string]any{"name": "Nobody"}, http.StatusBadRequest, "INVALID_EMAIL"},
		{"empty email", map[string]any{"email": ""}, http.StatusBadRequest, "INVALID_EMAIL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, body := env.POST("/sign-in/magic-link", tc.body)
			env.RequireErrorCode(res, body, tc.status, tc.code)
		})
	}
	if box.count() != 0 {
		t.Fatalf("emails sent = %d, want none for rejected requests", box.count())
	}
}

func TestDeliveryFailureIsReportedNotSwallowed(t *testing.T) {
	env, box := newEnv(t)
	box.mu.Lock()
	box.failWith = context.DeadlineExceeded
	box.mu.Unlock()

	// A caller that gets 200 while the mail never left would show the
	// user a "check your inbox" screen forever.
	res, body := env.POST("/sign-in/magic-link", map[string]any{"email": "nomail@example.com"})
	env.RequireErrorCode(res, body, http.StatusInternalServerError, "FAILED_TO_SEND_EMAIL")
}

func TestCallbackRedirects(t *testing.T) {
	env, box := newEnv(t)

	t.Run("new users can be sent somewhere else", func(t *testing.T) {
		token := requestLink(t, env, box, map[string]any{
			"email":              "fresh@example.com",
			"callbackURL":        "/dashboard",
			"newUserCallbackURL": "/onboarding",
		})
		res, body := env.GET("/magic-link/verify?token=" + url.QueryEscape(token))
		env.RequireStatus(res, body, http.StatusFound)
		if got := res.Header.Get("Location"); !strings.HasSuffix(got, "/onboarding") {
			t.Fatalf("Location = %q, want the new-user callback", got)
		}
	})

	t.Run("returning users go to the normal callback", func(t *testing.T) {
		client := env.Client()
		res, out := client.POST("/sign-in/magic-link", map[string]any{
			"email": "fresh@example.com", "callbackURL": "/dashboard",
		})
		env.RequireStatus(res, out, http.StatusOK)
		token := box.last(t).token
		res, body := client.GET("/magic-link/verify?token=" + url.QueryEscape(token))
		env.RequireStatus(res, body, http.StatusFound)
		if got := res.Header.Get("Location"); !strings.HasSuffix(got, "/dashboard") {
			t.Fatalf("Location = %q, want the callback", got)
		}
	})

	t.Run("a bad token redirects with an error instead of signing in", func(t *testing.T) {
		client := env.Client()
		res, _ := client.GET("/magic-link/verify?token=bogus&callbackURL=/login")
		if res.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want a redirect", res.StatusCode)
		}
		if got := res.Header.Get("Location"); !strings.Contains(got, "error=INVALID_TOKEN") {
			t.Fatalf("Location = %q, want an error marker", got)
		}
		if client.Signed() {
			t.Fatal("a failed verification still created a session")
		}
	})
}

func TestUntrustedCallbackIsNotFollowed(t *testing.T) {
	env, box := newEnv(t)
	token := requestLink(t, env, box, map[string]any{
		"email":       "redirect@example.com",
		"callbackURL": "https://evil.example.com/steal",
	})

	// An attacker who can seed the callback would otherwise turn the
	// sign-in link into an open redirect that lands on their page with
	// the session already established.
	res, body := env.GET("/magic-link/verify?token=" + url.QueryEscape(token))
	if res.StatusCode == http.StatusFound {
		t.Fatalf("redirected to an untrusted origin: %q", res.Header.Get("Location"))
	}
	env.RequireStatus(res, body, http.StatusOK)
	if !env.Signed() {
		t.Fatal("the sign-in itself should still succeed")
	}
}

func TestExistingUnverifiedAddressBecomesVerified(t *testing.T) {
	env, box := newEnv(t)
	user := env.SignUp("pending@example.com", "password123")
	if user.EmailVerified {
		t.Fatal("the fixture user should start out unverified")
	}
	env.SignOut()

	token := requestLink(t, env, box, map[string]any{"email": "pending@example.com"})
	res, body := env.GET("/magic-link/verify?token=" + url.QueryEscape(token))
	env.RequireStatus(res, body, http.StatusOK)

	// The same account, now verified: a magic link must not fork a
	// second user for an address that already exists.
	if n := env.Count(storage.ModelUser); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
	reloaded, err := env.Auth.FindUserByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.EmailVerified {
		t.Fatal("following the link did not verify the address")
	}
}

func TestPluginRequiresASender(t *testing.T) {
	// Without a sender the plugin would accept requests and mail
	// nothing, which fails silently at runtime instead of at boot.
	_, err := godevauth.New(godevauth.Config{
		BaseURL:  "http://127.0.0.1",
		Secret:   "magiclink-test-secret-0123456789abc",
		Database: memory.New(),
		Plugins:  []godevauth.Plugin{magiclink.New(magiclink.Options{})},
	})
	if err == nil {
		t.Fatal("building Auth without SendMagicLink succeeded")
	}
	if !strings.Contains(err.Error(), "SendMagicLink") {
		t.Fatalf("error = %v, want it to name the missing option", err)
	}
}

// TestMagicLinkValidatesEmail is the sibling of the admin create-user
// gap: with sign-up enabled, a magic link creates the account on first
// use, so a malformed address must be rejected before any link is sent —
// otherwise it becomes a user who can never receive a link again.
func TestMagicLinkValidatesEmail(t *testing.T) {
	env, box := newEnv(t)

	res, body := env.POST("/sign-in/magic-link", map[string]any{"email": "not-an-email"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_EMAIL")
	if box.count() != 0 {
		t.Fatalf("a link was sent to a malformed address: %d", box.count())
	}

	// a valid address still works
	res, body = env.POST("/sign-in/magic-link", map[string]any{"email": "good@example.com"})
	env.RequireStatus(res, body, http.StatusOK)
}
