package godevauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
	"sync"
)

// TestMassAssignmentBlocked covers the privilege-escalation hole where
// any field on the user table could be set from the request body: a
// self-registering user could send {"role":"admin"} and reach admin
// endpoints, or {"banned":false} to lift their own ban.
func TestMassAssignmentBlocked(t *testing.T) {
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{admin.New(), twofactor.New()}
		cfg.User.AdditionalFields = []storage.Field{
			{Name: "plan", Type: storage.FieldString, Input: true},
			{Name: "credits", Type: storage.FieldInt}, // not client-writable
		}
	})

	// escalation attempt at sign-up
	res, body := tc.post("/sign-up/email", map[string]any{
		"email": "sneaky@example.com", "password": "password123", "name": "Sneaky",
		"role": "admin", "banned": false, "twoFactorEnabled": true,
		"plan": "pro", "credits": 999999,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up: %d %v", res.StatusCode, body)
	}
	user := body["user"].(map[string]any)
	if user["role"] == "admin" {
		t.Error("role was set from the request body at sign-up")
	}
	if user["credits"] == float64(999999) {
		t.Error("a non-Input additional field was set from the request body")
	}
	if user["plan"] != "pro" {
		t.Errorf("declared Input field should be writable, got plan=%v", user["plan"])
	}

	// the account must not reach admin endpoints
	res, _ = tc.get("/admin/list-users")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from admin route, got %d", res.StatusCode)
	}

	// escalation attempt at update-user
	res, body = tc.post("/update-user", map[string]any{
		"name": "Still Sneaky", "role": "admin", "twoFactorEnabled": false,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update-user: %d %v", res.StatusCode, body)
	}
	stored, err := auth.FindUserByEmail(context.Background(), "sneaky@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if role, _ := stored.Extra["role"].(string); role == "admin" {
		t.Error("role was escalated through update-user")
	}
	res, _ = tc.get("/admin/list-users")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 after update-user, got %d", res.StatusCode)
	}
}

// TestRefreshTokenRequiresSession covers the unauthenticated OAuth
// access-token theft: /refresh-token used to accept an arbitrary userId
// from the body and return that user's fresh access token.
func TestRefreshTokenRequiresSession(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	victim := tc.signUp("victim@example.com", "password123", "Victim")
	victimID := victim["user"].(map[string]any)["id"].(string)

	anon := secondClient(t, tc)
	res, _ := anon.post("/refresh-token", map[string]any{
		"providerId": "google", "userId": victimID,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated refresh, got %d", res.StatusCode)
	}
}

// TestSessionTokensNotLeaked asserts raw session tokens never appear in
// session listings, where one XSS or log line would otherwise expose
// every device the user is signed in on.
func TestSessionTokensNotLeaked(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	body := tc.signUp("tokens@example.com", "password123", "Tokens")
	token := body["token"].(string)

	res, list := tc.do(http.MethodGet, "/list-sessions", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list-sessions: %d", res.StatusCode)
	}
	_ = list
	raw := rawBody(t, tc, "/list-sessions")
	if strings.Contains(raw, token) {
		t.Fatalf("/list-sessions leaked a raw session token: %s", raw)
	}
	raw = rawBody(t, tc, "/get-session")
	if strings.Contains(raw, token) {
		t.Fatalf("/get-session leaked a raw session token: %s", raw)
	}
}

func rawBody(t *testing.T, tc *testClient, path string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, tc.server.URL+"/api/auth"+path, nil)
	for _, c := range tc.client.Jar.Cookies(nil) {
		req.AddCookie(c)
	}
	res, err := tc.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := make([]byte, 1<<16)
	n, _ := res.Body.Read(buf)
	return string(buf[:n])
}

// TestChangeEmailFlow covers the flow that was previously broken end to
// end: the approval link stored one token kind and the verify endpoint
// looked up another, so a verified user could never change their email.
func TestChangeEmailFlow(t *testing.T) {
	var approveToken, sentTo string
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.User.ChangeEmail.Enabled = true
		cfg.User.ChangeEmail.SendChangeEmailVerification = func(ctx context.Context, user *storage.User, newEmail, url, token string) error {
			approveToken, sentTo = token, newEmail
			return nil
		}
	})
	body := tc.signUp("old@example.com", "password123", "User")
	userID := body["user"].(map[string]any)["id"].(string)
	if _, err := auth.UpdateUserRecord(context.Background(), userID, map[string]any{"emailVerified": true}); err != nil {
		t.Fatal(err)
	}

	res, out := tc.post("/change-email", map[string]any{"newEmail": "new@example.com"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("change-email: %d %v", res.StatusCode, out)
	}
	if approveToken == "" || sentTo != "new@example.com" {
		t.Fatalf("approval email not sent correctly (token=%q, to=%q)", approveToken, sentTo)
	}

	// address must not change until the link is followed
	user, _ := auth.FindUserByID(context.Background(), userID)
	if user.Email != "old@example.com" {
		t.Fatalf("email changed before approval: %s", user.Email)
	}

	res, out = tc.get("/verify-email?token=" + url.QueryEscape(approveToken))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("approval link failed: %d %v", res.StatusCode, out)
	}
	user, _ = auth.FindUserByID(context.Background(), userID)
	if user.Email != "new@example.com" {
		t.Fatalf("email not applied after approval: %s", user.Email)
	}
	if !user.EmailVerified {
		t.Error("new address should be marked verified")
	}

	// the token is single use
	res, _ = tc.get("/verify-email?token=" + url.QueryEscape(approveToken))
	if res.StatusCode == http.StatusOK {
		t.Error("approval token should be single use")
	}
}

// TestChangeEmailRequiresConfirmation asserts a verified address cannot
// be moved without email confirmation, which previously fell through
// silently when no sender was configured.
func TestChangeEmailRequiresConfirmation(t *testing.T) {
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.User.ChangeEmail.Enabled = true // no SendChangeEmailVerification
	})
	body := tc.signUp("verified@example.com", "password123", "User")
	userID := body["user"].(map[string]any)["id"].(string)
	if _, err := auth.UpdateUserRecord(context.Background(), userID, map[string]any{"emailVerified": true}); err != nil {
		t.Fatal(err)
	}
	res, out := tc.post("/change-email", map[string]any{"newEmail": "attacker@example.com"})
	if res.StatusCode == http.StatusOK {
		t.Fatalf("verified email changed with no confirmation: %v", out)
	}
	user, _ := auth.FindUserByID(context.Background(), userID)
	if user.Email != "verified@example.com" {
		t.Fatalf("email changed to %s", user.Email)
	}
}

// TestOAuthStateBoundToBrowser covers login CSRF: a callback URL
// captured from the attacker's own OAuth flow must not sign a victim in,
// because the victim's browser holds no matching state cookie.
func TestOAuthStateBoundToBrowser(t *testing.T) {
	provider, _ := fakeProvider(t, "fakeco", map[string]any{
		"id": "attacker-1", "name": "Attacker", "email": "attacker@example.com",
		"email_verified": true,
	})
	_, attacker := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
	})

	// attacker starts and completes their own authorization
	res, body := attacker.post("/sign-in/social", map[string]any{"provider": "fakeco"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in/social: %d %v", res.StatusCode, body)
	}
	authURL := body["url"].(string)
	res2, _ := attacker.client.Get(authURL)
	res2.Body.Close()
	callbackURL := res2.Header.Get("Location")
	if callbackURL == "" {
		t.Fatal("provider did not redirect")
	}

	// victim (separate browser, no state cookie) follows the callback
	victim := secondClient(t, attacker)
	res3, err := victim.client.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	res3.Body.Close()
	if loc := res3.Header.Get("Location"); !strings.Contains(loc, "state_mismatch") {
		t.Fatalf("expected state_mismatch, got %q", loc)
	}
	_, session := victim.get("/get-session")
	if session != nil {
		t.Fatal("victim was signed in by a replayed OAuth callback")
	}

	// the legitimate browser still completes successfully
	res4, err := attacker.client.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	res4.Body.Close()
	_, session = attacker.get("/get-session")
	if session == nil {
		t.Fatal("legitimate OAuth callback did not sign the user in")
	}
}

// TestUnverifiedProviderEmailDoesNotLink covers the nOAuth-style
// takeover: a provider asserting an unverified (or self-set) address
// must not be linked to an existing local account.
func TestUnverifiedProviderEmailDoesNotLink(t *testing.T) {
	provider, _ := fakeProvider(t, "fakeco", map[string]any{
		"id": "imposter", "name": "Imposter", "email": "target@example.com",
		"email_verified": true, // asserted, but the provider is not trusted
	})
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
		// deliberately not listing "fakeco" as trusted
		cfg.Account.AccountLinking.TrustedProviders = []string{"google"}
	})
	tc.signUp("target@example.com", "password123", "Target")
	tc.post("/sign-out", map[string]any{})

	_, body := tc.post("/sign-in/social", map[string]any{"provider": "fakeco"})
	res, _ := tc.client.Get(body["url"].(string))
	res.Body.Close()
	res2, _ := tc.client.Get(res.Header.Get("Location"))
	res2.Body.Close()
	if loc := res2.Header.Get("Location"); !strings.Contains(loc, "ACCOUNT_NOT_LINKED") {
		t.Fatalf("expected ACCOUNT_NOT_LINKED, got %q", loc)
	}
	if _, session := tc.get("/get-session"); session != nil {
		t.Fatal("untrusted provider linked into an existing account")
	}
}

// TestCookieCacheDoesNotDeferRevocation covers the cache that refreshed
// itself from cached data, which let a polling client keep a revoked
// session alive for its full lifetime.
func TestCookieCacheDoesNotDeferRevocation(t *testing.T) {
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Session.CookieCache.Enabled = true
		cfg.Session.CookieCache.MaxAge = 50 * time.Millisecond
	})
	body := tc.signUp("cache@example.com", "password123", "Cache")
	userID := body["user"].(map[string]any)["id"].(string)

	// keep polling so the cache would be continuously re-issued
	for i := 0; i < 3; i++ {
		if _, session := tc.get("/get-session"); session == nil {
			t.Fatal("expected a live session")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := auth.RevokeUserSessions(context.Background(), userID); err != nil {
		t.Fatal(err)
	}
	// within one cache window the revocation must take effect
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, session := tc.get("/get-session"); session == nil {
			return // revoked as expected
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("revoked session still served from the cookie cache")
}

// TestSetPasswordRequiresFreshSession covers the session-to-credential
// upgrade. /set-password exists for accounts that have no password, so
// there is nothing to re-authenticate against except the session
// itself: a stolen cookie used to be enough to mint a permanent
// password, which outlives the session's expiry and survives every
// revocation the owner can perform. The endpoint now demands a session
// created inside Session.FreshAge, and drops the user's other sessions
// on success the way /change-password does.
func TestSetPasswordRequiresFreshSession(t *testing.T) {
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Session.FreshAge = time.Hour
	})
	body := tc.signUp("social@example.com", "password123", "Social")
	userID := body["user"].(map[string]any)["id"].(string)

	// A second browser, signed in as the same user. It stands in for the
	// legitimate owner when the first client is the hijacked session.
	other := secondClient(t, tc)
	if res, b := other.post("/sign-in/email", map[string]any{
		"email": "social@example.com", "password": "password123",
	}); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in on the second client: %d %v", res.StatusCode, b)
	}

	// Turn the account into the social-only shape /set-password serves:
	// a user with no credential account at all.
	ctx := context.Background()
	if _, err := auth.Storage().DeleteMany(ctx, storage.ModelAccount,
		[]storage.Where{storage.W("userId", userID)}); err != nil {
		t.Fatal(err)
	}

	sessions, err := auth.ListSessions(ctx, userID)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("ListSessions = %d sessions, %v; want 2", len(sessions), err)
	}
	age := func(d time.Duration) {
		t.Helper()
		for _, s := range sessions {
			if _, err := auth.UpdateSessionRecord(ctx, s.Token,
				map[string]any{"createdAt": time.Now().UTC().Add(-d)}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Past the freshness window: refused, and nothing is written.
	age(2 * time.Hour)
	res, b := tc.post("/set-password", map[string]any{"newPassword": "hijacked-password-1"})
	if res.StatusCode != http.StatusForbidden || b["code"] != "SESSION_NOT_FRESH" {
		t.Fatalf("a stale session set a password: %d %v", res.StatusCode, b)
	}
	if _, err := auth.FindCredentialAccountByUser(ctx, userID); err == nil {
		t.Fatal("a credential account was created from a stale session")
	}

	// Freshly authenticated: allowed.
	age(0)
	res, b = tc.post("/set-password", map[string]any{"newPassword": "chosen-password-1"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("set-password from a fresh session: %d %v", res.StatusCode, b)
	}
	if _, err := auth.FindCredentialAccountByUser(ctx, userID); err != nil {
		t.Fatalf("no credential account after set-password: %v", err)
	}
	// The acting session survives; every other one is gone, so the owner
	// finds out on their next request instead of after the next breach.
	if _, session := tc.get("/get-session"); session == nil {
		t.Fatal("set-password revoked the session that performed it")
	}
	if _, session := other.get("/get-session"); session != nil {
		t.Fatalf("another session survived set-password: %v", session)
	}
}

// TestMethodNotAllowed asserts a known path with the wrong method
// reports 405 with an Allow header rather than a misleading 404.
func TestMethodNotAllowed(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	res, _ := tc.do(http.MethodGet, "/sign-in/email", nil)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", res.StatusCode)
	}
	if allow := res.Header.Get("Allow"); !strings.Contains(allow, http.MethodPost) {
		t.Errorf("Allow header = %q", allow)
	}
}

// TestConfigValidation asserts unsafe or unusable configurations are
// rejected at construction instead of failing subtly in production.
func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  godevauth.Config
	}{
		{"no database", godevauth.Config{BaseURL: "https://x.test", Secret: "0123456789abcdef"}},
		{"no secret", godevauth.Config{BaseURL: "https://x.test", Database: memory.New()}},
		{"short secret", godevauth.Config{BaseURL: "https://x.test", Secret: "short", Database: memory.New()}},
		{"no base url", godevauth.Config{Secret: "0123456789abcdef", Database: memory.New()}},
		{"relative base url", godevauth.Config{BaseURL: "/api", Secret: "0123456789abcdef", Database: memory.New()}},
		{"samesite none without secure", godevauth.Config{
			BaseURL: "http://x.test", Secret: "0123456789abcdef", Database: memory.New(),
			Advanced: godevauth.AdvancedConfig{SameSite: "none"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := godevauth.New(tc.cfg); err == nil {
				t.Fatal("expected New to reject this configuration")
			}
		})
	}
}

// TestTokensStoredHashed asserts one-time tokens are not recoverable
// from the database: read access to a backup or replica must not yield
// working password-reset links.
func TestTokensStoredHashed(t *testing.T) {
	var resetToken string
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.ResetPasswordURL = "/reset"
		cfg.EmailAndPassword.SendResetPassword = func(ctx context.Context, user *storage.User, url, token string) error {
			resetToken = token
			return nil
		}
	})
	tc.signUp("hash@example.com", "password123", "Hash")
	tc.post("/forget-password", map[string]any{"email": "hash@example.com"})
	if resetToken == "" {
		t.Fatal("no reset token issued")
	}
	recs, err := auth.Storage().FindMany(context.Background(), storage.ModelVerification, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("no verification records stored")
	}
	for _, rec := range recs {
		for k, v := range rec {
			if s, ok := v.(string); ok && strings.Contains(s, resetToken) {
				t.Fatalf("raw token found in verification.%s", k)
			}
		}
	}
}

// TestCleanupExpired asserts the sweeper actually collects expired rows,
// so the verification table does not grow without bound.
func TestCleanupExpired(t *testing.T) {
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.ResetPasswordURL = "/reset"
		cfg.EmailAndPassword.SendResetPassword = func(ctx context.Context, user *storage.User, url, token string) error {
			return nil
		}
		cfg.EmailAndPassword.ResetPasswordTokenExpiresIn = time.Millisecond
	})
	tc.signUp("sweep@example.com", "password123", "Sweep")
	tc.post("/forget-password", map[string]any{"email": "sweep@example.com"})
	time.Sleep(10 * time.Millisecond)

	n, err := auth.CleanupExpired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected the sweeper to delete the expired token")
	}
	count, _ := auth.Storage().Count(context.Background(), storage.ModelVerification, nil)
	if count != 0 {
		t.Fatalf("expected 0 verification rows after cleanup, got %d", count)
	}
}

// TestCORSPreflight asserts cross-origin browser clients get usable
// preflight responses for trusted origins only.
func TestCORSPreflight(t *testing.T) {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:          "https://api.test",
		Secret:           "0123456789abcdef0123456789abcdef",
		Database:         memory.New(),
		TrustedOrigins:   []string{"https://app.test"},
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.CORS(auth.Handler())

	req := httptest.NewRequest(http.MethodOptions, "/api/auth/sign-in/email", nil)
	req.Header.Set("Origin", "https://app.test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.test" {
		t.Errorf("allow-origin = %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("allow-credentials = %q", got)
	}

	req = httptest.NewRequest(http.MethodOptions, "/api/auth/sign-in/email", nil)
	req.Header.Set("Origin", "https://evil.test")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("untrusted origin was allowed")
	}
}

// ---------------------------------------------------------------------
// Regression tests for the second security review: session/token
// lifecycle, fail-closed behaviour, and input bounds.
// ---------------------------------------------------------------------

// TestPendingChallengeIsSingleUse covers the two-factor challenge that
// survived its own attempt counter: recording a failed guess appended a
// new verification row, lookups saw only the newest, and consuming
// deleted only that one — so the challenge could be replayed for extra
// sessions and brute-forced past the attempt cap.
func TestPendingChallengeIsSingleUse(t *testing.T) {
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{twofactor.New()}
	})
	tc.signUp("2fa@example.com", "password123", "TF")
	res, body := tc.post("/two-factor/enable", map[string]any{"password": "password123"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enable: %d %v", res.StatusCode, body)
	}
	secret := totpSecretFromURI(t, body["totpURI"].(string))
	code, _ := crypto.TOTP(secret, time.Now(), 30, 6)
	if res, _ := tc.post("/two-factor/verify-totp", map[string]any{"code": code}); res.StatusCode != http.StatusOK {
		t.Fatalf("confirm enable: %d", res.StatusCode)
	}

	// start a fresh challenge
	tc.post("/sign-out", map[string]any{})
	res, body = tc.post("/sign-in/email", map[string]any{
		"email": "2fa@example.com", "password": "password123",
	})
	if body["twoFactorRedirect"] != true {
		t.Fatalf("expected a 2FA challenge, got %v", body)
	}

	// burn the attempt budget with wrong codes
	locked := false
	for i := 0; i < 8; i++ {
		res, body = tc.post("/two-factor/verify-totp", map[string]any{"code": "000000"})
		if body["code"] == "TOO_MANY_ATTEMPTS" {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatal("attempt cap never triggered")
	}
	// After lockout the challenge must be gone: a correct code must not
	// complete it.
	code, _ = crypto.TOTP(secret, time.Now(), 30, 6)
	res, body = tc.post("/two-factor/verify-totp", map[string]any{"code": code})
	if res.StatusCode == http.StatusOK {
		t.Fatalf("a locked-out challenge still accepted the correct code: %v", body)
	}
	if res, sess := tc.get("/get-session"); res.StatusCode == http.StatusOK && sess["user"] != nil {
		t.Fatalf("a session was issued after the challenge was locked out: %v", sess)
	}
	// and no stale pending rows may survive
	n, err := auth.Storage().Count(context.Background(), storage.ModelVerification, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d verification rows left after lockout; the challenge must be fully consumed", n)
	}
}

// TestTokenRedeemedOnlyOnce covers the lookup-then-delete race that let
// concurrent requests all redeem the same one-time token.
func TestTokenRedeemedOnlyOnce(t *testing.T) {
	auth, _ := newTestAuth(t, nil)
	ctx := context.Background()
	token, err := auth.StoreToken(ctx, "test-kind", "the-value", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	redeemed := 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if v, err := auth.ConsumeToken(ctx, "test-kind", token); err == nil && v == "the-value" {
				mu.Lock()
				redeemed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if redeemed != 1 {
		t.Fatalf("%d of %d concurrent callers redeemed the same one-time token, want exactly 1", redeemed, n)
	}
}

// TestStoreTokenValueReplacesPriorRows asserts re-storing a token does
// not leave the previous row redeemable.
func TestStoreTokenValueReplacesPriorRows(t *testing.T) {
	auth, _ := newTestAuth(t, nil)
	ctx := context.Background()
	const token = "fixed-token"
	for i, v := range []string{"first", "second", "third"} {
		if err := auth.StoreTokenValue(ctx, "test-kind", token, v, time.Minute); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	n, _ := auth.Storage().Count(ctx, storage.ModelVerification, nil)
	if n != 1 {
		t.Fatalf("%d rows stored for one token, want 1", n)
	}
	v, err := auth.ConsumeToken(ctx, "test-kind", token)
	if err != nil || v != "third" {
		t.Fatalf("consume = %q %v, want the latest value", v, err)
	}
	if _, err := auth.ConsumeToken(ctx, "test-kind", token); err == nil {
		t.Fatal("token remained redeemable after being consumed")
	}
}

// TestBannedUserBlockedOnCachedSessionAndAPIKey covers two ways a ban
// used to be ignored: a cookie-cache hit skipped the session guards
// entirely, and API keys never ran them at all.
func TestBannedUserBlockedOnCachedSessionAndAPIKey(t *testing.T) {
	adminPlugin := admin.New()
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{adminPlugin, apikey.New()}
		cfg.Session.CookieCache.Enabled = true
		cfg.Session.CookieCache.MaxAge = time.Hour // long enough to hide a ban
	})
	body := tc.signUp("victim@example.com", "password123", "Victim")
	userID := body["user"].(map[string]any)["id"].(string)

	// create an API key while still in good standing
	res, keyBody := tc.post("/api-key/create", map[string]any{"name": "k"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("api-key/create: %d %v", res.StatusCode, keyBody)
	}
	apiKey := keyBody["key"].(string)

	// warm the cookie cache
	if _, session := tc.get("/get-session"); session == nil {
		t.Fatal("expected a live session")
	}

	// ban out of band
	if _, err := auth.UpdateUserRecord(context.Background(), userID, map[string]any{"banned": true}); err != nil {
		t.Fatal(err)
	}

	// the cached cookie must not keep the ban at bay
	res, sess := tc.get("/get-session")
	if res.StatusCode == http.StatusOK && sess["user"] != nil {
		t.Fatalf("banned user still served from the cookie cache: %v", sess)
	}

	// nor may the API key
	req, _ := http.NewRequest(http.MethodGet, tc.server.URL+"/api/auth/get-session", nil)
	req.Header.Set("x-api-key", apiKey)
	apiRes, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer apiRes.Body.Close()
	// A signed-out /get-session answers with the JSON literal null, so
	// the check is on the decoded payload rather than on the body
	// length: "null" is four bytes of "no session", not a short session.
	var apiSess map[string]any
	_ = json.NewDecoder(apiRes.Body).Decode(&apiSess)
	if apiRes.StatusCode == http.StatusOK && apiSess["user"] != nil {
		t.Fatalf("banned user authenticated with an API key: %v", apiSess)
	}
}

// TestUnreadableSecurityFlagsFailClosed asserts that a value of the
// wrong type in a security-deciding column denies access rather than
// granting it.
func TestUnreadableSecurityFlagsFailClosed(t *testing.T) {
	adminPlugin := admin.New()
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{adminPlugin, twofactor.New()}
	})
	body := tc.signUp("weird@example.com", "password123", "Weird")
	userID := body["user"].(map[string]any)["id"].(string)

	// A string where a bool belongs (a corrupted row, a bad migration,
	// a hand-edited record).
	if _, err := auth.Storage().Update(context.Background(), storage.ModelUser,
		[]storage.Where{storage.W("id", userID)},
		map[string]any{"banned": "true", "twoFactorEnabled": "true"}); err != nil {
		t.Fatal(err)
	}
	user, err := auth.FindUserByID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if !adminPlugin.IsAdmin(user) { // sanity: not an admin
		_ = user
	}
	// the ban must be honoured
	res, sess := tc.get("/get-session")
	if res.StatusCode == http.StatusOK && sess["user"] != nil {
		t.Fatalf("unreadable banned flag was treated as 'not banned': %v", sess)
	}
}

// TestReservedAdditionalFieldRejected asserts a configuration that
// would re-open mass assignment is refused at startup.
func TestReservedAdditionalFieldRejected(t *testing.T) {
	for _, name := range []string{"id", "email", "emailVerified", "createdAt"} {
		t.Run(name, func(t *testing.T) {
			_, err := godevauth.New(godevauth.Config{
				BaseURL:  "https://x.test",
				Secret:   "0123456789abcdef0123456789abcdef",
				Database: memory.New(),
				User: godevauth.UserConfig{AdditionalFields: []storage.Field{
					{Name: name, Type: storage.FieldString, Input: true},
				}},
			})
			if err == nil {
				t.Fatalf("AdditionalFields redeclaring the core field %q was accepted", name)
			}
		})
	}
}

// TestAdminSearchInputBounded asserts the admin user search rejects
// oversized needles and unknown filter columns with a 4xx rather than
// scanning the table or returning a 500.
func TestAdminSearchInputBounded(t *testing.T) {
	adminPlugin := admin.New()
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{adminPlugin}
	})
	body := tc.signUp("root@example.com", "password123", "Root")
	rootID := body["user"].(map[string]any)["id"].(string)
	if _, err := auth.UpdateUserRecord(context.Background(), rootID, map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}

	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	res, _ := tc.get("/admin/list-users?searchValue=" + string(long))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized searchValue: got %d, want 400", res.StatusCode)
	}
	res, _ = tc.get("/admin/list-users?filterField=notAColumn&filterValue=x")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown filterField: got %d, want 400", res.StatusCode)
	}
}

func totpSecretFromURI(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("secret")
}

var _ = context.Background
