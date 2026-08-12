package twofactor_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

const (
	userEmail    = "tf@example.com"
	userPassword = "password123"
)

// newEnv returns an environment with the two-factor plugin mounted and a
// signed-in user who has not enrolled yet.
func newEnv(t *testing.T, opts ...twofactor.Options) *plugintest.Env {
	t.Helper()
	env := plugintest.New(t, twofactor.New(opts...))
	env.SignUp(userEmail, userPassword)
	return env
}

// enroll completes enrolment and returns the TOTP secret and the backup
// codes handed to the user. After this the account really requires a
// second factor at sign-in.
func enroll(t *testing.T, env *plugintest.Env) (secret string, backupCodes []string) {
	t.Helper()
	res, body := env.POST("/two-factor/enable", map[string]any{"password": userPassword})
	env.RequireStatus(res, body, http.StatusOK)
	secret = secretFromURI(t, body["totpURI"])
	for _, c := range body["backupCodes"].([]any) {
		backupCodes = append(backupCodes, c.(string))
	}

	res, body = env.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	env.RequireStatus(res, body, http.StatusOK)
	return secret, backupCodes
}

// challenge signs in far enough to be handed a pending second-factor
// challenge, and asserts that no session exists yet.
func challenge(t *testing.T, env *plugintest.Env) *plugintest.Env {
	t.Helper()
	client := env.Client()
	res, body := client.SignIn(userEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] != true {
		t.Fatalf("sign-in = %v, want a pending second factor", body)
	}
	// A password alone must not be enough; if a session existed here the
	// second factor would be decorative.
	if client.Signed() {
		t.Fatal("a session was issued before the second factor")
	}
	return client
}

func TestRoutesRequireAuthentication(t *testing.T) {
	env := newEnv(t)

	// Every endpoint either manages the enrolled secret (needs a
	// session) or completes a challenge (needs the pending cookie).
	// Neither is available to an anonymous caller.
	paths := []string{
		"/two-factor/enable",
		"/two-factor/disable",
		"/two-factor/get-totp-uri",
		"/two-factor/generate-backup-codes",
		"/two-factor/verify-totp",
		"/two-factor/verify-backup-code",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			anon := env.Client()
			res, body := anon.POST(path, map[string]any{
				"password": userPassword, "code": "000000",
			})
			env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")
		})
	}
}

func TestManagementRoutesRequireThePassword(t *testing.T) {
	env := newEnv(t)

	// Re-authentication is what stops a stolen session cookie from
	// silently swapping or removing the second factor.
	paths := []string{
		"/two-factor/enable",
		"/two-factor/disable",
		"/two-factor/get-totp-uri",
		"/two-factor/generate-backup-codes",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			res, body := env.POST(path, map[string]any{"password": "wrong-password"})
			env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_PASSWORD")

			res, body = env.POST(path, map[string]any{})
			env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_PASSWORD")

			res, body = env.POST(path, nil)
			env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_BODY")
		})
	}
}

func TestSecretRoutesRefuseWhenNotEnrolled(t *testing.T) {
	env := newEnv(t)

	// The correct password must not conjure a secret that was never
	// generated.
	for _, path := range []string{"/two-factor/get-totp-uri", "/two-factor/generate-backup-codes"} {
		t.Run(path, func(t *testing.T) {
			res, body := env.POST(path, map[string]any{"password": userPassword})
			env.RequireErrorCode(res, body, http.StatusBadRequest, "TWO_FACTOR_NOT_ENABLED")
		})
	}
	res, body := env.POST("/two-factor/verify-totp", map[string]any{"code": "000000"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "TWO_FACTOR_NOT_ENABLED")
}

func TestEnableIssuesASecretAndBackupCodes(t *testing.T) {
	env := newEnv(t)
	res, body := env.POST("/two-factor/enable", map[string]any{"password": userPassword})
	env.RequireStatus(res, body, http.StatusOK)

	secret := secretFromURI(t, body["totpURI"])
	// The URI is what the authenticator app scans; without a usable
	// secret in it enrolment silently produces codes nobody can match.
	if _, err := crypto.TOTP(secret, time.Now(), 30, 6); err != nil {
		t.Fatalf("the issued secret does not generate codes: %v", err)
	}

	codes, _ := body["backupCodes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("backup codes = %d, want 10", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		code := c.(string)
		if seen[code] {
			t.Fatalf("backup code %q was issued twice", code)
		}
		seen[code] = true
	}

	// The secret is stored encrypted: database read access alone must
	// not yield a working second factor.
	rec, err := env.Auth.Storage().FindOne(context.Background(), twofactor.ModelTwoFactor, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stored, _ := rec["secret"].(string); stored == secret {
		t.Fatal("the TOTP secret is stored in plaintext")
	}
	if stored, _ := rec["backupCodes"].(string); stored == "" {
		t.Fatal("no backup codes were stored")
	} else if containsAny(stored, codes) {
		t.Fatal("backup codes are stored in plaintext")
	}
}

func TestEnrolmentTakesEffectOnlyAfterVerification(t *testing.T) {
	env := newEnv(t)
	res, body := env.POST("/two-factor/enable", map[string]any{"password": userPassword})
	env.RequireStatus(res, body, http.StatusOK)
	secret := secretFromURI(t, body["totpURI"])

	// Enrolling without proving the app works would lock the user out of
	// their own account, so sign-in stays unchanged until they do.
	env.SignOut()
	res, body = env.SignIn(userEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] == true {
		t.Fatal("sign-in demanded a second factor before enrolment was confirmed")
	}

	res, body = env.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	env.RequireStatus(res, body, http.StatusOK)

	env.SignOut()
	res, body = env.SignIn(userEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] != true {
		t.Fatalf("sign-in = %v, want a second factor after confirmation", body)
	}
}

func TestCorrectTOTPCompletesSignIn(t *testing.T) {
	env := newEnv(t)
	secret, _ := enroll(t, env)

	client := challenge(t, env)
	res, body := client.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	env.RequireStatus(res, body, http.StatusOK)
	if body["token"] == nil {
		t.Fatalf("verify-totp = %v, want a session token", body)
	}

	session := client.Session()
	if session == nil {
		t.Fatal("no session after passing the second factor")
	}
	if user, _ := session["user"].(map[string]any); user["email"] != userEmail {
		t.Fatalf("session belongs to %v", user)
	}
}

func TestWrongCodeIsRefused(t *testing.T) {
	env := newEnv(t)
	enroll(t, env)
	client := challenge(t, env)

	res, body := client.POST("/two-factor/verify-totp", map[string]any{"code": "000000"})
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE")
	if client.Signed() {
		t.Fatal("a wrong code produced a session")
	}

	res, body = client.POST("/two-factor/verify-backup-code", map[string]any{"code": "nope-nope"})
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE")
	if client.Signed() {
		t.Fatal("a wrong backup code produced a session")
	}
}

func TestAttemptCapDiscardsTheChallenge(t *testing.T) {
	env := newEnv(t)
	secret, _ := enroll(t, env)
	client := challenge(t, env)

	// Four guesses are merely wrong; the fifth exhausts the budget. The
	// cap is what keeps a six-digit code out of reach during the ten
	// minutes a challenge lives.
	for i := 0; i < 4; i++ {
		res, body := client.POST("/two-factor/verify-totp", map[string]any{"code": "000000"})
		env.RequireErrorCode(res, body, http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE")
	}
	res, body := client.POST("/two-factor/verify-totp", map[string]any{"code": "000000"})
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "TOO_MANY_ATTEMPTS")

	// The challenge is gone, so even the right code cannot revive it.
	res, body = client.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")
	if client.Signed() {
		t.Fatal("the discarded challenge still yielded a session")
	}
}

func TestBackupCodeWorksExactlyOnce(t *testing.T) {
	env := newEnv(t)
	_, codes := enroll(t, env)
	code := codes[0]

	client := challenge(t, env)
	res, body := client.POST("/two-factor/verify-backup-code", map[string]any{"code": code})
	env.RequireStatus(res, body, http.StatusOK)
	if !client.Signed() {
		t.Fatal("a valid backup code did not sign the user in")
	}

	// A backup code is single-use: one written on a piece of paper that
	// someone photographs must not keep working.
	replay := challenge(t, env)
	res, body = replay.POST("/two-factor/verify-backup-code", map[string]any{"code": code})
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE")
	if replay.Signed() {
		t.Fatal("a spent backup code produced a session")
	}

	// The other codes are untouched.
	other := challenge(t, env)
	res, body = other.POST("/two-factor/verify-backup-code", map[string]any{"code": codes[1]})
	env.RequireStatus(res, body, http.StatusOK)
}

func TestRegeneratingBackupCodesRetiresTheOldOnes(t *testing.T) {
	env := newEnv(t)
	_, old := enroll(t, env)

	res, body := env.POST("/two-factor/generate-backup-codes", map[string]any{"password": userPassword})
	env.RequireStatus(res, body, http.StatusOK)
	fresh, _ := body["backupCodes"].([]any)
	if len(fresh) != 10 {
		t.Fatalf("regenerated codes = %d, want 10", len(fresh))
	}

	// Regeneration is how a user responds to a leaked sheet of codes; if
	// the old ones survived it would achieve nothing.
	client := challenge(t, env)
	res, body = client.POST("/two-factor/verify-backup-code", map[string]any{"code": old[0]})
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE")

	client = challenge(t, env)
	res, body = client.POST("/two-factor/verify-backup-code", map[string]any{"code": fresh[0].(string)})
	env.RequireStatus(res, body, http.StatusOK)
}

func TestChallengeIsBoundToTheBrowserThatStartedIt(t *testing.T) {
	env := newEnv(t)
	secret, codes := enroll(t, env)
	challenge(t, env) // the pending cookie lives on that client only

	cookieName := env.Auth.Config().Advanced.CookiePrefix + ".two_factor_pending"
	cases := []struct{ name, cookie string }{
		{"no pending cookie", ""},
		{"forged cookie value", cookieName + "=forged-token"},
		{"empty cookie value", cookieName + "="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Somebody else's browser, holding the right code but no
			// proof that they passed the password step.
			outsider := env.Client()
			var res *http.Response
			var body map[string]any
			payload := map[string]any{"code": totp(t, secret)}
			if tc.cookie == "" {
				res, body = outsider.POST("/two-factor/verify-totp", payload)
			} else {
				res, body = outsider.POST("/two-factor/verify-totp", payload, "Cookie", tc.cookie)
			}
			env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")

			payload = map[string]any{"code": codes[0]}
			if tc.cookie == "" {
				res, body = outsider.POST("/two-factor/verify-backup-code", payload)
			} else {
				res, body = outsider.POST("/two-factor/verify-backup-code", payload, "Cookie", tc.cookie)
			}
			env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")
			if outsider.Signed() {
				t.Fatal("an unbound client completed somebody else's challenge")
			}
		})
	}
}

func TestDisableRemovesTheRequirement(t *testing.T) {
	env := newEnv(t)
	enroll(t, env)

	res, body := env.POST("/two-factor/disable", map[string]any{"password": userPassword})
	env.RequireStatus(res, body, http.StatusOK)

	// The stored secret must go with it; leaving it behind would let a
	// later re-enable resurrect a secret the user thought was gone.
	if n := env.Count(twofactor.ModelTwoFactor); n != 0 {
		t.Fatalf("stored two-factor records = %d, want 0", n)
	}

	env.SignOut()
	res, body = env.SignIn(userEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] == true {
		t.Fatal("sign-in still demands a second factor after disabling")
	}
	if !env.Signed() {
		t.Fatal("no session after signing in with two-factor disabled")
	}
}

func TestSkipVerificationOnEnable(t *testing.T) {
	env := newEnv(t, twofactor.Options{SkipVerificationOnEnable: true})
	res, body := env.POST("/two-factor/enable", map[string]any{"password": userPassword})
	env.RequireStatus(res, body, http.StatusOK)
	secret := secretFromURI(t, body["totpURI"])

	// With the option set, enrolment is immediate: no confirming code.
	env.SignOut()
	res, body = env.SignIn(userEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] != true {
		t.Fatalf("sign-in = %v, want an immediate second factor", body)
	}
	res, body = env.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	env.RequireStatus(res, body, http.StatusOK)
}

func TestEmailOTPRoutesExistOnlyWhenConfigured(t *testing.T) {
	t.Run("absent without a sender", func(t *testing.T) {
		env := newEnv(t)
		// An endpoint that exists but cannot deliver is worse than no
		// endpoint: clients would offer the user an option that fails.
		for _, path := range []string{"/two-factor/send-otp", "/two-factor/verify-otp"} {
			res, body := env.POST(path, map[string]any{"code": "000000"})
			env.RequireErrorCode(res, body, http.StatusNotFound, "NOT_FOUND")
		}
	})

	t.Run("complete a sign-in when configured", func(t *testing.T) {
		box := &otpbox{}
		env := newEnv(t, twofactor.Options{SendOTP: box.send})
		enroll(t, env)
		client := challenge(t, env)

		res, body := client.POST("/two-factor/send-otp", map[string]any{})
		env.RequireStatus(res, body, http.StatusOK)
		code := box.last(t)

		res, body = client.POST("/two-factor/verify-otp", map[string]any{"code": "999999"})
		env.RequireErrorCode(res, body, http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE")

		res, body = client.POST("/two-factor/verify-otp", map[string]any{"code": code})
		env.RequireStatus(res, body, http.StatusOK)
		if !client.Signed() {
			t.Fatal("a correct emailed OTP did not complete the sign-in")
		}

		// The OTP is consumed with the session it produced.
		replay := challenge(t, env)
		res, body = replay.POST("/two-factor/verify-otp", map[string]any{"code": code})
		if res.StatusCode == http.StatusOK {
			t.Fatalf("a spent OTP was accepted again: %v", body)
		}
	})
}

func TestPluginRegistersItsSchemaAndGuard(t *testing.T) {
	env := newEnv(t)

	// The sign-in guard is what makes the second factor unskippable
	// across every sign-in path, and the user column is what it reads.
	var _ godevauth.SignInGuard = twofactor.New()
	table := env.Auth.Schema().Tables[storage.ModelUser]
	if table == nil || table.FieldByName("twoFactorEnabled") == nil {
		t.Fatal("the plugin did not add twoFactorEnabled to the user table")
	}
}

// otpbox captures emailed one-time codes. The sender runs on the server
// goroutine, so the mutex is what makes reading them safe.
type otpbox struct {
	mu    sync.Mutex
	codes []string
}

func (b *otpbox) send(_ context.Context, _ *storage.User, otp string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.codes = append(b.codes, otp)
	return nil
}

func (b *otpbox) last(t *testing.T) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.codes) == 0 {
		t.Fatal("no OTP was sent")
	}
	return b.codes[len(b.codes)-1]
}

// secretFromURI pulls the shared secret out of an otpauth:// URI, the
// way an authenticator app does when it scans the QR code.
func secretFromURI(t *testing.T, raw any) string {
	t.Helper()
	uri, _ := raw.(string)
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parsing totpURI %q: %v", uri, err)
	}
	if u.Scheme != "otpauth" {
		t.Fatalf("totpURI = %q, want an otpauth:// URI", uri)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatalf("totpURI %q carries no secret", uri)
	}
	return secret
}

func totp(t *testing.T, secret string) string {
	t.Helper()
	code, err := crypto.TOTP(secret, time.Now(), 30, 6)
	if err != nil {
		t.Fatalf("generating a TOTP code: %v", err)
	}
	return code
}

func containsAny(haystack string, needles []any) bool {
	for _, n := range needles {
		if s, ok := n.(string); ok && s != "" && strings.Contains(haystack, s) {
			return true
		}
	}
	return false
}
