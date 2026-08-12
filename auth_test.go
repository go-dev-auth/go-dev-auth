package godevauth_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

func TestSignUpAndSignIn(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	body := tc.signUp("alice@example.com", "password123", "Alice")
	user, _ := body["user"].(map[string]any)
	if user["email"] != "alice@example.com" {
		t.Fatalf("user = %v", user)
	}
	if body["token"] == nil {
		t.Fatal("expected auto sign-in token")
	}

	// duplicate sign up fails
	res, _ := tc.post("/sign-up/email", map[string]any{
		"email": "alice@example.com", "password": "password123", "name": "Alice",
	})
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for duplicate, got %d", res.StatusCode)
	}

	// session is live
	res, session := tc.get("/get-session")
	if res.StatusCode != http.StatusOK || session == nil {
		t.Fatalf("get-session: %d %v", res.StatusCode, session)
	}
	if session["user"].(map[string]any)["email"] != "alice@example.com" {
		t.Fatalf("session user = %v", session["user"])
	}

	// sign out
	tc.post("/sign-out", map[string]any{})
	res, _ = tc.get("/get-session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get-session after sign-out: %d", res.StatusCode)
	}

	// sign in wrong password
	res, _ = tc.post("/sign-in/email", map[string]any{
		"email": "alice@example.com", "password": "wrong-password",
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}

	// sign in correct
	res, body = tc.post("/sign-in/email", map[string]any{
		"email": "alice@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusOK || body["token"] == nil {
		t.Fatalf("sign-in: %d %v", res.StatusCode, body)
	}
}

func TestPasswordValidation(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	res, body := tc.post("/sign-up/email", map[string]any{
		"email": "short@example.com", "password": "short", "name": "S",
	})
	if res.StatusCode != http.StatusBadRequest || body["code"] != "PASSWORD_TOO_SHORT" {
		t.Fatalf("expected PASSWORD_TOO_SHORT, got %d %v", res.StatusCode, body)
	}
	res, body = tc.post("/sign-up/email", map[string]any{
		"email": "bademail", "password": "password123", "name": "B",
	})
	if res.StatusCode != http.StatusBadRequest || body["code"] != "INVALID_EMAIL" {
		t.Fatalf("expected INVALID_EMAIL, got %d %v", res.StatusCode, body)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	var resetURL, resetToken string
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.ResetPasswordURL = "/new-password"
		cfg.EmailAndPassword.SendResetPassword = func(ctx context.Context, user *storage.User, url, token string) error {
			resetURL, resetToken = url, token
			return nil
		}
	})
	tc.signUp("bob@example.com", "password123", "Bob")

	res, _ := tc.post("/forget-password", map[string]any{"email": "bob@example.com"})
	if res.StatusCode != http.StatusOK || resetToken == "" {
		t.Fatalf("forget-password: %d, token %q", res.StatusCode, resetToken)
	}
	if !strings.Contains(resetURL, resetToken) {
		t.Fatalf("reset URL %q missing token", resetURL)
	}

	// unknown email should not leak
	res, _ = tc.post("/forget-password", map[string]any{"email": "nobody@example.com"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("forget-password unknown: %d", res.StatusCode)
	}

	// reset with bad token
	res, _ = tc.post("/reset-password", map[string]any{
		"newPassword": "newpassword456", "token": "bogus",
	})
	if res.StatusCode == http.StatusOK {
		t.Fatal("expected bad token to fail")
	}

	// reset with real token
	res, _ = tc.post("/reset-password", map[string]any{
		"newPassword": "newpassword456", "token": resetToken,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password: %d", res.StatusCode)
	}

	// old password dead, new works
	res, _ = tc.post("/sign-in/email", map[string]any{
		"email": "bob@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password still works: %d", res.StatusCode)
	}
	res, _ = tc.post("/sign-in/email", map[string]any{
		"email": "bob@example.com", "password": "newpassword456",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("new password rejected: %d", res.StatusCode)
	}

	// token single use
	res, _ = tc.post("/reset-password", map[string]any{
		"newPassword": "anotherpass789", "token": resetToken,
	})
	if res.StatusCode == http.StatusOK {
		t.Fatal("expected reset token to be single use")
	}
}

func TestEmailVerificationFlow(t *testing.T) {
	var verifyToken string
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.RequireEmailVerification = true
		cfg.EmailVerification.SendOnSignUp = true
		cfg.EmailVerification.SendVerificationEmail = func(ctx context.Context, user *storage.User, url, token string) error {
			verifyToken = token
			return nil
		}
	})
	res, body := tc.post("/sign-up/email", map[string]any{
		"email": "carol@example.com", "password": "password123", "name": "Carol",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up: %d %v", res.StatusCode, body)
	}
	if body["token"] != nil {
		t.Fatal("expected no session before verification")
	}
	if verifyToken == "" {
		t.Fatal("expected verification email")
	}

	// sign-in blocked before verification
	res, body = tc.post("/sign-in/email", map[string]any{
		"email": "carol@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusForbidden || body["code"] != "EMAIL_NOT_VERIFIED" {
		t.Fatalf("expected EMAIL_NOT_VERIFIED, got %d %v", res.StatusCode, body)
	}

	// verify
	res, body = tc.get("/verify-email?token=" + url.QueryEscape(verifyToken))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify-email: %d %v", res.StatusCode, body)
	}

	// now sign-in works
	res, _ = tc.post("/sign-in/email", map[string]any{
		"email": "carol@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in after verify: %d", res.StatusCode)
	}
}

func TestChangePasswordAndSessions(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	tc.signUp("dave@example.com", "password123", "Dave")

	res, _ := tc.post("/change-password", map[string]any{
		"currentPassword": "wrong", "newPassword": "changed456",
	})
	if res.StatusCode == http.StatusOK {
		t.Fatal("expected wrong current password to fail")
	}
	res, _ = tc.post("/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "changed456",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("change-password: %d", res.StatusCode)
	}

	res, _ = tc.get("/list-sessions")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list-sessions: %d", res.StatusCode)
	}

	res, _ = tc.post("/revoke-other-sessions", map[string]any{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke-other-sessions: %d", res.StatusCode)
	}

	res, _ = tc.post("/revoke-sessions", map[string]any{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke-sessions: %d", res.StatusCode)
	}
	// all sessions revoked -> unauthenticated
	res, session := tc.get("/get-session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get-session: %d", res.StatusCode)
	}
	if session != nil {
		t.Fatalf("expected nil session, got %v", session)
	}
}

func TestUpdateUser(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.User.AdditionalFields = []storage.Field{
			// Input marks the field as client-writable; without it the
			// value is ignored (see TestMassAssignmentBlocked).
			{Name: "favoriteColor", Type: storage.FieldString, Input: true},
		}
	})
	tc.signUp("erin@example.com", "password123", "Erin")
	res, body := tc.post("/update-user", map[string]any{
		"name": "Erin Updated", "favoriteColor": "green",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update-user: %d %v", res.StatusCode, body)
	}
	user := body["user"].(map[string]any)
	if user["name"] != "Erin Updated" {
		t.Errorf("name = %v", user["name"])
	}
	if user["favoriteColor"] != "green" {
		t.Errorf("favoriteColor = %v", user["favoriteColor"])
	}
}

func TestCSRFOriginCheck(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	res, body := tc.do(http.MethodPost, "/sign-up/email", map[string]any{
		"email": "eve@example.com", "password": "password123", "name": "Eve",
	}, "Origin", "https://evil.example.com")
	if res.StatusCode != http.StatusForbidden || body["code"] != "INVALID_ORIGIN" {
		t.Fatalf("expected INVALID_ORIGIN, got %d %v", res.StatusCode, body)
	}
	// same-origin passes
	res, _ = tc.do(http.MethodPost, "/sign-up/email", map[string]any{
		"email": "eve@example.com", "password": "password123", "name": "Eve",
	}, "Origin", tc.server.URL)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("same-origin blocked: %d", res.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.RateLimit.Disabled = false
	})
	var last int
	var lastBody map[string]any
	for i := 0; i < 5; i++ {
		res, body := tc.post("/sign-in/email", map[string]any{
			"email": "nobody@example.com", "password": "password123",
		})
		last = res.StatusCode
		lastBody = body
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after burst, got %d %v", last, lastBody)
	}
}

func TestSignUpDisabled(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.DisableSignUp = true
	})
	res, body := tc.post("/sign-up/email", map[string]any{
		"email": "x@example.com", "password": "password123", "name": "X",
	})
	if res.StatusCode != http.StatusForbidden || body["code"] != "SIGNUP_DISABLED" {
		t.Fatalf("expected SIGNUP_DISABLED, got %d %v", res.StatusCode, body)
	}
}

func TestNotFoundAndOK(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	res, _ := tc.get("/ok")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/ok: %d", res.StatusCode)
	}
	res, _ = tc.get("/definitely-not-a-route")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestServerSideHelpers(t *testing.T) {
	auth, tc := newTestAuth(t, nil)
	tc.signUp("frank@example.com", "password123", "Frank")

	// server-side session lookup from a request carrying the cookie
	req, _ := http.NewRequest(http.MethodGet, tc.server.URL+"/api/auth/get-session", nil)
	for _, c := range tc.client.Jar.Cookies(nil) {
		req.AddCookie(c)
	}
	sd, err := auth.GetSession(req)
	if err != nil {
		t.Fatal(err)
	}
	if sd.User.Email != "frank@example.com" {
		t.Errorf("user = %v", sd.User.Email)
	}
	if !auth.IsFresh(sd.Session) {
		t.Error("expected fresh session")
	}
}

// ExampleNew and the rest of the package's runnable examples live in
// example_test.go.

// TestEmailedResetLinkIsFollowable follows the password-reset link the
// way a user does — by fetching the exact URL that arrived in the email
// — instead of posting the token straight to /reset-password.
//
// That distinction is the whole point of this test. TestPasswordResetFlow
// exercised the API but never fetched the link, so it stayed green while
// the advertised flow was broken: without a callbackURL the redirect
// endpoint sent every user to the generic error page. A reset flow is
// only working if the thing in the email works.
func TestEmailedResetLinkIsFollowable(t *testing.T) {
	var emailed string
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.ResetPasswordURL = "/choose-password"
		cfg.EmailAndPassword.SendResetPassword = func(ctx context.Context, u *storage.User, link, token string) error {
			emailed = link
			return nil
		}
	})
	tc.signUp("linkuser@example.com", "password123", "Link User")

	// Note: no "redirectTo". That is the default case, and the one that
	// used to dead-end.
	if res, _ := tc.post("/forget-password", map[string]any{
		"email": "linkuser@example.com",
	}); res.StatusCode != http.StatusOK {
		t.Fatalf("forget-password: %d", res.StatusCode)
	}
	if emailed == "" {
		t.Fatal("no reset link was emailed")
	}

	// Fetch the emailed URL verbatim, as a browser would.
	req, err := http.NewRequest(http.MethodGet, emailed, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tc.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound && res.StatusCode != http.StatusSeeOther {
		t.Fatalf("emailed link returned %d, want a redirect to the application", res.StatusCode)
	}
	location := res.Header.Get("Location")
	if strings.Contains(location, "/error") {
		t.Fatalf("emailed link sent the user to the error page: %s", location)
	}
	if !strings.Contains(location, "/choose-password") {
		t.Fatalf("emailed link did not reach the configured reset page: %s", location)
	}
	// The application needs the token to complete the reset.
	target, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	token := target.Query().Get("token")
	if token == "" {
		t.Fatalf("redirect carried no token: %s", location)
	}
	if res, _ := tc.post("/reset-password", map[string]any{
		"newPassword": "brand-new-password", "token": token,
	}); res.StatusCode != http.StatusOK {
		t.Fatalf("the token from the emailed link did not work: %d", res.StatusCode)
	}
	if res, _ := tc.post("/sign-in/email", map[string]any{
		"email": "linkuser@example.com", "password": "brand-new-password",
	}); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in with the reset password: %d", res.StatusCode)
	}
}

// TestResetPasswordWithoutADestinationIsRejectedAtStartup pins the
// decision to fail at construction rather than in front of a user who
// has already lost access to their account.
func TestResetPasswordWithoutADestinationIsRejectedAtStartup(t *testing.T) {
	_, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://app.example.com",
		Secret:   "0123456789abcdef0123456789abcdef",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
			SendResetPassword: func(ctx context.Context, u *storage.User, link, token string) error {
				return nil
			},
		},
	})
	if err == nil {
		t.Fatal("New accepted SendResetPassword with no ResetPasswordURL; the emailed link cannot work")
	}
	if !strings.Contains(err.Error(), "ResetPasswordURL") {
		t.Fatalf("error should name the missing field, got: %v", err)
	}
}
