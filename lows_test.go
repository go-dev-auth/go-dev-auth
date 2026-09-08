package godevauth_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Regression test for L7: a BaseURL with a trailing slash must not
// produce "//api/auth/..." in callback URLs.
func TestBaseURLTrailingSlashTrimmed(t *testing.T) {
	base := ""
	auth, _ := newTestAuth(t, func(cfg *godevauth.Config) {
		base = cfg.BaseURL
		cfg.BaseURL = cfg.BaseURL + "/"
	})
	_ = base
	cb := auth.CallbackURL("google")
	if strings.Contains(cb, "//api/auth") {
		t.Fatalf("callback URL has a doubled slash: %q", cb)
	}
}

// busyHasher always reports the hasher is saturated.
type busyHasher struct{}

func (busyHasher) Hash(string) (string, error)         { return "hash", nil }
func (busyHasher) Verify(string, string) (bool, error) { return false, crypto.ErrHasherBusy }

// Regression test for L8: a hasher error on change-password must not be
// reported as a wrong password (which would invite a retry storm that
// deepens the saturation).
func TestChangePasswordHasherErrorNotWrongPassword(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.PasswordHasher = busyHasher{}
	})
	tc.signUp("busy@example.com", "password123", "Busy")
	res, body := tc.post("/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpassword123",
	})
	if code, _ := body["code"].(string); code == "INVALID_PASSWORD" {
		t.Fatalf("hasher-busy reported as wrong password (status %d, body %v)", res.StatusCode, body)
	}
}

// Regression test for L6: with ConfirmationPage on, GET /verify-email
// renders a page and does NOT consume the token; the POST does.
func TestVerifyEmailConfirmationPage(t *testing.T) {
	var token string
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailVerification.ConfirmationPage = true
		cfg.EmailVerification.SendVerificationEmail = func(ctx context.Context, u *storage.User, link, tok string) error {
			token = tok
			return nil
		}
	})
	body := tc.signUp("confirm@example.com", "password123", "Confirm")
	userID := body["user"].(map[string]any)["id"].(string)

	res, _ := tc.post("/send-verification-email", map[string]any{"email": "confirm@example.com"})
	if res.StatusCode != http.StatusOK || token == "" {
		t.Fatalf("send-verification-email: %d, token=%q", res.StatusCode, token)
	}

	// GET renders the confirmation page and must not verify.
	res, _ = tc.get("/verify-email?token=" + url.QueryEscape(token))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET verify-email confirmation page: %d", res.StatusCode)
	}
	user, _ := auth.FindUserByID(context.Background(), userID)
	if user.EmailVerified {
		t.Fatal("GET /verify-email consumed the token and verified — a scanner could do this")
	}

	// POST performs the verification.
	res, _ = tc.post("/verify-email?token="+url.QueryEscape(token), nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST verify-email: %d", res.StatusCode)
	}
	user, _ = auth.FindUserByID(context.Background(), userID)
	if !user.EmailVerified {
		t.Fatal("POST /verify-email did not verify the address")
	}
}
