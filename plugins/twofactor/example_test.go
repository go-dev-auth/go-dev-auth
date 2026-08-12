package twofactor_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Enabling the second factor. TOTP and backup codes work with no
// options at all; setting SendOTP is what adds the email-OTP endpoints.
//
// TOTP secrets and backup codes are stored encrypted with
// Config.Secret, so rotating that secret needs the PreviousSecrets
// procedure — see Auth.ReencryptSecrets.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		// AppName is the default TOTP issuer, the label an
		// authenticator app shows next to the code.
		AppName:  "Example App",
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{
			twofactor.New(twofactor.Options{
				BackupCodeCount: 10,
				SendOTP: func(ctx context.Context, user *storage.User, otp string) error {
					log.Printf("email to %s: your code is %s", user.Email, otp)
					return nil
				},
				OTPExpiresIn: 5 * time.Minute,
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, rt := range auth.Routes() {
		if strings.HasPrefix(rt.Path, "/two-factor/") {
			fmt.Println(rt.Method, auth.Config().BasePath+rt.Path)
		}
	}

	// Output:
	// POST /api/auth/two-factor/enable
	// POST /api/auth/two-factor/disable
	// POST /api/auth/two-factor/get-totp-uri
	// POST /api/auth/two-factor/verify-totp
	// POST /api/auth/two-factor/generate-backup-codes
	// POST /api/auth/two-factor/verify-backup-code
	// POST /api/auth/two-factor/send-otp
	// POST /api/auth/two-factor/verify-otp
}

// The client-side contract. Once a user has 2FA enabled, /sign-in/email
// no longer returns a session: it answers {"twoFactorRedirect": true}
// and sets a short-lived pending cookie. The client then posts a code to
// one of the /two-factor/verify-* endpoints to finish signing in.
//
// The guard runs on every sign-in path — password, magic link, social,
// email-verification auto-login — so the second factor cannot be
// skipped by choosing a different method.
func Example_signInChallenge() {
	auth, err := godevauth.New(godevauth.Config{
		AppName:  "Example App",
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{
			twofactor.New(twofactor.Options{
				// Turns 2FA on as soon as /two-factor/enable succeeds.
				// The default is to wait for the user to prove they
				// scanned the QR code by posting a valid TOTP code.
				SkipVerificationOnEnable: true,
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// A browser's cookie handling, spelled out.
	jar := map[string]*http.Cookie{}
	post := func(path, body string) map[string]any {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, cookie := range jar {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		auth.Handler().ServeHTTP(rec, req)
		res := rec.Result()
		for _, cookie := range res.Cookies() {
			jar[cookie.Name] = cookie
		}
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return out
	}

	post("/api/auth/sign-up/email",
		`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`)

	// Enrolment returns the otpauth:// URI to render as a QR code, and
	// the one-time backup codes. Both are shown to the user once.
	enrol := post("/api/auth/two-factor/enable", `{"password":"correct-horse"}`)
	totpURI, _ := enrol["totpURI"].(string)
	uri, err := url.Parse(totpURI)
	if err != nil {
		log.Fatal(err)
	}
	secret := uri.Query().Get("secret")

	post("/api/auth/sign-out", `{}`)

	// Signing in now yields a challenge instead of a session.
	challenge := post("/api/auth/sign-in/email",
		`{"email":"ada@example.com","password":"correct-horse"}`)
	fmt.Println("twoFactorRedirect:", challenge["twoFactorRedirect"])

	// The authenticator app computes this from the shared secret.
	code, err := crypto.TOTP(secret, time.Now(), 30, 6)
	if err != nil {
		log.Fatal(err)
	}
	done := post("/api/auth/two-factor/verify-totp", `{"code":"`+code+`"}`)
	user, _ := done["user"].(map[string]any)
	fmt.Println("signed in as:", user["email"])

	// Output:
	// twoFactorRedirect: true
	// signed in as: ada@example.com
}
