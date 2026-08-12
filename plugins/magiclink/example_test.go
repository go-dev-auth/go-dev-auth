package magiclink_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/magiclink"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Passwordless sign-in. Note that EmailAndPassword is not enabled here:
// magic links can be the only credential a user ever has.
//
// Options.SendMagicLink is required. It is validated in Init, so a
// missing mailer fails godevauth.New rather than the first sign-in.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		AppName:  "Example App",
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		Plugins: []godevauth.Plugin{
			magiclink.New(magiclink.Options{
				SendMagicLink: func(ctx context.Context, email, link, token string) error {
					// Put link in the email verbatim; token is the same
					// value for clients that build their own URL.
					log.Printf("email to %s: %s", email, link)
					return nil
				},
				// A magic link is a bearer credential in an inbox, so
				// keep the window short.
				ExpiresIn: 5 * time.Minute,
				// DisableSignUp: true rejects addresses with no account
				// instead of creating one on first use.
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, rt := range auth.Routes() {
		if strings.Contains(rt.Path, "magic-link") {
			fmt.Println(rt.Method, auth.Config().BasePath+rt.Path)
		}
	}

	// Output:
	// POST /api/auth/sign-in/magic-link
	// GET /api/auth/magic-link/verify
}

// The whole flow: request a link, then follow it. Following the link
// consumes the token and creates a session, so the same link cannot be
// used twice.
func Example_signIn() {
	var emailed string

	auth, err := godevauth.New(godevauth.Config{
		AppName:  "Example App",
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		Plugins: []godevauth.Plugin{
			magiclink.New(magiclink.Options{
				SendMagicLink: func(ctx context.Context, email, link, token string) error {
					emailed = link
					return nil
				},
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// The client asks for a link. The response is the same whether or
	// not the address has an account.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/magic-link",
		strings.NewReader(`{"email":"ada@example.com","name":"Ada"}`))
	req.Header.Set("Content-Type", "application/json")
	auth.Handler().ServeHTTP(httptest.NewRecorder(), req)

	// The user clicks the link in their inbox.
	link, err := url.Parse(emailed)
	if err != nil {
		log.Fatal(err)
	}
	rec := httptest.NewRecorder()
	auth.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, link.RequestURI(), nil))

	// They now hold a session cookie, and their address counts as
	// verified: they proved they can read mail sent to it.
	follow := httptest.NewRequest(http.MethodGet, "/anything", nil)
	for _, cookie := range rec.Result().Cookies() {
		follow.AddCookie(cookie)
	}
	sd, err := auth.GetSession(follow)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sd.User.Email, "verified:", sd.User.EmailVerified)

	// Output: ada@example.com verified: true
}
