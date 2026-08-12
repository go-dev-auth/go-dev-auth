package bearer_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/bearer"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Mobile apps and other non-browser clients have no cookie jar. The
// bearer plugin lets them send the session token in an Authorization
// header instead, and exposes a freshly minted token in the
// `set-auth-token` response header of sign-in style endpoints.
//
// The plugin adds no routes of its own: it is a MiddlewarePlugin that
// wraps the whole handler, so every endpoint accepts either form.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{
			bearer.New(bearer.Options{
				// Accept only the signed value (what the cookie holds)
				// rather than a raw session token. Signed tokens are
				// what set-auth-token returns, so this costs the client
				// nothing and rejects anything a database leak alone
				// would yield.
				RequireSignature: true,
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Sign in and read the token out of the header.
	signIn := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email",
		strings.NewReader(`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`))
	signIn.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	auth.Handler().ServeHTTP(rec, signIn)
	token := rec.Header().Get("set-auth-token")

	// Use it in place of the cookie.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/get-session", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	auth.Handler().ServeHTTP(out, req)

	var session map[string]any
	if err := json.NewDecoder(out.Body).Decode(&session); err != nil {
		log.Fatal(err)
	}
	user, _ := session["user"].(map[string]any)
	fmt.Println("status:", out.Code)
	fmt.Println("acting as:", user["email"])

	// Output:
	// status: 200
	// acting as: ada@example.com
}
