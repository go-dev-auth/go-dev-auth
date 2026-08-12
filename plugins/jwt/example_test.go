package jwt_test

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	jwtplugin "github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Issuing JWTs for a session, so a downstream service can authenticate
// a caller without sharing this database.
//
// The Ed25519 signing key is created on first use and stored with its
// private half encrypted under Config.Secret; /jwks publishes every
// public key so tokens outlive a key rotation.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{
			jwtplugin.New(jwtplugin.Options{
				// Both default to BaseURL. Set them to whatever the
				// relying party is configured to expect.
				Issuer:   "https://example.com",
				Audience: "https://api.example.com",
				// Keep it short: a JWT cannot be revoked, only expired.
				ExpiresIn: 5 * time.Minute,
				// Claims beyond the registered ones. "sub", "iss",
				// "aud", "iat" and "exp" are reserved and cannot be
				// overwritten here.
				DefinePayload: func(sd *godevauth.SessionData) map[string]any {
					return map[string]any{
						"email":     sd.User.Email,
						"sessionId": sd.Session.ID,
					}
				},
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, rt := range auth.Routes() {
		if rt.Path == "/token" || strings.Contains(rt.Path, "jwks") {
			fmt.Println(rt.Method, auth.Config().BasePath+rt.Path)
		}
	}

	// Output:
	// GET /api/auth/token
	// GET /api/auth/jwks
	// GET /api/auth/.well-known/jwks.json
}

// Signing and verifying server-side, without going through HTTP. Hold
// on to the *Plugin value you pass to Config.Plugins — that is the
// handle to these methods.
func ExamplePlugin_SignSession() {
	plugin := jwtplugin.New(jwtplugin.Options{
		Issuer:    "https://example.com",
		Audience:  "https://api.example.com",
		ExpiresIn: 5 * time.Minute,
	})

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		Plugins:  []godevauth.Plugin{plugin},
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = auth // the plugin reaches the instance through Init

	ctx := context.Background()
	sd := &godevauth.SessionData{
		Session: &storage.Session{ID: "sess-1", UserID: "user-1"},
		User:    &storage.User{ID: "user-1", Email: "ada@example.com"},
	}

	token, err := plugin.SignSession(ctx, sd)
	if err != nil {
		log.Fatal(err)
	}

	// A relying party would fetch /jwks instead; Verify is for this
	// process, where the key is already at hand.
	claims, err := plugin.Verify(ctx, token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sub:", claims["sub"])
	fmt.Println("aud:", claims["aud"])
	fmt.Println("email:", claims["email"])

	// Output:
	// sub: user-1
	// aud: https://api.example.com
	// email: ada@example.com
}
