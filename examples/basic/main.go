// Command basic is a runnable example server showing go-dev-auth with
// email/password auth, email verification (logged to stdout), magic
// links, two-factor auth, JWT and an admin panel API — all backed by the
// in-memory storage.
//
// Run it:
//
//	go run ./examples/basic
//
// Then try:
//
//	curl -X POST localhost:8080/api/auth/sign-up/email \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"you@example.com","password":"password123","name":"You"}'
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/bearer"
	"github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/magiclink"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

func main() {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		// Long enough to pass validation; generate a real one with
		// `openssl rand -base64 32` before deploying anything.
		secret = "dev-only-secret-change-me-0123456789"
	}

	auth, err := godevauth.New(godevauth.Config{
		AppName:  "Example App",
		BaseURL:  "http://localhost:8080",
		Secret:   secret,
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
			SendResetPassword: func(ctx context.Context, user *storage.User, url, token string) error {
				log.Printf("[email to %s] reset your password: %s", user.Email, url)
				return nil
			},
		},
		EmailVerification: godevauth.EmailVerificationConfig{
			SendOnSignUp: true,
			SendVerificationEmail: func(ctx context.Context, user *storage.User, url, token string) error {
				log.Printf("[email to %s] verify your email: %s", user.Email, url)
				return nil
			},
		},
		Plugins: []godevauth.Plugin{
			bearer.New(),
			jwt.New(),
			twofactor.New(),
			admin.New(),
			organization.New(),
			magiclink.New(magiclink.Options{
				SendMagicLink: func(ctx context.Context, email, url, token string) error {
					log.Printf("[email to %s] your magic link: %s", email, url)
					return nil
				},
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())

	// a protected application route using the server-side helper
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		sd, err := auth.GetSession(r)
		if err != nil {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"` + sd.User.Name + `"}`))
	})

	// Expired one-time tokens and sessions are swept periodically;
	// without this the verification table grows forever.
	stopCleanup := auth.StartCleanup(context.Background(), time.Hour)
	defer stopCleanup()

	log.Println("listening on http://localhost:8080 (auth at /api/auth)")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
