// Command basic is the smallest runnable go-dev-auth server: email &
// password auth with verification and password reset, "emails" printed
// to stdout, everything stored in memory. No plugins — see
// examples/fullapp for a complete web app and the README for the
// plugin catalogue.
//
// Run it:
//
//	go run ./examples/basic
//
// Then try:
//
//	# create an account (signs you in; note the Set-Cookie header)
//	curl -i -X POST localhost:8080/api/auth/sign-up/email \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"you@example.com","password":"password123","name":"You"}'
//
//	# sign in
//	curl -i -X POST localhost:8080/api/auth/sign-in/email \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"you@example.com","password":"password123"}'
//
//	# who am I? (paste the cookie from the response above)
//	curl localhost:8080/api/me -H 'Cookie: <paste Set-Cookie value>'
//
//	# forgot password — the "email" appears in this terminal; open the
//	# printed link in a browser to choose a new password
//	curl -X POST localhost:8080/api/auth/forget-password \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"you@example.com"}'
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
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
		Database: memory.New(), // in-process RAM; gone when the server stops
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
			// Where the emailed reset link sends the user to type a new
			// password. This example serves that page itself, below.
			ResetPasswordURL: "/choose-password",
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
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())

	// A protected application route using the server-side helper.
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		sd, err := auth.GetSession(r)
		if err != nil {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"` + sd.User.Name + `"}`))
	})

	// The "choose a new password" page the emailed reset link lands on.
	// The library has already validated the token and appended it as
	// ?token=...; this form posts it back with the new password.
	mux.HandleFunc("/choose-password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<title>Choose a new password</title>
<h1>Choose a new password</h1>
<form id=f>
  <input type=password name=p placeholder="new password" minlength=8 required>
  <button>Save</button>
</form>
<p id=out></p>
<script>
f.onsubmit = async (e) => {
  e.preventDefault();
  const token = new URLSearchParams(location.search).get('token');
  const r = await fetch('/api/auth/reset-password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({newPassword: f.p.value, token}),
  });
  out.textContent = r.ok ? 'Password changed - sign in with it now.'
                         : 'Failed: ' + await r.text();
};
</script>`))
	})

	// Expired one-time tokens and sessions are swept periodically;
	// without this the verification table grows forever.
	stopCleanup := auth.StartCleanup(context.Background(), time.Hour)
	defer stopCleanup()

	log.Println("listening on http://localhost:8080 (auth at /api/auth)")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
