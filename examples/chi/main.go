// Command chi mounts go-dev-auth inside a chi router and shows the two
// integration points a router user actually needs:
//
//  1. Mounting the auth handler under a path prefix.
//  2. A middleware that turns the library's server-side session lookup
//     into request context, so downstream handlers stay framework-idiomatic.
//
// Run it:
//
//	go run .
//
// Then:
//
//	curl -c jar -X POST localhost:8080/api/auth/sign-up/email \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"you@example.com","password":"password123","name":"You"}'
//	curl -b jar localhost:8080/api/me
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// ctxKey is unexported so no other package can collide with it.
type ctxKey struct{}

// requireSession is ordinary chi middleware over auth.GetSession. The
// library never sees the router; the router never sees a cookie.
func requireSession(auth *godevauth.Auth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sd, err := auth.GetSession(r)
			if err != nil {
				http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), ctxKey{}, sd)))
		})
	}
}

// sessionFrom retrieves what requireSession stored.
func sessionFrom(r *http.Request) *godevauth.SessionData {
	sd, _ := r.Context().Value(ctxKey{}).(*godevauth.SessionData)
	return sd
}

func main() {
	auth, err := godevauth.New(godevauth.Config{
		AppName:  "Chi Example",
		BaseURL:  "http://localhost:8080",
		Secret:   "dev-only-secret-change-me-0123456789",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Everything under /api/auth/* belongs to the library. Mount, not
	// Handle: chi strips its own routing context and the library does
	// its own path dispatch beneath the prefix.
	r.Mount("/api/auth", auth.Handler())

	// Application routes, session-gated by ordinary middleware.
	r.Group(func(r chi.Router) {
		r.Use(requireSession(auth))
		r.Get("/api/me", func(w http.ResponseWriter, r *http.Request) {
			sd := sessionFrom(r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"hello":"` + sd.User.Name + `"}`))
		})
	})

	log.Println("listening on http://localhost:8080 (auth at /api/auth)")
	log.Fatal(http.ListenAndServe(":8080", r))
}
