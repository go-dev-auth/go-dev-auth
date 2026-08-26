// Command fullapp is a complete, small web application built on
// go-dev-auth: registration, sign-in, a protected dashboard with
// session management, password reset — all persisted to a real SQLite
// file, so restarting the server keeps your users.
//
// The shape to copy is the boot order:
//
//	store := sqlstore.New(db, sqlstore.SQLite, nil)   // 1. adapter
//	auth, _ := godevauth.New(...Database: store...)   // 2. auth (hands the adapter the full schema)
//	store.Migrate(ctx)                                // 3. migrate — after New, or plugin tables are missed
//
// Run it:
//
//	go run .
//
// then open http://localhost:8080 — reset links are printed to stdout.
package main

import (
	"context"
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// One writer at a time is how every production SQLite deployment
	// runs; the busy timeout makes contending writers wait, not fail.
	db, err := sql.Open("sqlite3", "file:fullapp.db?_busy_timeout=5000&_journal=WAL&_fk=1")
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	store := sqlstore.New(db, sqlstore.SQLite, nil)

	auth, err := godevauth.New(godevauth.Config{
		AppName:  "Full App",
		BaseURL:  "http://localhost:8080",
		Secret:   "dev-only-secret-change-me-0123456789",
		Database: store,
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled:          true,
			ResetPasswordURL: "/reset-password",
			SendResetPassword: func(_ context.Context, user *storage.User, url, _ string) error {
				log.Printf("[email to %s] reset your password: %s", user.Email, url)
				return nil
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	// Migrate after New: New hands the adapter the complete schema
	// (core + plugins + custom fields), so migrating earlier would
	// create only part of it.
	if err := store.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	stop := auth.StartCleanup(context.Background(), time.Hour)
	defer stop()

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())

	// Public pages. A signed-in visitor is bounced to the dashboard.
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		if _, err := auth.GetSession(r); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		render(w, "home", nil)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) { render(w, "register", nil) })
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { render(w, "login", nil) })
	mux.HandleFunc("/forgot", func(w http.ResponseWriter, r *http.Request) { render(w, "forgot", nil) })
	mux.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		render(w, "reset", map[string]any{"Token": r.URL.Query().Get("token")})
	})

	// The protected page: one server-side session check, no JWT
	// parsing, no middleware framework required.
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		sd, err := auth.GetSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		render(w, "dashboard", map[string]any{"User": sd.User})
	})

	log.Println("open http://localhost:8080 — data persists in fullapp.db")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// The pages POST JSON to the auth API with fetch() and follow with a
// client-side redirect — the same calls a SPA or mobile client makes,
// so what you see in the network tab is exactly the integration.
var pages = template.Must(template.New("").Parse(`
{{define "layout-top"}}<!doctype html><meta charset="utf-8">
<title>Full App</title>
<style>
 body{font-family:system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem}
 input,button{display:block;width:100%;margin:.5rem 0;padding:.5rem;box-sizing:border-box}
 .err{color:#b00}nav a{margin-right:1rem}
</style>
<script>
 async function api(path, body){
   const res = await fetch('/api/auth'+path,{method:'POST',
     headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   if(!res.ok){const e=await res.json().catch(()=>({}));
     throw new Error(e.message||('HTTP '+res.status));}
   return res.json().catch(()=>({}));
 }
 function fail(err){document.getElementById('err').textContent=err.message}
</script>{{end}}

{{define "home"}}{{template "layout-top"}}
<h1>Full App</h1>
<p>A go-dev-auth example with persistent SQLite storage.</p>
<nav><a href="/register">Register</a><a href="/login">Sign in</a></nav>{{end}}

{{define "register"}}{{template "layout-top"}}
<h1>Register</h1><p id="err" class="err"></p>
<form onsubmit="event.preventDefault();
  api('/sign-up/email',{name:n.value,email:e.value,password:p.value})
    .then(()=>location='/dashboard').catch(fail)">
 <input id="n" placeholder="Name" required>
 <input id="e" type="email" placeholder="Email" required>
 <input id="p" type="password" placeholder="Password (8+ chars)" required>
 <button>Create account</button>
</form>
<p><a href="/login">Already have an account?</a></p>{{end}}

{{define "login"}}{{template "layout-top"}}
<h1>Sign in</h1><p id="err" class="err"></p>
<form onsubmit="event.preventDefault();
  api('/sign-in/email',{email:e.value,password:p.value})
    .then(()=>location='/dashboard').catch(fail)">
 <input id="e" type="email" placeholder="Email" required>
 <input id="p" type="password" placeholder="Password" required>
 <button>Sign in</button>
</form>
<p><a href="/forgot">Forgot password?</a> · <a href="/register">Register</a></p>{{end}}

{{define "forgot"}}{{template "layout-top"}}
<h1>Reset password</h1><p id="err" class="err"></p>
<form onsubmit="event.preventDefault();
  api('/forget-password',{email:e.value})
    .then(()=>document.body.insertAdjacentHTML('beforeend',
      '<p>If that address exists, a reset link was sent (see the server log).</p>'))
    .catch(fail)">
 <input id="e" type="email" placeholder="Email" required>
 <button>Send reset link</button>
</form>{{end}}

{{define "reset"}}{{template "layout-top"}}
<h1>Choose a new password</h1><p id="err" class="err"></p>
<form onsubmit="event.preventDefault();
  api('/reset-password',{token:'{{.Token}}',newPassword:p.value})
    .then(()=>location='/login').catch(fail)">
 <input id="p" type="password" placeholder="New password" required>
 <button>Set password</button>
</form>{{end}}

{{define "dashboard"}}{{template "layout-top"}}
<h1>Hello, {{.User.Name}}</h1>
<p>Signed in as {{.User.Email}}.</p>
<p id="err" class="err"></p>
<button onclick="api('/sign-out',{}).then(()=>location='/').catch(fail)">Sign out</button>
<button onclick="api('/revoke-other-sessions',{})
  .then(()=>alert('Other sessions revoked.')).catch(fail)">Sign out everywhere else</button>{{end}}
`))
