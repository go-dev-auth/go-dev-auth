// Command fullapp is a complete, small web application built on
// go-dev-auth — a tour of the library's feature set in one file:
//
//   - registration, sign-in, sign-out
//   - passwordless sign-in via magic links
//   - two-factor auth: TOTP enrolment, sign-in challenge, backup codes
//   - password reset and change-password
//   - session management: list devices, sign out everywhere else
//
// all persisted to a real SQLite file, so restarting the server keeps
// your users. "Emails" (reset and magic links) are printed to stdout.
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
// then open http://localhost:8080.
package main

import (
	"context"
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/magiclink"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
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
		Plugins: []godevauth.Plugin{
			twofactor.New(),
			magiclink.New(magiclink.Options{
				SendMagicLink: func(_ context.Context, email, url, _ string) error {
					log.Printf("[email to %s] your magic link: %s", email, url)
					return nil
				},
			}),
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
		render(w, "dashboard", map[string]any{
			"User":      sd.User,
			"SessionID": sd.Session.ID,
		})
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Full App</title>
<style>
 body{font-family:system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#1c1a17;background:#faf6ef}
 input,button{display:block;width:100%;margin:.5rem 0;padding:.55rem;box-sizing:border-box}
 button{background:#111;color:#faf6ef;border:1px solid #111;cursor:pointer}
 button.quiet{background:transparent;color:#111}
 .err{color:#b00}nav a{margin-right:1rem}
 section{border-top:1px solid #ded5c6;margin-top:2rem;padding-top:1rem}
 table{width:100%;border-collapse:collapse;font-size:.85rem}
 td,th{text-align:left;padding:.3rem;border-bottom:1px solid #ded5c6}
 code{background:#efe9df;padding:.1rem .3rem;word-break:break-all}
 .ok{color:#2a6}
</style>
<script>
 async function api(path, body, method){
   const res = await fetch('/api/auth'+path,{method:method||'POST',
     headers:{'Content-Type':'application/json'},
     body:method==='GET'?undefined:JSON.stringify(body||{})});
   if(!res.ok){const e=await res.json().catch(()=>({}));
     throw new Error(e.message||('HTTP '+res.status));}
   return res.json().catch(()=>({}));
 }
 function fail(err){document.getElementById('err').textContent=err.message}
 function say(msg){const o=document.getElementById('err');o.textContent=msg;o.classList.add('ok')}
</script>{{end}}

{{define "home"}}{{template "layout-top"}}
<h1>Full App</h1>
<p>A go-dev-auth feature tour: password and passwordless sign-in,
two-factor auth, password reset, and session management — persisted to
SQLite.</p>
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
    .then(r=>{ if(r.twoFactorRedirect){twofa.style.display='block'}
               else{location='/dashboard'} }).catch(fail)">
 <input id="e" type="email" placeholder="Email" required>
 <input id="p" type="password" placeholder="Password" required>
 <button>Sign in</button>
</form>

<div id="twofa" style="display:none">
 <p>This account has two-factor auth. Enter the 6-digit code from your
 authenticator app (or a backup code below).</p>
 <form onsubmit="event.preventDefault();
   api('/two-factor/verify-totp',{code:c.value})
     .then(()=>location='/dashboard').catch(fail)">
  <input id="c" placeholder="123456" required>
  <button>Verify code</button>
 </form>
 <form onsubmit="event.preventDefault();
   api('/two-factor/verify-backup-code',{code:bc.value})
     .then(()=>location='/dashboard').catch(fail)">
  <input id="bc" placeholder="backup code">
  <button class="quiet">Use a backup code instead</button>
 </form>
</div>

<section>
 <h2>Or skip the password</h2>
 <form onsubmit="event.preventDefault();
   api('/sign-in/magic-link',{email:me.value,callbackURL:'/dashboard'})
     .then(()=>say('Magic link sent — see the server log.')).catch(fail)">
  <input id="me" type="email" placeholder="Email" required>
  <button class="quiet">Email me a magic link</button>
 </form>
</section>
<p><a href="/forgot">Forgot password?</a> · <a href="/register">Register</a></p>{{end}}

{{define "forgot"}}{{template "layout-top"}}
<h1>Reset password</h1><p id="err" class="err"></p>
<form onsubmit="event.preventDefault();
  api('/forget-password',{email:e.value})
    .then(()=>say('If that address exists, a reset link was sent (see the server log).'))
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
<p>{{.User.Email}}{{if .User.EmailVerified}} · verified{{end}}</p>
<p id="err" class="err"></p>
<button onclick="api('/sign-out').then(()=>location='/').catch(fail)">Sign out</button>

<section>
 <h2>Sessions</h2>
 <p>Every signed-in device, from <code>GET /list-sessions</code>. Raw
 session tokens are never in this list — by design.</p>
 <table id="stab"><tr><th>Created</th><th>IP</th><th>Device</th><th></th></tr></table>
 <button class="quiet" onclick="loadSessions()">Refresh</button>
 <button onclick="api('/revoke-other-sessions')
   .then(()=>{say('Other sessions revoked.');loadSessions()}).catch(fail)">
   Sign out everywhere else</button>
 <script>
  async function loadSessions(){
    const list = await api('/list-sessions',null,'GET').catch(fail);
    const rows = list.map(s =>
      '<tr><td>'+new Date(s.createdAt).toLocaleString()+'</td>'+
      '<td>'+(s.ipAddress||'—')+'</td>'+
      '<td>'+((s.userAgent||'—').slice(0,40))+'</td>'+
      '<td>'+(s.id==='{{.SessionID}}'?'this device':'')+'</td></tr>');
    stab.innerHTML = '<tr><th>Created</th><th>IP</th><th>Device</th><th></th></tr>'+rows.join('');
  }
  loadSessions();
 </script>
</section>

<section>
 <h2>Two-factor auth</h2>
 <div id="tf-off">
  <form onsubmit="event.preventDefault();
    api('/two-factor/enable',{password:tp.value}).then(r=>{
      document.getElementById('tf-enroll').style.display='block';
      turi.textContent=r.totpURI;
      tcodes.textContent=r.backupCodes.join('  ');
    }).catch(fail)">
   <input id="tp" type="password" placeholder="Confirm your password" required>
   <button>Enable two-factor</button>
  </form>
 </div>
 <div id="tf-enroll" style="display:none">
  <p>Add this to your authenticator app (or paste the URI into it):</p>
  <p><code id="turi"></code></p>
  <p>Backup codes — store them somewhere safe; each works once:</p>
  <p><code id="tcodes"></code></p>
  <form onsubmit="event.preventDefault();
    api('/two-factor/verify-totp',{code:tv.value})
      .then(()=>say('Two-factor is on. Next sign-in will ask for a code.')).catch(fail)">
   <input id="tv" placeholder="6-digit code from the app" required>
   <button>Verify and finish</button>
  </form>
 </div>
 <form onsubmit="event.preventDefault();
   api('/two-factor/disable',{password:dp.value})
     .then(()=>say('Two-factor is off.')).catch(fail)">
  <input id="dp" type="password" placeholder="Password">
  <button class="quiet">Disable two-factor</button>
 </form>
</section>

<section>
 <h2>Change password</h2>
 <form onsubmit="event.preventDefault();
   api('/change-password',{currentPassword:cp.value,newPassword:np.value,revokeOtherSessions:true})
     .then(()=>{say('Password changed; other sessions revoked.');loadSessions()}).catch(fail)">
  <input id="cp" type="password" placeholder="Current password" required>
  <input id="np" type="password" placeholder="New password (8+ chars)" required>
  <button>Change password</button>
 </form>
</section>{{end}}
`))
