# go-dev-auth

A comprehensive, framework-agnostic authentication library for Go, modeled after [better-auth](https://github.com/better-auth/better-auth). Email & password, social sign-on, sessions, account linking, two-factor auth, magic links, organizations, admin tooling, API keys and JWT — with **zero external dependencies** (pure standard library).

```
go get github.com/go-dev-auth/go-dev-auth
```

## Features

**Core**

- Email & password authentication (scrypt hashing, compatible with better-auth's hash format)
- Social sign-on via OAuth 2.0 / OIDC with PKCE — Google, GitHub, Discord, Facebook, Microsoft, Apple, GitLab, LinkedIn, Spotify, Twitch, X built in, plus a declarative `oauth2.Spec` for any custom provider
- Database-backed sessions with sliding expiration, signed cookies, optional cookie caching, list/revoke endpoints
- Email verification, password reset, change email/password, delete user flows
- Account linking & unlinking (trusted providers, token refresh, account info)
- CSRF origin checking, trusted origins with wildcard subdomains, IP-based rate limiting
- Storage adapter interface with built-in `database/sql` (Postgres, MySQL, SQLite) and in-memory adapters, plus schema/migration SQL generation
- Request hooks, database hooks, custom user/session fields

**Plugins** (mirroring better-auth's plugin system)

- `twofactor` — TOTP, email OTP and backup codes
- `magiclink` — passwordless email links
- `organization` — orgs, members, roles, invitations, teams
- `admin` — user management, bans, roles, impersonation
- `apikey` — hashed API keys that authenticate like sessions
- `jwt` — EdDSA-signed JWTs + JWKS endpoint
- `bearer` — Authorization header auth for non-browser clients

## Quick start

```go
package main

import (
	"context"
	"net/http"
	"os"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

func main() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "http://localhost:8080",       // required
		Secret:   os.Getenv("AUTH_SECRET"),      // required, 32+ random chars
		Database: memory.New(),                  // required
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},

		// Required in production if anything sits in front of this
		// process (load balancer, ingress, CDN). See below.
		Advanced: godevauth.AdvancedConfig{
			TrustProxyHeaders: true,
			TrustedProxies:    []string{"10.0.0.0/8"},
		},
	})
	if err != nil {
		panic(err)
	}

	// sweep expired one-time tokens and sessions
	defer auth.StartCleanup(context.Background(), time.Hour)()

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	http.ListenAndServe(":8080", mux)
}
```

The handler is a plain `http.Handler`, so it mounts on chi, echo, gorilla, or gin (via `gin.WrapH`) the same way. If your frontend runs on a different origin, wrap it: `auth.CORS(auth.Handler())` and list that origin in `TrustedOrigins`.

`New` validates the configuration and returns an error rather than starting up in an unsafe state: a missing/short `Secret`, a missing or relative `BaseURL` (it decides cookie security, trusted origins and redirect targets), `SameSite=none` without secure cookies, or `TrustProxyHeaders` without `TrustedProxies` are all rejected.

### Deployment requirement: tell it about your proxy

Rate limiting and every recorded session IP depend on resolving the *client's* address. If anything terminates the connection in front of this process — an AWS ALB, nginx, Cloudflare, a Kubernetes ingress — you must say so, because **both defaults are wrong in a different direction**:

| Configuration | What happens |
|---|---|
| Nothing set, but running behind a proxy | Every request resolves to the proxy's address, so all clients share one bucket. The documented strict rule of 3 sign-ins per 10 seconds becomes 3 per 10 seconds **for your whole fleet**, and the limiter fails closed. This is a self-inflicted outage. |
| `TrustProxyHeaders` with no `TrustedProxies` | `X-Forwarded-For` is client-supplied. Any caller picks its own bucket and the limit stops limiting anything. |
| `TrustProxyHeaders` + `TrustedProxies` | Correct. Forwarded headers are read only from a listed peer, and the header chain is walked right-to-left past trusted hops, so addresses a client prepended are ignored. |

So:

```go
Advanced: godevauth.AdvancedConfig{
	TrustProxyHeaders: true,
	// IPs or CIDRs of your load balancers / ingress pods.
	TrustedProxies: []string{"10.0.0.0/8", "192.168.0.0/16"},
	// Or, for a provider-specific header:
	// IPAddressHeaders: []string{"CF-Connecting-IP"},
},
```

`New` **refuses to start** if `TrustProxyHeaders` (or `IPAddressHeaders`) is set without `TrustedProxies`. Use `TrustedProxies: []string{"*"}` to trust any peer — that is the old, spoofable behaviour, and it is only safe when the network guarantees the service is unreachable except through a proxy that overwrites the header.

The opposite mistake cannot be caught at startup, because it depends on the traffic. The first request that arrives with a forwarded header while proxy headers are untrusted logs an error naming the header and the peer. If you see it in production, you are in row one of that table.

Direct-to-internet deployments need none of this: leave all three unset.

## Storage adapters

| Adapter | Import | Notes |
|---|---|---|
| In-memory | `storage/memory` | Tests, examples, single-process. Enforces unique constraints and indexes unique fields. |
| SQL | `storage/sqlstore` | PostgreSQL, MySQL, SQLite via `database/sql`. Bring your own driver. |
| MongoDB | `storage/mongostore` | Official `mongo-go-driver`. Separate Go module. |

All adapters are written against the same conformance suite (`storage/storagetest`), which pins the semantics the auth core depends on: unique-violation reporting, NULL vs zero, chronological sorting, clause folding, literal case-insensitive substring matching and compare-and-set update counts.

**What has actually been executed, as of this revision:** the suite runs in CI against the in-memory adapter and against **real SQLite**, and against a wire-protocol test double for MongoDB. It has **not** yet been run against a real PostgreSQL, MySQL or MongoDB server — so the Postgres and MySQL dialects (placeholder style, quoting, the offset form, driver-error classification) are covered by unit tests on the generated SQL and not by execution. Treat those two backends as beta and report anything you hit. This paragraph gets deleted the day CI runs the suite against all three.

If you write your own adapter, run that suite against it:

```go
func TestConformance(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) (storage.Adapter, func()) {
		return myAdapter(storagetest.Schema()), func() {}
	})
}
```

## MongoDB

```go
import (
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/go-dev-auth/go-dev-auth/storage/mongostore"
)

client, err := mongo.Connect(options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
store := mongostore.New(client.Database("myapp"))

auth, err := godevauth.New(godevauth.Config{Database: store, /* ... */})
```

`New` creates the indexes the schema implies, including the unique ones. That step is not cosmetic on MongoDB: collections are created lazily, so an instance without them looks healthy while every "does this email already exist?" check degrades into a race. Use `Advanced.DisableAutoMigrate` only if you create them in a separate deploy step.

The adapter maps the `id` field onto Mongo's `_id`, rejects composite values where MongoDB would read them as operators (the NoSQL-injection shape), escapes regex metacharacters in substring searches, and reports duplicate keys as `storage.ErrUniqueViolation`. `Transaction` needs a replica set or mongos, as MongoDB itself does.

## Using a real database

```go
import (
	"database/sql"

	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"
	_ "github.com/jackc/pgx/v5/stdlib" // bring your own driver
)

db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))
store := sqlstore.New(db, sqlstore.Postgres, nil)

auth, _ := godevauth.New(godevauth.Config{
	Secret:   os.Getenv("AUTH_SECRET"),
	Database: store,
	// ...
})

// pick up the plugin tables *and columns*, then apply them
store.SetSchema(auth.Schema())
if err := store.Migrate(context.Background()); err != nil { ... }

// or hand the DDL to your own migration tool:
fmt.Println(store.MigrationSQL())          // the whole schema, from nothing
pending, _ := store.PendingMigrationSQL(ctx) // only what this database lacks
```

`Migrate` is idempotent and does two things: it creates missing tables and indexes, and it adds missing **columns** to tables that already exist. The second matters as soon as the database has data in it — see [Migrations](#migrations).

## Social sign-on

```go
import (
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/providers"
)

godevauth.Config{
	SocialProviders: []oauth2.Provider{
		providers.Google(providers.Credentials{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		}),
		providers.GitHub(providers.Credentials{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		}),
	},
}
```

Set the provider redirect URI to `{BaseURL}/api/auth/callback/{provider}`. Custom providers are a single `oauth2.New(oauth2.Spec{...})` call.

## Plugins

```go
import (
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/magiclink"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
)

godevauth.Config{
	Plugins: []godevauth.Plugin{
		twofactor.New(),
		organization.New(organization.Options{Teams: true}),
		admin.New(),
		jwt.New(),
		magiclink.New(magiclink.Options{
			SendMagicLink: func(ctx context.Context, email, url, token string) error {
				return mailer.Send(email, "Sign in", url)
			},
		}),
	},
}
```

Writing your own plugin means implementing three methods (`ID`, `Init`, `Routes`) and optionally `Schema`, `Middleware`, `BeforeRequest`/`AfterRequest`, `SignInGuard` (veto or challenge a sign-in on every path) or `SessionGuard` (re-check every request).

## Server-side session access

```go
func handler(w http.ResponseWriter, r *http.Request) {
	sd, err := auth.GetSession(r)
	if err != nil {
		// errors.Is(err, godevauth.ErrNoSession) → unauthenticated
	}
	_ = sd.User  // *storage.User
	_ = sd.Session // *storage.Session
}
```

## API endpoints

All endpoints live under `Config.BasePath` (default `/api/auth`) and match better-auth's route names:

| Area | Endpoints |
|---|---|
| Email & password | `POST /sign-up/email`, `POST /sign-in/email`, `POST /forget-password`, `POST /reset-password`, `GET /reset-password/:token`, `POST /change-password`, `POST /set-password` |
| Email verification | `POST /send-verification-email`, `GET /verify-email` |
| Session | `GET /get-session`, `POST /sign-out`, `GET /list-sessions`, `POST /revoke-session`, `POST /revoke-sessions`, `POST /revoke-other-sessions` |
| Social | `POST /sign-in/social`, `GET|POST /callback/:provider`, `POST /link-social`, `POST /unlink-account`, `GET /list-accounts`, `POST /refresh-token`, `GET /account-info` |
| User | `POST /update-user`, `POST /change-email`, `POST /delete-user`, `GET|POST /delete-user/callback` (GET confirms, POST deletes) |
| Two-factor | `POST /two-factor/{enable,disable,get-totp-uri,verify-totp,send-otp,verify-otp,generate-backup-codes,verify-backup-code}` |
| Magic link | `POST /sign-in/magic-link`, `GET /magic-link/verify` |
| Organization | `POST /organization/{create,update,delete,set-active,invite-member,accept-invitation,reject-invitation,cancel-invitation,remove-member,update-member-role,leave,check-slug,create-team,remove-team}`, `GET /organization/{list,get-full-organization,get-invitation,list-invitations,get-active-member,list-teams}` |
| Admin | `POST /admin/{create-user,set-role,set-user-password,update-user,ban-user,unban-user,impersonate-user,stop-impersonating,list-user-sessions,revoke-user-session,revoke-user-sessions,remove-user}`, `GET /admin/list-users` |
| API keys | `POST /api-key/{create,update,delete,verify}`, `GET /api-key/{get,list}` |
| JWT | `GET /token`, `GET /jwks`, `GET /.well-known/jwks.json` |

Errors are returned as `{"code": "USER_ALREADY_EXISTS", "message": "..."}` with matching HTTP status codes. A known path with the wrong method returns `405` with an `Allow` header.

## Configuration reference

`godevauth.Config` mirrors better-auth's options: `EmailAndPassword` (min/max length, verification requirements, reset delivery, custom `PasswordHasher`), `EmailVerification`, `Session` (`ExpiresIn`, `UpdateAge`, `FreshAge`, cookie cache), `User` (additional fields, change-email, delete-user), `Account` (linking rules, token encryption at rest), `Advanced` (cookie prefix, cross-subdomain cookies, SameSite, proxy trust, custom ID generation, CSRF exemptions), `TrustedOrigins`, `RateLimit` (windows, per-path rules, pluggable store), `Events` (the audit hook), `PreviousSecrets` (secret rotation), `Hooks` and `DatabaseHooks`.

Rate-limit rules in `RateLimit.CustomRules` may be keyed by the route pattern (`"/reset-password/:token"`) as well as by a literal path. Buckets are keyed by the pattern, so a parameterised route is limited as one endpoint rather than one bucket per parameter value.

## Example app

A runnable demo with most plugins enabled lives in [`examples/basic`](examples/basic/main.go):

```
go run ./examples/basic
```

## Custom user fields

Extra columns are declared on the config and are **not** client-writable unless you say so. This is the difference between a profile field and a privilege:

```go
User: godevauth.UserConfig{
	AdditionalFields: []storage.Field{
		{Name: "displayName", Type: storage.FieldString, Input: true},  // user may set it
		{Name: "plan",        Type: storage.FieldString},               // server-controlled
	},
},
```

Fields contributed by plugins (`role`, `banned`, `twoFactorEnabled`, …) are never writable from a request body, whatever `Input` says.

## Security model

**Passwords.** scrypt (N=16384, r=16, p=1), better-auth's `salt:key` hex format. Each hash costs ~50 ms of CPU and ~32 MiB of scratch memory by design; the hasher bounds concurrency (default `GOMAXPROCS`) and pools its buffers so a burst of sign-ins cannot exhaust memory. Tune via `crypto.NewScryptHasher`.

**Rate limiting is on by default** (fail-closed) because the sign-in endpoint is expensive by construction. Set `RateLimit.Disabled` only when a gateway already throttles these paths, and supply `RateLimit.Storage` when running more than one instance.

**Sessions.** 32-byte random tokens, HMAC-signed cookies with domain separation and `__Secure-` prefixes on HTTPS. Raw tokens are never included in session listings. The optional cookie cache carries an absolute revalidation deadline that is never extended from cached data, so revocation always takes effect within `CookieCache.MaxAge`.

**One-time tokens** (password reset, email verification, magic links, deletion, OAuth state) are stored as SHA-256 digests and consumed atomically, so database read access yields no usable links.

**OAuth.** PKCE (S256), state pinned to the browser with a cookie *and* to the issuing provider, single-use and expiring. Automatic account linking requires both a provider-asserted verified email **and** that the provider is listed in `Account.AccountLinking.TrustedProviders` — an unverified or self-set address at the IdP cannot take over an existing local account.

**CSRF.** State-changing requests are origin-checked against `BaseURL` + `TrustedOrigins` (wildcard subdomains supported), falling back to `Sec-Fetch-Site` when no Origin/Referer is present.

**Sign-in guards.** Every sign-in path — password, magic link, social, verification auto-login — funnels through `SignInUser`, so a plugin implementing `SignInGuard` (two-factor, bans) cannot be bypassed by choosing another method. `SessionGuard` additionally re-checks every request, so a ban takes effect immediately rather than at next login.

**ID tokens.** The native "sign in with X" path verifies the token's signature against the issuer's published JWKS and checks `iss`, `aud` (plus `azp` for multi-audience tokens), `exp` and the nonce. Keys are cached with a bounded stale-serve window, and a failed fetch cannot be induced by a client to block key rotation.

**Secrets at rest.** TOTP secrets, backup codes and JWT private keys are AES-256-GCM encrypted with a key derived from your `Secret`; OAuth tokens too when `Account.EncryptOAuthTokens` is set. Encryption failure is an error, never a silent plaintext write, and **decryption failure is an error too** — never a fallback that returns the ciphertext. Every ciphertext is **bound to where it is stored** — its model, record id and field name are authenticated alongside the value — so a value copied from one encrypted column into another does not decrypt, and database write access cannot be turned into a read oracle for somebody else's secrets. Ciphertexts also carry a key identifier, so `Secret` can be rotated: see [Rotating the secret](#rotating-the-secret).

**Audit trail.** Every security-relevant event — sign-in success and failure with the reason, sign-out, session creation and revocation, password and email changes, account link/unlink and deletion, 2FA enable/disable, bans, and administrator impersonation start/stop — is emitted as a typed `godevauth.Event`. Events never contain passwords, session tokens or one-time tokens; there is no free-form field, and a test asserts the property by reflection. See [Audit events](#audit-events).

## Rotating the secret

`Config.Secret` derives the key that encrypts values at rest. Changing it used to be unrecoverable — every enrolled 2FA user locked out permanently, JWT signing keys unreadable — because the ciphertext said nothing about which key wrote it. Stored values are versioned and tagged with a key identifier:

```
v2.<kid>.<base64url(nonce || AES-256-GCM(plaintext))>
```

The GCM additional data covers the version, the key id, **and the value's location** — model, record id, field name — so a ciphertext only opens in the column of the row it was written to.

Two earlier formats exist in deployed databases and are still read, so upgrading needs no migration:

| Format | Shape | Key derivation | Location-bound |
| --- | --- | --- | --- |
| `v0` | bare `base64url(nonce‖ct)`, no `.` | `sha256("go-dev-auth-enc:"+secret)` | no |
| `v1` | `v1.<kid>.<body>` | scrypt | no |
| `v2` | `v2.<kid>.<body>` | scrypt | **yes** |

Rotation — and the `v0`/`v1` → `v2` migration, which uses the same pass — is a three-step deploy:

```go
// 1. Deploy: new secret current, old one still readable.
Secret:          os.Getenv("AUTH_SECRET"),      // the new value
PreviousSecrets: []string{os.Getenv("AUTH_SECRET_OLD")},
```

```go
// 2. Migrate. Safe to run against a live instance; re-run until Done.
result, err := auth.ReencryptSecrets(ctx)
// result.Rewritten  — values moved to the current key and format
// result.Unreadable — values no key can read; investigate before step 3
// result.Skipped    — rows a concurrent write changed mid-pass; re-run
// result.Failed     — write errors; re-run once the cause is fixed
// result.Done()     — nothing left to do
```

```go
// 3. Deploy again with PreviousSecrets empty.
//    Once step 2 reports Done, also set:
RequireBoundCiphertexts: true,
```

`ReencryptSecrets` covers OAuth tokens on the account table and calls every plugin implementing `godevauth.SecretRotator` (two-factor, jwt) for their own tables. It walks each table in batches of 200 in id order rather than loading it whole, and every write is a compare-and-set on the ciphertext it read — so a token refreshed or a backup-code set regenerated mid-pass is never reverted, only skipped. One plugin's rotator failing does not stop the others. It is idempotent: a pass that reports `Done()` means nothing is left under an old key or in an unbound format.

**`RequireBoundCiphertexts` is the second half of the fix.** Until it is set, the unbound `v0` and `v1` formats are still accepted on read, which means a ciphertext captured from an old backup can still be relocated between columns. Turning it on before the migration finishes does not lose data — clearing it makes those values readable again — but users whose values have not been migrated cannot authenticate while it is set. So: upgrade, migrate to `Done()`, then turn it on.

Skip step 1 and the library will not guess. A stored TOTP secret it cannot read is a `500 TWO_FACTOR_SECRET_UNREADABLE`, not a "wrong code"; an unreadable OAuth token is a `500 TOKEN_DECRYPTION_FAILED`, not an `enc:…` blob forwarded to the provider; and `/jwks` keeps publishing every public key regardless, so tokens already in circulation stay verifiable while you fix the configuration.

Note that cookie and token *signatures* are not versioned. Rotating `Secret` invalidates existing signed cookies — users are signed out — whatever `PreviousSecrets` says.

## Audit events

There is one hook and one type:

```go
Events: godevauth.EventsConfig{
	Handler: func(ctx context.Context, e *godevauth.Event) {
		// e.Type, e.Outcome, e.Reason, e.ActorID, e.TargetID,
		// e.Email, e.SessionID, e.Method, e.Action,
		// e.ClientIP, e.UserAgent, e.RequestMethod, e.RequestPath
		siem.Send(e)
	},
},
```

Notable properties:

- **On by default.** With no `Handler`, events go to `Config.Logger` — successes at `Info`, failures at `Warn`. An audit trail that has to be switched on is missing from exactly the deployments that need it. Set `Events.DisableDefaultLogging` to opt out (events include the subject's email address, which may not belong in ordinary application logs).
- **Failure reasons are more specific than the HTTP response.** Sign-in answers `INVALID_EMAIL_OR_PASSWORD` to the client so it cannot be used to enumerate accounts; the event distinguishes `unknown_user` from `invalid_password` from `banned` from `two_factor_required`, which is what tells credential stuffing apart from password guessing.
- **429s are recorded.** `Ctx.Error` only logs 5xx, so a throttled brute-force attempt otherwise leaves no server-side trace at all.
- **`RequestPath` is the route pattern**, e.g. `/reset-password/:token` — never the resolved path, which contains the token.
- **Impersonation is bracketed.** While it is active every action is recorded against the impersonated user, so `admin.impersonation_started` / `admin.impersonation_stopped` are the only thread tying those actions back to the administrator.

Plugins emit their own with `auth.EmitEvent(c, godevauth.Event{...})`.

## Operations

- **Cleanup:** `auth.CleanupExpired(ctx)` or `auth.StartCleanup(ctx, time.Hour)`. Expired verification rows and sessions are otherwise never collected.
- **Behind a proxy:** set `Advanced.TrustProxyHeaders` **and** `Advanced.TrustedProxies`. See [the quick start](#deployment-requirement-tell-it-about-your-proxy) — the default is an outage waiting to happen behind a load balancer.
- **Rotating `Secret`:** three-step deploy with `Config.PreviousSecrets` and `auth.ReencryptSecrets`. See [Rotating the secret](#rotating-the-secret).
- **Upgrading to bound ciphertexts:** run `auth.ReencryptSecrets` until it reports `Done()`, then deploy with `Config.RequireBoundCiphertexts: true`. Same section.
- **Audit trail:** on by default to `Config.Logger`; route it with `Events.Handler`. See [Audit events](#audit-events).
- **Multi-instance:** supply a shared `RateLimit.Storage`; everything else is stateless.
- **Session cookie cache:** it is bypassed automatically when a plugin registers a `SessionGuard` (the admin plugin's ban check does). Serving authorization decisions from a cached copy of the user would let a ban sit unnoticed for the cache window.
- **Migrations:** see [Migrations](#migrations) below.
- **Introspection:** `auth.Routes()` lists every registered endpoint; `auth.Schema()` the full schema.

## Migrations

Plugins do not only add tables. They add **columns to the tables you already have**: `admin` adds `role`, `banned`, `banReason` and `banExpires` to `user` and `impersonatedBy` to `session`, `twofactor` adds `twoFactorEnabled` to `user`, `organization` adds `activeOrganizationId` to `session`, and `Config.User.AdditionalFields` does the same. A library upgrade can add a core column the same way.

`CREATE TABLE IF NOT EXISTS` does nothing for a table that is already there, so a column-level step is not optional on a database that has data in it. `store.Migrate(ctx)` does both:

| | |
|---|---|
| `store.Migrate(ctx)` | Creates missing tables and indexes, **and** adds missing columns to existing tables. Idempotent — call it on every boot. Auto-migration in `godevauth.New` runs exactly this. |
| `store.MigrationSQL()` | The full create-from-nothing DDL, for provisioning a new database by hand. Never contains an `ALTER`; it has no idea what your database already has. |
| `store.PendingMigrationSQL(ctx)` | Introspects the live database and returns **only** the statements it is missing — `CREATE TABLE` for absent tables, `ALTER TABLE ... ADD COLUMN` for absent columns. Empty means up to date. |
| `store.CheckSchema(ctx)` | Reports drift as an error naming the tables and columns, without changing anything. |

Two things to know about added columns:

- **They are always nullable**, whatever `Field.Required` says. The rows already in the table have no value for a column that did not exist, and no engine will accept `NOT NULL` without a default on a populated table. A required column added by a migration is therefore enforced by the application, not the database, until you backfill the rows and tighten it yourself.
- **Migrate needs DDL rights.** If your application's database role does not have them, run migrations from a deploy step, set `Advanced.DisableAutoMigrate`, and set `Advanced.VerifySchema` so a missed migration fails at startup with a message naming the missing columns — instead of at the first sign-in, with a driver error.

```go
auth, err := godevauth.New(godevauth.Config{
	Database: store,
	Advanced: godevauth.AdvancedConfig{
		DisableAutoMigrate: true, // migrations are a deploy step
		VerifySchema:       true, // ...so refuse to start if one was missed
	},
	// ...
})
// go-dev-auth: verifying the database schema: sqlstore: the database schema is
// out of date: table "twoFactor" is missing; table "user" is missing column(s)
// "role", "banned", "banReason", "banExpires"
```

## Performance and cost

Measured on a 4-core arm64 container (`go test -bench .`) **against the in-memory adapter**. That is an honest measure of the library's own request path and a poor proxy for your production latency, where a database round-trip will dominate every row below except password hashing. Read these as "what the library adds", not "what a sign-in costs".

| Operation | Cost |
|---|---|
| Session validation (cookie -> user) | ~0.6 µs parallel, 21 allocs |
| Full HTTP request through the router | ~4 µs, 47 allocs |
| Session lookup, 10k rows (memory adapter) | ~0.5 µs (indexed) |
| Password hash / verify | ~51 ms, 21 KB |

Everything except password hashing is microseconds. Where the money actually goes, in order:

**1. Password hashing dominates CPU.** ~51 ms per sign-in means roughly `sign-ins/sec ÷ 20` CPU cores. At 100 sign-ins/sec that is ~5 cores doing nothing but scrypt. This is deliberate — it is what makes stolen hashes expensive to crack — so the lever is not to make it cheaper but to *do it less often*: sessions last 7 days by default, so a signed-in user never touches it again.

**2. Database round trips dominate everything else.** An authenticated request costs two queries (session, then user), which on a managed database is ~1 ms each — a thousand times the CPU cost of the request itself. Turn on the session cookie cache to make that zero:

```go
Session: godevauth.SessionConfig{
	CookieCache: godevauth.CookieCacheConfig{Enabled: true, MaxAge: 5 * time.Minute},
},
```

The trade is staleness: a revoked session keeps working until the cached copy expires. With a `SessionGuard` plugin registered (the admin plugin's ban check is one) the cache is bypassed by default rather than serving authorization decisions from a stale user; set `CookieCache.AcceptStaleAuthorization` to take the saving anyway and accept that bans apply within `MaxAge`.

**3. Memory under a sign-in burst is bounded, not proportional to traffic.** Each in-flight hash needs 128·N·r = 32 MiB of scratch, so concurrency is capped at `GOMAXPROCS` and buffers are pooled: peak transient memory is `GOMAXPROCS × 32 MiB` no matter how many requests arrive. Requests that cannot get a slot within `MaxWait` (3s) are shed with `503 SERVICE_BUSY` instead of queueing into a multi-second backlog that clients experience as a hang.

Tuning the hash cost is possible but changes the security/cost trade and makes existing hashes unverifiable:

```go
// Fewer cores per sign-in, less resistance to offline cracking.
// Fresh deployments only.
crypto.NewScryptHasher(crypto.ScryptParams{N: 16384, R: 8, P: 1, MaxConcurrent: 8})
```

## Project layout

```
.                          the godevauth package: config, routing, handlers
.github/                   CI, templates, CONTRIBUTING, SECURITY
storage/                   persistence contract, models, schema
storage/memory             in-memory adapter
storage/sqlstore           PostgreSQL / MySQL / SQLite
storage/mongostore         MongoDB (separate module)
storage/storagetest        adapter conformance suite
crypto/                    password hashing, tokens, TOTP, JWT
oauth2/                    OAuth 2.0 / OIDC client
providers/                 ready-made provider configurations
plugins/<name>/            optional features, one package each
plugins/plugintest         harness for testing a plugin
ratelimit/                 rate limiter and store interface
examples/basic             a runnable server
docs/                      architecture map, plugin guide, reviews
```

The root directory is flat because Go requires every file of a package
to share one directory: these files *are* the `godevauth` package, and
nesting them would mean either changing the import path or splitting the
package. Everything that can be its own package already is. Files are
named for what they hold — `session.go`, `router.go`, `handler_email.go`
— so the listing reads as a table of contents.

[docs/architecture.md](docs/architecture.md) is the full map: what each
file owns, and where a new change belongs.

## Developing

```
go work init . ./storage/mongostore ./storage/sqlstore/integration
make check      # fmt, vet, lint, tests, race
```

`make help` lists every target. `go.work` is developer-local and not
committed. The SQLite integration tests need `CGO_ENABLED=1`; the
Postgres, MySQL and MongoDB suites skip unless the matching DSN
environment variables are set.

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for expectations on changes,
[SECURITY.md](.github/SECURITY.md) for the security model and reporting process,
and [docs/](docs/) for the architecture map and audit records.

Working with an AI coding assistant? [`llms.txt`](llms.txt) is a
single-file briefing on the API and the rules that keep generated code
correct; [`AGENTS.md`](AGENTS.md) covers agents contributing to this
repository.

## License

MIT
