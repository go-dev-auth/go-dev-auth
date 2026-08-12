/*
Package godevauth is a framework-agnostic authentication library for Go,
modeled after better-auth.

It provides email/password authentication, social sign-on (OAuth 2.0 and
OpenID Connect), database-backed sessions, account linking, and a plugin
system covering two-factor authentication, magic links, organizations,
administration, API keys and JWTs. The core library depends only on the
standard library.

# Getting started

Construct an Auth instance and mount its handler:

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   os.Getenv("AUTH_SECRET"),
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
	})
	if err != nil {
		return err
	}
	mux.Handle("/api/auth/", auth.Handler())

New validates the configuration and returns an error rather than
starting in an unsafe state. Handler is an ordinary http.Handler, so it
mounts unchanged on chi, echo, gorilla or gin.

# Reading a session

From any handler in your application:

	sd, err := auth.GetSession(r)
	if errors.Is(err, godevauth.ErrNoSession) {
		// unauthenticated
	}
	user := sd.User

# Package layout

	godevauth              this package: configuration, routing, handlers
	godevauth/storage      the persistence contract, models and schema
	godevauth/storage/...  adapters: memory, sqlstore, mongostore
	godevauth/crypto       password hashing, tokens, TOTP, JWT primitives
	godevauth/oauth2       OAuth 2.0 / OIDC client and ID token verification
	godevauth/providers    ready-made configurations for common providers
	godevauth/plugins/...  optional features, each an independent package
	godevauth/ratelimit    the rate limiter and its pluggable store

# Extending

A plugin implements ID, Init and Routes, and may additionally implement
SchemaPlugin to add tables, MiddlewarePlugin to wrap the handler,
HookPlugin to observe every request, SignInGuard to veto or challenge a
sign-in on every sign-in path, SessionGuard to re-check a session on
every request, or SecretRotator to re-encrypt its stored values when
Config.Secret is rotated.

Storage backends implement storage.Adapter. Run
storage/storagetest.Run against any implementation: the auth core
depends on precise semantics (unique-violation reporting, NULL versus
zero, chronological ordering, compare-and-set update counts) that the
conformance suite pins down.

# Auditing

Every security-relevant event — sign-in success and failure with its
reason, sign-out, session creation and revocation, credential and email
changes, account link/unlink, 2FA changes, bans and administrator
impersonation — is emitted as a typed Event. Route them with
Config.Events.Handler; with no handler they go to Config.Logger.
Events never carry passwords, session tokens or one-time tokens.

# Security posture

Rate limiting is enabled by default and fails closed. It buckets by
client IP and route pattern, which means client IPs must resolve
correctly: behind a proxy, set Advanced.TrustProxyHeaders together with
Advanced.TrustedProxies. New refuses to start if the first is set
without the second.

Passwords are hashed with scrypt using better-auth compatible
parameters. One-time tokens are stored as digests and consumed
atomically. OAuth flows use PKCE with browser-bound, provider-pinned
state. Session cookies are HMAC-signed with domain separation.

Values held encrypted at rest (TOTP secrets, backup codes, JWT signing
keys, optionally OAuth tokens) carry a format version and a key
identifier, so Config.Secret can be rotated: list the old value in
Config.PreviousSecrets, call Auth.ReencryptSecrets, then drop it. A
value that no configured key can decrypt is always an error, never a
silent fallback.

Each value is also bound to where it is stored: the model, record id and
field name are authenticated alongside the ciphertext, so a value copied
from one encrypted column into another does not decrypt there. Older
values written before that binding existed are still readable and are
migrated by the same Auth.ReencryptSecrets pass; set
Config.RequireBoundCiphertexts once the migration is complete to stop
accepting them.

See .github/SECURITY.md for the full model and for how to report a
vulnerability.
*/
package godevauth
