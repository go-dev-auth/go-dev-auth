# Architecture

A map of the repository, and where new code belongs.

## Why the root directory is flat

Go requires every file of a package to sit in the same directory. The
package developers import is `github.com/go-dev-auth/go-dev-auth`, so
its files must live in the repository root — they cannot be tucked into
a `src/`, `internal/core/` or `pkg/auth/` subfolder without changing the
import path or fragmenting the package.

That is why the root holds 18 source files rather than 4 folders. It is
the same shape as `net/http` (which is one directory of ~40 files) and
is idiomatic Go, not an accident. Everything that *can* live in its own
package does: crypto, storage, OAuth, providers, rate limiting and every
plugin are separate packages with their own directories and tests.

Two consequences worth knowing before you open a PR:

- **File names are the navigation.** They are grouped by layer, and the
  table below is the index. Keep a new file inside one of those layers
  rather than adding a new top-level concept.
- **Root files stay small.** If a root file grows past roughly 500
  lines, that is the signal to ask whether the thing it describes is
  really a separate package.

## Root package — `godevauth`

### Public surface and wiring

| File | Owns |
|---|---|
| `doc.go` | Package documentation; the overview a user reads first on pkg.go.dev. |
| `auth.go` | The `Auth` type, `New`, and the lifecycle that assembles config, storage, plugins and routes. |
| `config.go` | The whole `Config` tree, its defaults, and validation. |
| `errors.go` | `APIError`, the sentinel errors, and the status/code mapping clients see. |
| `plugin.go` | The `Plugin` interfaces a third-party package implements. |

### HTTP layer

| File | Owns |
|---|---|
| `router.go` | The `Route` type, the built-in route table, path matching, and the per-request pipeline (origin check → rate limit → hooks → handler). |
| `context.go` | `Ctx`: request parsing, JSON responses, redirects, session lookup. |
| `cookie.go` | Cookie naming, secure/SameSite policy, and HMAC signing with domain separation. |
| `origin.go` | Cross-origin policy — CORS and CSRF together, because both must read the same trusted-origin list. |

### Domain logic

| File | Owns |
|---|---|
| `session.go` | Session creation, guards, revocation, and the signed cookie cache. |
| `store.go` | Typed data access over `storage.Adapter`; every read and write of a user, session, account or verification row. |
| `token.go` | One-time verification tokens: issue, look up, consume atomically, expire. |
| `events.go` | The audit trail: the `Event` type, its vocabulary, and dispatch to `Events.Handler` or the logger. Handlers call `EmitEvent`; nothing else decides what an event looks like. |
| `secrets.go` | Secret rotation and at-rest format migration: `ReencryptSecrets`, the `SecretRotator` plugin interface, and the batched, compare-and-set record walker plugins reuse. |

### Endpoints

`handler_*.go` — one file per feature area (`account`, `email`,
`session`, `social`, `user`, `verification`). A handler validates input,
calls into the domain layer, and writes a response; it should not talk
to `storage.Adapter` directly.

### Tests

Grouped by what they assert rather than by the file under test, because
the interesting behaviour is cross-cutting:

| File | Asserts |
|---|---|
| `harness_test.go` | Shared fixture: an in-process server, a cookie jar, and a cheap password hasher. Start here. |
| `auth_test.go` | The happy paths — sign up, sign in, sign out, sessions. |
| `oauth_test.go` | Social sign-in, PKCE, state binding, account linking. |
| `plugins_test.go` | Plugins composed with the core, and plugin interaction. |
| `security_test.go` | The attacks each defence exists to stop. Every fix has a case here. |
| `concurrency_test.go` | Races and compare-and-set behaviour under parallel requests. |
| `resilience_test.go` | Degraded conditions: load shedding, storage failures. |
| `rotation_test.go` | `Config.Secret` rotation: old ciphertext stays readable, the legacy format still opens, an unconfigured key fails loudly, and re-encryption lets the old secret be dropped. |
| `events_test.go` | The audit trail, including the reflection sweep asserting no event carries a credential. |
| `proxy_test.go` | Client-IP resolution and the rate-limit bucket key — the two configurations that must not be reachable by accident. |
| `benchmark_test.go` | Request-path time and allocations. |

## Packages

| Package | Purpose |
|---|---|
| `crypto/` | scrypt and PBKDF2 hashing, AES-GCM, HMAC, TOTP/HOTP, JWT and JWKS. No auth logic. `Keyring` owns the versioned at-rest ciphertext format (`v2.<kid>.<body>`, with the value's `Binding` — model, record id, field — authenticated so a ciphertext cannot be relocated), the readers for the older unbound `v0`/`v1` formats, and the current/previous key set that makes `Config.Secret` rotatable. |
| `storage/` | The `Adapter` interface, models, and query building blocks. |
| `storage/memory/` | In-memory adapter for tests and development. |
| `storage/sqlstore/` | Postgres, MySQL and SQLite over `database/sql`, including schema migration: `Migrate` creates missing tables and indexes *and* adds missing columns, because plugins extend the core tables rather than only adding their own. |
| `storage/mongostore/` | MongoDB (its own module, so the driver is not forced on everyone). |
| `storage/storagetest/` | Conformance suite every adapter must pass; this is what keeps backends behaving identically. |
| `oauth2/` | Generic OAuth 2.0 / OIDC: PKCE, token exchange, ID-token verification, JWKS caching. |
| `providers/` | Configuration for the named social providers. |
| `ratelimit/` | Rule types and the default limiter store. |
| `plugins/*` | Optional features, each importing the root package's public API only. |
| `plugins/plugintest/` | Harness for testing a plugin end to end in a few lines. |

## Where does my change go?

- **A new endpoint on an existing feature** → the matching
  `handler_*.go`, plus an entry in `coreRoutes` in `router.go`.
- **A new optional feature** → a new package under `plugins/`. Read
  [writing-a-plugin.md](writing-a-plugin.md); do not add it to the core.
- **A new database backend** → a new package under `storage/`, and it
  must pass `storagetest`.
- **A new cryptographic primitive** → `crypto/`, with test vectors from
  the relevant RFC.
- **A new social provider** → `providers/`.
- **A new security-relevant action** → emit a `godevauth.Event` for it
  from the handler. Add an `EventType` to `events.go` rather than
  overloading an existing one, and never put a credential in a field.
- **A plugin that stores encrypted values** → encrypt through
  `auth.Keyring()`, never `crypto.EncryptString(cfg.Secret, ...)`; pass
  a `crypto.Binding{Model, Record, Field}` naming the row and column the
  value is written to, generating the record id *before* encrypting if
  the insert would otherwise mint it; and implement `SecretRotator`
  (delegating to `Auth.ReencryptRecords`) so a rotation can migrate the
  table. Without the binding every ciphertext in the deployment is
  interchangeable, and any endpoint that returns a decrypted value
  becomes a read oracle for every other encrypted column.

## Repository layout

```
.                       the godevauth package (see tables above)
.github/                CI, issue and PR templates, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
crypto/                 cryptographic primitives
docs/                   this map, the plugin guide, and reviews/
examples/basic/         a runnable server
oauth2/                 OAuth 2.0 and OIDC
plugins/                optional features
providers/              social provider definitions
ratelimit/              rate limiting
storage/                persistence: interface, models, adapters, conformance suite
```
