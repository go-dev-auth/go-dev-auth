# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Pre-1.0: the public API may still change. Once tagged v1, breaking
changes will require a major version.

### Security
- `admin`: **create-user now enforces the library's own credential
  rules.** It previously validated only that the e-mail was non-empty,
  so it accepted `not-an-email` with the password `123`. With public
  sign-up disabled, create-user is the only account-creation path, so
  every account could bypass every credential rule — and a typo'd
  address is a user who can never receive a password reset. It now calls
  the same email and password validation as the public sign-up path.
  `set-role` and create-user also validate the role against an optional
  `Options.Roles` allow-list, closing the typo hole where `enginer`
  silently created an account locked out of every route. The admin check
  still runs first, so a non-admin is refused before any validation and
  cannot use the endpoint as a validity oracle.
- A repo-wide sweep for the same class fixed three more account-creation
  and credential paths that skipped the library's own rules:
  `admin.set-user-password` now validates the new password; `magiclink`
  sign-in validates the e-mail before a link is sent (with sign-up on, a
  malformed address would otherwise become an unreachable account);
  `organization.invite-member` validates the e-mail and constrains the
  role to the known set, exactly as `update-member-role` already did — a
  typo'd role was previously written to the invitation and copied onto
  the member on accept, silently locking them out of every role-gated
  route. Social sign-in now refuses to create a user when the provider
  returns no e-mail address instead of persisting an empty one.

### Added
- `Auth.ValidateEmail` and `Auth.ValidatePassword` expose the sign-up
  path's credential checks so plugins that create accounts enforce the
  same rules. Previously these were unexported, which is why the admin
  plugin could not reuse them.
- `admin.Options.Roles`: an optional allow-list of accepted role values.

## [0.1.1] - 2026-08-12

CI only — no library code changed, so nothing a `go get` consumer
depends on is affected.

### Changed
- CI: `golangci-lint-action` upgraded to v8 so it installs golangci-lint
  v2, which the repository's `.golangci.yml` (`version: "2"`) requires;
  the v1 action rejected the v2 config schema.
- CI: `actions/checkout` (v4 → v5) and `actions/setup-go` (v5 → v6) moved
  to their Node 24 major versions, off the deprecated Node 20 runtime.

## [0.1.0] - 2026-08-12

First tagged release. Everything below was introduced in it.

### Added
- Email/password authentication, social sign-on (OAuth 2.0 / OIDC with
  PKCE), database-backed sessions, account linking, email verification,
  password reset and account deletion flows.
- Plugins: two-factor (TOTP, email OTP, backup codes), magic link,
  organization (members, roles, invitations, teams), admin, API keys,
  JWT with a JWKS endpoint, and bearer-token support.
- Storage adapters for in-memory, `database/sql` (PostgreSQL, MySQL,
  SQLite) and MongoDB, plus `storage/storagetest`, a conformance suite
  every adapter must pass.
- ID token verification against a provider's JWKS, with issuer,
  audience, `azp`, expiry and nonce checks.
- `CORS` helper, expired-record cleanup (`CleanupExpired`,
  `StartCleanup`), configuration validation at construction, and load
  shedding when password hashing saturates.
- `sqlstore.Adapter.PendingMigrationSQL` returns only the DDL the live
  database is missing, for operators who apply migrations by hand;
  `MigrationSQL` still renders the full create-from-nothing schema.
- `sqlstore.Adapter.CheckSchema` / `Inspect` report schema drift as a
  `*sqlstore.SchemaDrift` error naming the missing tables and columns,
  and `Advanced.VerifySchema` makes `New` refuse to start on drift —
  worth pairing with `DisableAutoMigrate`, so a missed migration fails
  at startup rather than at the first sign-in.
- **Secret rotation.** `Config.PreviousSecrets` lists secrets this
  instance used before `Secret` was rotated. Decryption tries the
  current key first, then each previous one; encryption always uses the
  current key. `Auth.ReencryptSecrets(ctx)` rewrites stored values under
  the new key — OAuth tokens in the account table, plus every plugin
  implementing the new `SecretRotator` interface (`twofactor`, `jwt`) —
  reporting how many values were scanned, rewritten, skipped, failed and
  left unreadable, so an operator knows when the old secret can be
  dropped. The rotation is a three-step deploy; see README, *Rotating
  the secret*.
- **Versioned at-rest ciphertext.** Encrypted values are written as
  `v2.<kid>.<base64url(nonce || AES-256-GCM(plaintext))>`, where `kid`
  identifies the key that produced them. The version, the key id and the
  value's `crypto.Binding` (model, record id, field) are authenticated
  as GCM additional data, so neither relabelling a ciphertext with a
  different key id nor moving it to another column opens it. Two earlier
  formats are still read so that upgrading needs no migration: `v1`
  (`v1.<kid>.<body>`, same key derivation, unbound) and `v0` (bare
  base64url, no key id, SHA-256 derivation). Both are rewritten as `v2`
  by `Auth.ReencryptSecrets`, and `Config.RequireBoundCiphertexts`
  refuses them once that is done. `crypto.Keyring` is the entry point;
  `crypto.EncryptString` / `DecryptString` remain as single-key
  wrappers.
- **Stronger key derivation for new writes.** The v1 and v2 formats
  derive the key with scrypt (N=2^14, r=8, p=1) rather than a single
  SHA-256 pass,
  with independent labels for the encryption key and the key id. This
  was only safe to change because it rides the version tag: v0 values
  keep the old derivation. Derivation is memoised per secret, so the
  cost is paid once per process rather than per value.
- **Structured auth events.** `Config.Events.Handler` receives a typed
  `godevauth.Event` for every security-relevant action: sign-in success
  and failure (with a reason more specific than the HTTP response —
  `unknown_user` vs `invalid_password` vs `banned` vs
  `two_factor_required`), sign-out, session creation and revocation,
  password set/change/reset, email change and verification, account
  link/unlink and deletion, 2FA enable/disable/verify, bans, every
  privileged `admin` action including refused ones, impersonation start
  and stop, and rate-limited requests. Events carry actor, target,
  email, session **id** (never the token), client IP, user agent and the
  route *pattern*. With no handler configured they are logged to
  `Config.Logger` (Info for successes, Warn for failures); set
  `Events.DisableDefaultLogging` to suppress that. Plugins emit their own
  with `Auth.EmitEvent`.
- `Advanced.TrustedProxies` lists the reverse proxies allowed to set
  forwarded headers, as IPs or CIDRs (or `"*"` for the previous,
  spoofable behaviour). `Ctx.RoutePattern` exposes the matched route
  pattern; `Ctx.SetAuthMethod` labels how a request's subject
  authenticated, for the audit trail.

### Security

<!-- merged from pre-release blocker fixes BL-2, BL-3, and hardening -->
### Security / Fixed
- `sqlstore`: **migration is now atomic and self-healing.** `Migrate`
  previously ran DDL statement-by-statement with no transaction, no lock
  and no state tracking. On SQLite a unique column is added as two
  statements (ADD COLUMN, then CREATE UNIQUE INDEX); a crash between them
  left the column present but its uniqueness silently unenforced, and both
  `Migrate` and `CheckSchema` then reported success — a declared-unique
  identifier permitting duplicates with no signal. Now: each table's DDL
  runs in a transaction where the engine supports it (PostgreSQL, SQLite;
  MySQL cannot roll DDL back), a third pass re-issues unique indexes
  idempotently so an already-broken database heals on the next boot, and
  `CheckSchema`/`Inspect` detect a missing unique constraint instead of
  reporting all-clear.
- `sqlstore`: **concurrent migrations are serialised.** `Migrate` takes a
  session advisory lock (`pg_advisory_lock` on PostgreSQL, `GET_LOCK` on
  MySQL; SQLite is single-writer already), so a rolling deploy no longer
  crash-loops the replica that loses the race to `ADD COLUMN`.
- `sqlstore`: **SQLite/ANSI introspection is scoped to the main database.**
  `pragma_table_info` is now called with the `'main'` schema argument (and
  the pre-3.16 fallback uses `PRAGMA main.table_info`), so a TEMP or
  attached table of the same name can no longer shadow the real one and
  turn a migration into a silent no-op.
- `sqlstore`: **MySQL DDL-injection via a field default is fixed.**
  `defaultLiteral` escaped `'` but not `\`; under MySQL's default sql_mode a
  backslash-terminated default escaped its own closing quote and let the
  rest of `CREATE TABLE` be reparsed. Backslashes are now doubled for
  MySQL. `float64` and `time.Time` defaults are also rendered rather than
  silently dropped.

### Changed
- `sqlstore.Adapter.Update` now honours its documented "first match"
  contract: it resolves the first matching row by primary key and updates
  only that row, instead of issuing an unbounded `UPDATE` that hit every
  match. This matches the memory and Mongo adapters. A new
  `storagetest` conformance case (`UpdateTouchesOnlyTheFirstMatch`) pins
  it for every backend.
- `sqlstore.SchemaDrift` gains `MissingUniqueConstraints`.

## Problem

`account` had no unique constraint on `(providerId, accountId)`, and the
schema model could not express a composite unique at all. Two identical
`(providerId, accountId)` rows both inserted. `linkOAuthAccount` was
check-then-create with no database backstop, so two concurrent OAuth
callbacks for the same external identity created two account rows pointing
at two different local users — breaking the "one external identity, one
local user" invariant, making sign-in resolution row-order dependent, and
breaking unlink. The same gap existed for organization membership
`(organizationId, userId)`.

## Schema API added

`storage.Table` gained a `UniqueConstraints []UniqueConstraint` field.
`UniqueConstraint{Columns []string}` declares one composite (multi-column)
unique constraint over an ordered column list; a single-column unique
still uses `Field.Unique`. Helpers:

- `Table.AddUniqueConstraint(cols ...string)` — declares one, deduped,
  no-op for fewer than two columns.
- `Schema.AddTable` merges composite constraints when a table is extended,
  mirroring how it merges fields.

NULL semantics match single-column uniques and SQL: a row whose value for
any column of the constraint is NULL/absent does not participate (NULLs
never collide).

Applied to:
- `storage.CoreSchema()` → `account (providerId, accountId)`.
- organization plugin schema → `member (organizationId, userId)`.

## Enforcement per adapter

- **memory**: `violatesCompositeUnique` scans the table on Create and
  Update (composite constraints are rare, so they are not indexed) and
  returns `storage.ErrUniqueViolation`, consistent with the single-field
  path. A constraint with any NULL/absent column is skipped.
- **sqlstore**:
  - `CreateTableSQL` emits an inline `UNIQUE (a, b)` table constraint for
    every dialect — this covers a freshly created table.
  - **Migration path** (`Migrate` pass four, `ensureCompositeUniques`):
    a table that predates the constraint has its columns but not the
    constraint, and — unlike a single-column unique — there is no
    `ADD COLUMN` to hang it on, so it needs a separate
    `CREATE UNIQUE INDEX` on every engine. Idempotency: SQLite/MySQL are
    introspected first (pragma / `information_schema.statistics`);
    PostgreSQL uses `IF NOT EXISTS`. Reuses the existing per-boot
    self-heal shape rather than forking it.
  - **Existing duplicates**: adding the constraint to a table that already
    holds duplicates fails with a new `*sqlstore.DuplicateRowsError` that
    names the table, the columns, and a few of the offending value tuples.
    No data is dropped; the operator resolves the duplicates and re-runs
    Migrate.
  - `PendingMigrationSQL`, `Inspect`/`CheckSchema` (`SchemaDrift`) extended
    to emit / report a missing composite constraint. Drift detection is
    SQLite-only, matching the existing single-column
    `MissingUniqueConstraints`.
- **mongostore**: `EnsureIndexes` creates a compound unique index per
  constraint (`SetUnique(true).SetSparse(true)`), mirroring the
  single-field unique index.

## Handler rewrite: create-then-handle-conflict

- `linkOAuthAccount` (`handler_social.go`) no longer does an up-front
  `FindAccount` check. It attempts the insert; on `ErrUniqueViolation` it
  loads the existing row — same user is idempotent (returns nil), a
  different user is `ACCOUNT_ALREADY_LINKED`. The database is now the
  arbiter, closing the TOCTOU. Policy checks (linking disabled, email
  mismatch) still run before the insert.
- `handleAcceptInvitation` (organization `members.go`): on
  `ErrUniqueViolation` from the member insert it returns
  `USER_ALREADY_A_MEMBER` (a concurrent accept / another invitation won),
  leaving the invitation claimed. `handler_account.go` creates no account
  rows directly, so it needed no change.

## Tests added (all executed here unless noted)

- `storagetest` conformance: `CompositeUniqueViolation` and
  `ConcurrentCompositeUniqueInsert` over a new `conformanceLink` model —
  runs against **memory** and **real SQLite** (green). Also runs against
  Mongo when that suite is run (asserted, not executed here — the Mongo
  driver is not in this environment's module cache).
- `sqlstore` unit `TestCompositeUniqueDDL`: inline `UNIQUE(...)` and the
  `CREATE UNIQUE INDEX` migration statement for Postgres/MySQL/SQLite
  (Postgres/MySQL asserted-only; SQLite also executed via integration).
- Integration (**real SQLite**):
  - `TestCompositeUniqueReproducesAndFixesBL3` — before/after proof: with
    no constraint the duplicate inserts (defect reproduced); Inspect/
    CheckSchema report the gap; after Migrate the same duplicate is
    rejected with `ErrUniqueViolation`; re-migrate is a clean no-op.
  - `TestMigrateCompositeUniqueRejectsExistingDuplicates` — migrating a
    table that already holds duplicates fails with `*DuplicateRowsError`
    naming the duplicate value and drops no data; succeeds after the
    operator removes the duplicate.
- `TestAccountCompositeUniqueBackstop` (root) and
  `TestMemberCompositeUniqueBackstop` (organization) — the constraint is
  wired end-to-end through the default memory-backed Auth / plugin schema.

## Only asserted (not executed here)

- Postgres and MySQL DDL and index introspection (`information_schema`,
  `pg`/MySQL paths) — no server available; covered by unit assertions on
  the generated SQL, following the module's existing convention.
- Mongo composite index creation — driver not available offline.

Security and correctness fixes applied while hardening the root package
for release. Each fix has a regression test that fails against the
pre-fix code (proven by reverting the fix in a scratch copy and running
the test).

## S-4 — `POST /set-password` no longer grants a permanent credential from a stolen session

`handleSetPassword` (`handler_email.go`) creates a credential account for
a social-only user, turning a revocable, expiring session into an
offline-usable password. It required only `RequireSession()`.

- It now requires a **fresh** session (`IsFresh`, the same bar
  `delete-user` applies); a stale session is refused with
  `SESSION_NOT_FRESH` (HTTP 403) and a failure event, and nothing is
  written.
- On success it emits the `password.set` event and **revokes the user's
  other sessions** (honouring `RevokeOtherSessions` /
  `KeepSessionsOnPasswordChange`), consistent with `change-password`.
- The `/set-password` route now carries the **strict** per-IP rate limit
  (`router.go`, `coreRoutes`), matching its password-flow neighbours, so a
  single client cannot grind the endpoint at the global default.
- `change-password` was not weakened (still verifies the current
  password).

Tests: `TestSetPasswordRequiresFreshSession` (freshness + other-session
revocation), `TestSetPasswordRouteRateLimited` (strict throttling).

## `GET /get-session` returns the JSON literal `null` when signed out

A signed-out request returned HTTP 200 with a zero-length body under an
`application/json` content type, which makes `JSON.parse` / `res.json()`
throw in browsers. `Ctx.JSON(status, nil)` now writes the JSON literal
`null` (`context.go`), and `handleGetSession` returns it when there is no
session.

Choice: `null` (not `{"user":null,"session":null}`). The signed-in shape
is the `SessionData` object `{"session":…,"user":…}`; a signed-out `null`
is the standard sentinel `res.json()` decodes to `null`, matches
better-auth, and is unambiguous. The existing signed-out guards in the
suite check the decoded payload (`user == nil`), so `null` is consistent
with them.

Test: `TestGetSessionSignedOutIsNullNotEmpty` (body is non-empty, valid
JSON, and exactly `null`).

## S-8 — `Auth.Config()` returns an isolated snapshot

`Config()` returned `&a.config`, a pointer to the live configuration that
every request reads unsynchronised (`Secret`, `TrustedOrigins`,
`DisableCSRFCheck`). A caller writing through it was a data race on the
values that decide request authenticity.

Fix chosen: **return a copy** (`snapshot := a.config; return &snapshot`).
Trade-off: this breaks the old "mutate `Config()` after `New`" pattern —
writes now land on a discarded copy. That pattern was only ever used by
test harnesses to patch `BaseURL` after the listener was known; the fix
was to obtain the address *before* `New` and pass it in. The root harness
(`harness_test.go`) already constructs `BaseURL` from the listener before
`New`, so no post-`New` mutation remains in the files I own.

Alternative rejected: keeping the live pointer and adding a separate
mutable-field accessor. That leaves the footgun in place (the pointer is
still handed out and still mutable) and is a larger change; a copy removes
the race outright and reads (the common case — plugins call `Config()` to
read the password hasher, `AppName`, etc.) are unaffected because a copy
shares the same interface/function values.

Test: `TestConfigReturnsIsolatedSnapshot` (mutation through the returned
pointer does not reach the instance; distinct pointers; clean under
`-race` with concurrent snapshotting).

## S-5 — cookie cache no longer ships the whole user record and is size-bounded

The signed (not encrypted) session cache cookie serialised the entire
user record, including all `Extra` / `AdditionalFields`, with no size
check.

- **Restriction (`session.go`, `cookieCacheUser`):** the cache now
  carries only the core columns (`id`, `name`, `email`, `emailVerified`,
  `image`, `createdAt`, `updatedAt`) plus additional fields explicitly
  named in `Session.CookieCache.UserFields`. Everything else in
  `User.Extra` is dropped.
- **Size guard (`session.go`, `setCookieCache`):** if the assembled
  `Set-Cookie` exceeds `maxCookieCacheBytes` (4096, the RFC 6265 / browser
  floor) the cache is skipped and any stale cache cookie is cleared, so
  the request falls back to a database lookup instead of emitting a cookie
  the browser silently drops. A one-time log line explains it.
- Kept opt-in: the cache is off unless `Session.CookieCache.Enabled`.
  Encryption was **not** added (crypto is out of scope for this change,
  and a cookie has no record to bind a key to).

What was excluded and why it is safe for the guards: the session and its
guards read `id`, `email`, `emailVerified` (all core, always present) and
any authorization column a plugin needs — which the operator opts into
via `UserFields` (e.g. the admin plugin's `role`). Session guards are
already **bypassed** on a cache hit unless
`CookieCache.AcceptStaleAuthorization` is set, and even then they read
only allow-listed fields; a field omitted from the cache is therefore
never a field a guard silently evaluates as empty. Sensitive custom
fields (SSN, DOB, …) are exactly what the default now keeps out of a
client-readable cookie.

Tests: `TestCookieCacheOmitsUnlistedUserFields` (an unlisted additional
field never reaches the cookie; core fields still do),
`TestCookieCacheSkipsOversizedPayload` (an oversized payload is skipped,
not emitted, and the session still resolves).

## Left for the owner of `plugins/**`

`plugins/plugintest/plugintest.go:87` does
`auth.Config().BaseURL = server.URL` **after** `New`. With `Config()` now
returning a copy, that write is a silent no-op (the harness's `BaseURL`
stays `http://127.0.0.1`). The full suite is green today because no
passing plugin test depends on that patched value, but the line is now
dead and misleading. Recommend building `BaseURL` from the listener
before `New` (as the root harness does) and deleting line 87. I did not
touch `plugins/**` per ownership.

- **At-rest ciphertexts are bound to where they are stored.** The GCM
  additional data used to be `v1.<kid>` alone, and `kid` derives from
  the key, so every encrypted value in a deployment shared identical
  additional data: a TOTP secret, an OAuth refresh token and a JWT
  signing key were interchangeable ciphertexts. Anyone with database
  write access and an ordinary account could copy a victim's encrypted
  refresh token (or the jwt plugin's Ed25519 signing key) into their own
  `twoFactor.secret` row, call `/two-factor/get-totp-uri` with their own
  password, and read the plaintext out of the `otpauth://` URI —
  `crypto.TOTPURI` echoed whatever it was handed.

  Values are now written as `v2.<kid>.<body>` with the model, record id
  and field name authenticated alongside the version and key id, so a
  ciphertext only opens in the exact column of the exact row it was
  written to. `crypto.TOTPURI` additionally refuses anything that is not
  a base32 secret of at least 80 bits, and the two-factor plugin
  re-validates after decrypting. See *Changed* for the API break and
  *Rotating the secret* in the README for the migration.
- **`Config.RequireBoundCiphertexts`** refuses to read the pre-binding
  `v0` and `v1` formats at all. Accepting them is a downgrade path — an
  attacker holding an old unbound ciphertext from a backup can still
  relocate it — so once `Auth.ReencryptSecrets` reports a pass with
  nothing left to do, turn it on.
- **`Auth.ReencryptSecrets` is safe to run on a live instance.** It did
  read-decrypt-encrypt-write with no concurrency control, so any write
  that landed between the read and the write was silently reverted: a
  token refreshed by `/refresh-token` went back to the stale value, and
  a set of backup codes regenerated after a compromise was *restored*,
  re-enabling codes an attacker held. Every write is now a
  compare-and-set on the ciphertext the pass read; a row that changed
  underneath is counted in the new `ReencryptResult.Skipped` and left
  alone.
- Client-writable user fields are opt-in (`storage.Field.Input`), so
  plugin-owned columns such as `role` and `banned` can never be set from
  a request body.
- Sign-in guards run on every sign-in path, so a second factor or a ban
  cannot be bypassed by choosing a different method.
- One-time tokens are stored as digests and claimed atomically.
- Session tokens are omitted from API responses.
- Rate limiting is on by default and fails closed.
- **Rotating `Config.Secret` no longer destroys data.** Previously the
  AES key was a single `sha256("go-dev-auth-enc:"+secret)` with no key
  id and no second key, so changing the secret made every stored TOTP
  secret permanently undecryptable — every 2FA user locked out forever —
  dropped stored JWT signing keys from JWKS with only a log line, and
  made `maybeDecrypt` return the *ciphertext*, so `/refresh-token`
  shipped an `enc:…` blob to the OAuth provider. All three are fixed:
  ciphertexts are versioned and key-tagged, previous secrets are
  configurable, and every decryption failure is now an explicit error.
- **Rate limiting behind a proxy.** The bucket key was
  `ClientIP() + ":" + resolvedPath`, and `ClientIP` ignored forwarded
  headers unless `TrustProxyHeaders` was set. Behind any load balancer
  with the default configuration that put the entire fleet in one
  bucket — the documented 3-sign-ins-per-10-seconds rule became three
  for everyone, fail-closed. With `TrustProxyHeaders` set and no
  header-stripping proxy, any client could choose its own bucket
  instead. Both are now unreachable by accident: forwarded headers
  require `Advanced.TrustedProxies` (`New` refuses to start otherwise)
  and are only read from a listed peer, with the header chain walked
  right-to-left past trusted hops so client-prepended addresses are
  ignored; and the first request carrying a forwarded header while
  proxy trust is off logs an error naming the header and the peer.
- **Rate limiting on parameterised routes.** The bucket key used the
  resolved path, so `/reset-password/<token>` created a fresh bucket per
  request and the limit never engaged on the endpoint an attacker guesses
  tokens against. Buckets now key on the route pattern, and that
  endpoint carries an explicit 5-per-10-seconds rule.
- Refused `admin` requests are recorded with the caller's identity. An
  authenticated non-administrator probing `/admin/*` previously produced
  a 403 and nothing else, because `Ctx.Error` only logs 5xx.
- `Config.validate` warns when `Secret` is shorter than 32 characters
  and rejects a `PreviousSecrets` entry that is empty or equal to
  `Secret`.
- The hand-written JSON encoder now escapes U+2028 and U+2029. It escaped
  `<`, `>` and `&` but not the two JavaScript line terminators, so a
  user-controlled `name` could break out of a string literal when a
  response body was interpolated into a `<script>` block — the exact
  property the encoder documented itself as having. Found by
  `FuzzAppendJSONString`, a byte-level differential target; the previous
  equivalence tests compared decoded values and could not see it.
- A `*.example.com` trusted origin no longer matches the bare host
  `.example.com`. The wildcard was a plain suffix check, so the `*` was
  allowed to stand for nothing. Found by `FuzzIsTrustedOrigin`.
- 16 native Go fuzz targets across `crypto`, the root package and
  `storage`, each asserting a security property rather than only the
  absence of a panic, plus an authorization sweep over every route
  `Auth.Routes()` reports. `make fuzz` runs them and now fails when it
  finds none, which is how the CI job previously passed having executed
  nothing.

### Changed
- **Breaking:** `crypto.Keyring.Encrypt` / `Decrypt` and
  `crypto.EncryptString` / `DecryptString` take a `crypto.Binding`
  (model, record id, field) naming where the value is stored. It is
  authenticated, so a value written at one location does not open at
  another. All three components are required; an incomplete binding is
  `crypto.ErrInvalidBinding`, not a silently unbound write. In-repo
  callers (`handler_account.go`, `handler_social.go`,
  `plugins/twofactor`, `plugins/jwt`, `secrets.go`) are updated.
  Out-of-tree plugins that store encrypted values must pass the binding
  for their own table.
- **Breaking:** `crypto.TOTPURI` returns `(string, error)` and rejects a
  secret that is not valid base32 of at least 80 bits
  (`crypto.ErrInvalidTOTPSecret`). `crypto.ValidateTOTPSecret` exposes
  the same check for callers reading a secret out of storage.
- **Breaking:** `crypto.NewKeyringFrom(crypto.KeyringOptions{...})` is
  the full constructor; `crypto.NewKeyring(current, previous...)` is
  unchanged and still accepts the unbound formats on read.
- `ReencryptResult` gains `Skipped` (row changed mid-pass) and `Failed`
  (write error), and a `Done()` helper that reports when a pass found
  nothing left to do — the signal that `PreviousSecrets` can be emptied
  and `RequireBoundCiphertexts` turned on.
- `Auth.ReencryptSecrets` walks each table in batches of 200 in id
  order rather than loading it whole, and no longer abandons the
  remaining plugin rotators when one of them fails: every rotator runs
  and the errors are joined.
- **Breaking:** `Advanced.TrustProxyHeaders` and
  `Advanced.IPAddressHeaders` now require `Advanced.TrustedProxies`.
  `New` returns an error otherwise. Existing deployments that relied on
  the old behaviour should set `TrustedProxies` to their proxy's
  networks, or to `[]string{"*"}` to keep it exactly as it was.
- Password changes revoke the user's other sessions by default, matching
  password reset.
- `Auth.Adapter()` is now `Auth.Storage()`, matching the `storage`
  package it returns.
- `magiclink.New` takes variadic options like every other plugin;
  `SendMagicLink` is validated in `Init`.
- `/organization/check-slug` now requires a session. It was the only
  route in the plugin that did not, and without one it reports which
  organisations exist to anonymous callers.
- Repository layout: `cors.go` and `csrf.go` are merged into `origin.go`
  (both enforce the same trusted-origin list, and keeping them apart
  invited the two to drift); `route.go` is folded into `router.go`, so
  the route table and the matcher sit together; the `Route` type moved
  from `plugin.go` to `router.go`. No API changed.
- `CONTRIBUTING.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md` moved to
  `.github/`, where GitHub resolves them, leaving the root to code.
- Added `docs/architecture.md`: what each file and package owns, and
  where a new change belongs.

### Fixed
- `sqlstore`: **column-level migration.** `Migrate` emitted only
  `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`, which do
  nothing for a table that already exists. But plugins add *columns to
  the core tables* — `admin` adds `role`, `banned`, `banReason` and
  `banExpires` to `user` — so enabling one on a live database was a
  silent no-op and the next `SELECT ... "role","banned" FROM "user"`
  broke every sign-in and every session lookup. `Migrate` now
  introspects the live database (`information_schema.columns` on
  PostgreSQL and MySQL, `pragma_table_info` on SQLite) and issues
  `ALTER TABLE ... ADD COLUMN` for what is missing. Added columns are
  always nullable: the rows already in the table have no value for
  them, and no engine accepts `NOT NULL` without a default on a
  populated table.
- `sqlstore`: writes silently dropped keys the schema did not declare.
  `Create` and `UpdateMany` rendered themselves by walking the schema's
  fields, so an unknown key was skipped and the caller was told the
  write succeeded — while a *read* filtering on the same key had always
  been an error. Both now reject it, naming the fields. The in-memory
  adapter matches (Mongo already did), and `storage/storagetest` pins it
  for every backend.
- `sqlstore.New(nil, ...)`, the DDL-generator form, stored a typed-nil
  `*sql.DB` in the `Queryer` interface, so the `no database handle`
  guards never fired and `Migrate` panicked instead of reporting.
- `apikey`: a malformed quota column was treated as *unlimited* on the
  contention-retry path while the first read treated it as exhausted.
  Both now fail closed.
- `twofactor`: `send-otp` reported the wrong error when the session
  lookup failed, masking the real cause.
- `jwt`: `/jwks` decrypted every stored private key on the way through
  and silently skipped any it could not read, so one unreadable row
  quietly shrank the published key set and every token that key had
  signed started failing verification at the relying party — which
  cannot tell that apart from a forgery. It now decodes only the public
  halves, which need no secret at all, and refuses the request outright
  if a *public* key is corrupt rather than publishing an incomplete set.
  It also no longer loads the signing key just to publish, so an
  unreadable private key does not affect the endpoint.
- `Auth.maybeDecrypt` returned its input when decryption failed. A
  caller could not distinguish a plaintext token from a ciphertext one,
  and `/refresh-token` forwarded the `enc:…` blob to the third-party
  provider. It now returns an error, reported as
  `500 TOKEN_DECRYPTION_FAILED` with an operator-actionable log line.
