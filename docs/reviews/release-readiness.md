# Release-readiness assessment

Date: 8 August 2026. Question asked: *is this perfect, does it actually
work, and can we publish it?*

**Verdict: it works, it is not perfect, and it must not be published
today.** One blocker was introduced by this week's own fixes, and it is
worse than any of the three defects those fixes removed.

- **Does it work?** Yes. Every flow was exercised over real HTTP against
  a running server. 19/19 functional checks behaved correctly.
- **Is it perfect?** No. 3 blockers, 9 serious and ~10 minor defects
  remain open, listed in full below.
- **Publish as v0.1.0?** Not yet. Three fixes stand between here and a
  defensible tag, and one of them changes an on-disk format — far
  cheaper now than after strangers have data in production.

---

## 1. Test results — everything that was actually run

All figures measured on this machine (4-core arm64 container, Go 1.26.5)
on 8 August 2026. Nothing here is estimated.

### 1.1 Static analysis

| Check | Result |
|---|---|
| `gofmt -l .` | **0 files** unformatted |
| `go vet ./...` | **0 findings** (clean for the first time; previously 20+, see §2.5) |

### 1.2 Unit tests — core module, `go test -count=1 ./...`

**16/16 packages PASS.**

| Package | Time |
|---|---|
| root (`godevauth`) | 6.75s |
| crypto | 0.84s |
| oauth2 | 0.61s |
| plugins/admin | 0.09s |
| plugins/apikey | 0.12s |
| plugins/bearer | 0.13s |
| plugins/jwt | 0.18s |
| plugins/magiclink | 0.02s |
| plugins/organization | 0.18s |
| plugins/plugintest | 0.06s |
| plugins/twofactor | 0.46s |
| providers | 0.004s |
| ratelimit | 0.07s |
| storage | 0.01s |
| storage/memory | 0.01s |
| storage/sqlstore | 0.003s |

### 1.3 Race detector — `CGO_ENABLED=1 go test -race ./...`

**16/16 packages PASS, zero race warnings.** Root package 69.7s.

### 1.4 Integration — real SQLite, `CGO_ENABLED=1`

**PASS — 20 tests**, 1.25s. This is the only *real* database exercised:
a file-backed SQLite database, full DDL, migration, conformance suite
and a complete HTTP auth flow.

### 1.5 MongoDB module — **FAILS TO BUILD**

```
storage/mongostore$ go test ./...
mongostore.go:33: missing go.sum entry for go.mongodb.org/mongo-driver/bson
FAIL [setup failed]
```

`storage/mongostore` has **no committed `go.sum`**, so it cannot be
built or tested by anyone who clones the repository — including CI. It
also `require`s `github.com/go-dev-auth/go-dev-auth v0.1.0`, a tag that
does not exist. Could not be fixed here: the module proxy and
`go.mongodb.org` are both blocked in this sandbox. **Must be fixed
before publishing**, and it is a one-command fix on a networked machine.

### 1.6 Test inventory

| Metric | Count |
|---|---|
| Test functions | **257** |
| Fuzz targets | **16** |
| Benchmarks | 13 |
| Runnable examples | **35** |
| Committed fuzz seed corpus | 7 files |
| Source lines | 18,637 |
| Test lines | 14,196 (0.76 test:source ratio) |

### 1.7 Coverage — `-coverpkg=./...`, **75.3% overall**

| Package | Coverage |
|---|---|
| plugins/bearer | 100.0% |
| plugins/magiclink | 95.5% |
| ratelimit | 92.8% |
| plugins/plugintest | 92.8% |
| plugins/twofactor | 91.7% |
| plugins/organization | 90.7% |
| plugins/jwt | 90.4% |
| crypto | 90.4% |
| plugins/apikey | 87.6% |
| storage/memory | 85.2% |
| storage | 84.3% |
| plugins/admin | 81.5% |
| **root** | 80.3% |
| providers | 75.8% |
| storage/storagetest | 73.6% |
| **oauth2** | 64.7% |
| **storage/sqlstore** | 50.1% |
| examples/basic | 0.0% |

The two weakest are the two that matter most for a first release:
`oauth2` (only exercisable against a real provider) and `sqlstore` (the
new migration code, only exercised against SQLite).

### 1.8 Fuzzing — 16 targets, 32.9M executions previously measured

`make fuzz-list` discovers all 16. Spot-checked `FuzzAppendJSONString`
at 10s: **807,084 executions, PASS**, ~75k exec/s. Three real bugs were
found by these targets when first run, all fixed, all with committed
regression seeds — including U+2028/U+2029 unescaped in the hand-written
JSON encoder, a script-context escape.

### 1.9 Benchmarks (in-memory adapter — not production latency)

| Operation | Result |
|---|---|
| Password hash | 55.3 ms/op, 171,962 B/op, 28 allocs |
| Password verify | 56.1 ms/op, 3,720 B/op, 23 allocs |

Deliberately slow — that is scrypt working as intended.

### 1.10 Functional end-to-end — real server, 5 plugins, 70 routes

Built and ran a server with twofactor + organization + admin + jwt +
apikey. **19/19 checks correct:**

| # | Check | Result |
|---|---|---|
| 1 | sign-up | 200 |
| 2 | get-session (authenticated) | 200 |
| 3 | list-sessions | 200 |
| 4 | update-user | 200 |
| 5 | change-password | 200 |
| 6 | organization create | 200 |
| 7 | organization list | 200 |
| 8 | api-key create | 200 |
| 9 | JWKS (public) | 200 |
| 10 | 2FA enable | 200 |
| 11 | admin route as non-admin | **403** ✓ |
| 12 | forget-password | 200 |
| 13 | sign-out | 200 |
| 15 | anonymous list-sessions | **401** ✓ |
| 16 | anonymous admin | **401** ✓ |
| 17 | anonymous org create | **401** ✓ |
| 18 | unknown route | **404** ✓ |
| 19 | wrong method | **405** ✓ |
| — | cross-origin POST with session cookie | **403** ✓ CSRF holds |

The README quickstart compiles and runs verbatim. `auth.CallbackURL("google")`
returns the correct redirect URI. 2FA correctly requires a verification
step before it takes effect.

**One wart (#14):** `GET /get-session` when signed out returns
`HTTP 200`, `Content-Type: application/json`, **`Content-Length: 0`** —
an empty body with a JSON content type. `JSON.parse("")` throws in every
browser client. better-auth returns `null`. Minor but it will be the
first bug report.

---

## 2. What was fixed since the last review — verified, not asserted

| Was | Now | Evidence |
|---|---|---|
| 0 fuzz targets, docs claimed 8 and 4.4M execs | **16 targets, 32.9M execs measured** | `make fuzz-list`; 3 real bugs found and fixed |
| No `ALTER TABLE` — enabling a plugin broke every sign-in | **Column migration + drift detection** | 20 integration tests on real SQLite; a test reproduces the exact production symptom when the fix is disabled |
| Secret rotation locked out every 2FA user forever | **Versioned keys + `PreviousSecrets`** | End-to-end test: TOTP sign-in survives a rotation |
| Password-reset link dead-ended by default | **Fixed; `New` refuses the broken config** | New test follows the emailed URL verbatim |
| No auth audit trail at all | **25 event types incl. impersonation** | Reflection test asserts no event carries a credential |
| Rate limiting behind a proxy = fleet-wide outage | **`TrustedProxies` required; `New` rejects half-configs** | `proxy_test.go` |
| `go vet` 20+ findings; CI's Go 1.22 leg could not compile | **vet clean; 1.22 floor real** | `t.Context()` removed throughout |
| CI started 3 DB containers and tested none | **Job renamed to the truth: SQLite** | `ci.yml` |

That is real progress. It is also why the next section matters.

---

## 3. Open defects

### 3.1 BLOCKERS

**BL-1 — At-rest encryption can be defeated by relocating ciphertext.
REGRESSION, introduced by this week's rotation work.**

`crypto.Keyring.Encrypt(plaintext string)` takes no context parameter.
The GCM additional authenticated data is `v1.<kid>`, and `kid` derives
from the key alone — so **every ciphertext in a deployment has
byte-identical AAD**. Reproduced directly:

```
totp header : v1.xPSBV9Ra
oauth header: v1.xPSBV9Ra
jwt header  : v1.xPSBV9Ra
ALL HEADERS IDENTICAL: true
```

Nothing binds a value to its model, row, column or user, so any
encrypted value can be pasted into any other encrypted column and will
decrypt cleanly.

This becomes a **read oracle** because `handleGetTOTPURI`
(`plugins/twofactor/twofactor.go:391`) requires only the caller's *own*
session and *own* password, then decrypts `twoFactor.secret` and returns
it in the response — and `crypto.TOTPURI` (`crypto/otp.go:82`) does no
base32 validation, echoing arbitrary bytes verbatim.

So an attacker with **database write access** and an ordinary account
can copy any encrypted value — another user's TOTP secret, another
user's OAuth refresh token, or the JWT plugin's Ed25519 signing key —
into their own `twoFactor.secret` row, call `POST /two-factor/get-totp-uri`,
and read the plaintext. Recovering the signing key means forging a JWT
for any user.

Scope honestly: this needs database write access; it is not remotely
exploitable by an anonymous user. But at-rest encryption exists
*precisely* to limit the damage of database compromise, so against the
read-write case the feature currently buys nothing.

**Fix:** thread a context (`model || recordID || field`) into
`Encrypt`/`Decrypt` and bind it into the AAD; separately, validate the
secret is base32 before putting it in a URI. This changes the on-disk
format, which is why it must land *before* a public tag.

> **Resolved (unreleased).** `crypto.Keyring.Encrypt`/`Decrypt` take a
> `crypto.Binding{Model, Record, Field}`, authenticated as part of the
> AAD of the new `v2.<kid>.<body>` format. `crypto.TOTPURI` returns an
> error for anything that is not base32 of at least 80 bits, and the
> two-factor plugin re-validates after decrypting. `v0`/`v1` values
> still read so deployments are not bricked; `ReencryptSecrets`
> migrates them and `Config.RequireBoundCiphertexts` then refuses them.
> Regression tests: `TestKeyringCiphertextCannotBeRelocated`
> (`crypto/aead_test.go`) and
> `plugins/twofactor/relocation_test.go`, which stands the full
> read-oracle attack up over HTTP.

**BL-2 — `Migrate` is not atomic; a lost unique index is permanent and
silent. REGRESSION.**

`Migrate` (`storage/sqlstore/sqlstore.go:135`) uses no transaction, no
advisory lock and no version table. On SQLite a unique column is added
as two statements (`ALTER TABLE ADD COLUMN`, then `CREATE UNIQUE INDEX`);
if the process dies between them, the column exists so the field is
skipped forever, and both `Migrate` and `CheckSchema` return success
while the uniqueness constraint is silently gone. For an auth library, a
declared-unique identifier degrading to non-unique with no signal is a
security property lost invisibly. Auto-migrate is on by default, and
concurrent boot during a rolling deploy crash-loops the losing replica.

Also here: SQLite and the ANSI-fallback introspection are **unscoped**
(`migrate.go:41,53,78`), so a temp or attached table of the same name
produces a false all-clear.

**BL-3 — `account` has no composite unique on `(providerId, accountId)`.
PRE-EXISTING.**

The schema model cannot express a composite constraint at all
(`storage/storage.go:149-177`). Confirmed empirically: two identical
`(providerId, accountId)` rows both insert. `linkOAuthAccount`
(`handler_social.go:419-463`) is a check-then-create race with no
database backstop, so two concurrent OAuth callbacks — "user
double-clicks Sign in with Google" — can produce two account rows
pointing at different local users, after which resolution is row-order
dependent and unlink breaks.

### 3.2 SERIOUS

| # | Defect | Origin |
|---|---|---|
| S-1 | `ReencryptSecrets` does read-modify-write with **no optimistic concurrency**, despite documenting itself "safe to run on a live instance". It can silently revert a freshly refreshed OAuth token, and — worse — **restore 2FA backup codes a user just rotated after a compromise**. Also loads whole tables into memory (no batching). **Resolved (unreleased):** every write is a compare-and-set on the ciphertext the pass read (skipped rows are reported in `ReencryptResult.Skipped`), tables are walked in batches of 200 in id order, and one failing plugin rotator no longer aborts the rest. | REGRESSION |
| S-2 | The v0 legacy fallback keeps a single-SHA-256 derivation of the same secret alive. One surviving v0 row voids the scrypt hardening. And `Secret` is used raw as the cookie HMAC key anyway, so any signed-up user holds a free offline verification oracle. | REGRESSION |
| S-3 | `defaultLiteral` (`dialect.go:161`) escapes `'` but not `\`. A backslash-terminated `Field.Default` injects raw DDL into MySQL `CREATE TABLE`. Developer-controlled, not user-controlled. | REGRESSION |
| S-4 | `POST /set-password` needs only a session — no re-auth, no `IsFresh` check, no notification, no session revocation, and default-tier rate limiting. A hijacked session on a social-only account becomes a permanent password credential. | PRE-EXISTING |
| S-5 | Cookie cache serialises the whole user record including `Extra` into a **signed but unencrypted** cookie with no size guard. Measured an 8,956-byte `Set-Cookie` with an SSN readable in the clear. Opt-in, HttpOnly. | PRE-EXISTING |
| S-6 | Memory adapter silently ignores unknown fields in *reads*. Worse than first thought: `OpEq` fails closed, but **`OpNe` matches everything** — an exclusion filter like "not banned" against a stale column silently becomes "match all". | PRE-EXISTING |
| S-7 | `sqlstore.Update` mass-updates against a documented first-match contract (no `LIMIT`), diverging from memory and mongo. The conformance suite never tests a multi-match `Where`, so it cannot catch this. | PRE-EXISTING |
| S-8 | `Auth.Config()` returns a mutable pointer to the live config; `a.config` is read unsynchronised on every request. A write is a genuine data race on `Secret` / `TrustedOrigins` / `DisableCSRFCheck`. | PRE-EXISTING |
| S-9 | `storage/mongostore` has no `go.sum` and cannot build (§1.5). | PRE-EXISTING |

### 3.3 MINOR

`kid` uses a compile-time global scrypt salt, so one precomputed table
works against every deployment · no identifier validation on the SQL
path (Mongo has one) · `defaultLiteral` silently drops float and time
defaults · legacy trial-decrypt leaks which previous secret wrote a
value · `EncryptString`/`DecryptString` remain exported foot-guns ·
`GET /get-session` returns an empty body rather than `null` ·
`Required` columns added by migration are never backfilled ·
`CheckSchema` compares column names only, so type and nullability drift
are invisible · quickstart panics if `AUTH_SECRET` is unset (the message
is excellent, so this is arguably correct).

---

## 4. Intent versus delivery

The stated goal was *"implement the exact features we have on better-auth,
for Golang, don't miss anything."*

### Delivered

Email/password with scrypt · social sign-on (OAuth 2.0 / OIDC, PKCE, 11
providers) · database-backed sessions · account linking · email
verification · password reset · change email/password · delete user ·
CSRF and trusted origins · rate limiting · request and database hooks ·
custom fields · 4 storage backends · plugin system · **7 plugins**
(twofactor, magiclink, organization, admin, apikey, jwt, bearer) · plus
things better-auth does not have: a storage conformance suite, zero
dependencies, a structured audit trail.

### Not delivered

| Missing | Why it matters |
|---|---|
| **Passkeys / WebAuthn** | The single biggest gap. better-auth 1.6 added passkey-first onboarding. A new auth library in 2026 without passkeys reads as dated. |
| **SSO (SAML 2.0 + OIDC)** | The feature that unlocks enterprise buyers. |
| **OAuth 2.1 / OIDC provider** | Being an identity provider, not just a client. |
| **OpenTelemetry** | Added in better-auth 1.6. |
| Phone/SMS, anonymous sessions, multi-session, org-owned API keys | Smaller gaps. |

**Honest parity score: roughly 70% of better-auth's feature surface**, and
the missing 30% contains the two features enterprise buyers screen for.
"Don't miss anything" was not achieved — and the target moved during
development, which is the structural risk of porting a funded, actively
released project.

### Does it solve the problem it set out to solve?

For the case "I want embedded auth in a Go service, with no external
identity server and no dependency tree" — **yes, functionally.** All 19
end-to-end checks pass. The architecture is sound. The security design
is above average, and the single-funnel `SignInUser` with guards is
better than most libraries in this category.

For "drop-in better-auth parity" — **no.**

---

## 5. Market position (unchanged)

19 Go better-auth ports exist. The best has 3 stars. The realistic
ceiling for this category in Go is `authboss`: 4,198 stars over eleven
years. Incumbents in adjacent shapes: authelia 28.5k, supertokens 15.3k,
zitadel 14.7k, casdoor 14.1k, ory/kratos 13.8k, goth 6.6k.

This project is materially more complete than any of the 19. That is
necessary and not sufficient — Go developers tend to compose (`goth` +
`scs` + their own user table) rather than adopt a framework that owns
their schema.

---

## 6. Verdict and the shortest path to publishable

**Not perfect. Working. Not publishable today.**

The gap between "our tests are green" and "this is safe to publish" is
exactly BL-1: 257 tests, 16 fuzz targets and a clean race detector did
not catch a defeat of the at-rest encryption, because the tests verify
that encryption round-trips — not that a ciphertext cannot be moved.
That is worth internalising more than any individual fix.

**Before tagging v0.1.0 — three items:**

1. **BL-1** — bind the AAD to `model || recordID || field`, and stop
   `TOTPURI` echoing an unvalidated secret. Changes the on-disk format;
   must precede any public tag.
2. **BL-2** — wrap migration per-table in a transaction, take an
   advisory lock, scope SQLite introspection to `main`, and make
   `CheckSchema` verify indexes and not just column names.
3. **S-9** — commit `go.sum` for `storage/mongostore` (and drop the
   reference to the non-existent `v0.1.0` tag). One command on a
   networked machine; without it the module is unbuildable.

**Then, cheaply, before announcing:** BL-3 (composite unique), S-4
(`/set-password` re-auth), S-1 (concurrency control in
`ReencryptSecrets`), and return `null` from `/get-session`.

**Before claiming parity:** passkeys, then SSO.

My estimate: items 1–3 are a focused day. The full serious list is
perhaps a week. Passkeys and SSO are the larger project — and they are
what decide whether this competes at all.
