# Product and QA assessment

Date: 6 August 2026. Scope: the whole project — code, claims, and
market position. Written to be useful rather than flattering.

**Short answer to "will developers definitely use it?" — No, not as it
stands.** Not because the engineering is bad; the security design is
genuinely above average. Because (a) three defects make it unsafe to run
past its first production week, (b) the backends most people deploy have
never been executed against, and (c) the market evidence says this niche
has been attempted 19 times and nobody has gained traction.

---

## 1. What was measured

| Metric | Value |
|---|---|
| Source | 16,212 lines, 82 Go files, 21 packages |
| Tests | 8,128 lines, 210 test functions |
| Aggregate coverage | 69.7% |
| External dependencies (core module) | **0** |
| HTTP endpoints | 82 |
| Storage backends | 4 (memory, Postgres, MySQL, SQLite, MongoDB) |
| Tagged releases | **0** — no commits in the repository at all |

Verification that passes today: `gofmt`, `go vet`, all 15 packages under
`-race`, SQLite against a real database file.

---

## 2. Accuracy — the part that matters most

An auth library is judged on whether its claims are true. Three of ours
are not, and I found them by verifying rather than trusting.

### 2.1 The repository documented tests that did not exist — RESOLVED

*Original finding, kept because the failure mode is worth remembering:*

`docs/reviews/security-review-3.md` stated *"8 native Go fuzz targets and
4.4M+ executions, zero crashes"* and an *"authorization sweep — all 80
routes"*.

```
$ grep -rn "^func Fuzz" --include='*.go' .   →   0 results
$ go test -list 'Fuzz.*' ./...               →   empty
```

There were **zero fuzz targets in the repository**. The fuzzing had been
run in a scratch directory and the targets were never committed. The
`make fuzz` target looped over an empty list and exited 0, so the CI
`fuzz` job **passed having executed nothing**. A security document that
cites unreproducible evidence is worse than no document: it invites a
reader to skip the verification they would otherwise do.

**Resolved by writing the tests rather than deleting the claims:**

```
$ grep -rn "^func Fuzz" --include='*.go' .   →   16
$ make fuzz-list                             →   16 targets across 3 packages
$ go test -run TestEveryRouteRequiresAuthentication -v ./plugins/plugintest/
                                             →   swept 82 routes
```

`make fuzz` now iterates package-by-package and target-by-target, and
exits non-zero when it discovers no targets, so the original failure mode
cannot recur silently. The measured execution counts and the three
findings the targets produced are in
`docs/reviews/security-review-3.md`; the numbers there were measured, not
estimated.

### 2.2 The integration CI job is inert

`.github/workflows/ci.yml` starts `postgres:16`, `mysql:8` and `mongo:7`
service containers and exports `POSTGRES_DSN`, `MYSQL_DSN`,
`MONGODB_URI`. **No Go file reads any of them.**
`storage/sqlstore/integration/go.mod` requires only `mattn/go-sqlite3` —
there is no Postgres or MySQL driver in the repository. MongoDB is tested
only against a hand-written wire-protocol fake that is larger than the
adapter it tests.

Neither submodule has a committed `go.sum`, so as checked in they cannot
build at all.

So: the Postgres `$n` placeholders, the MySQL backtick quoting and
`LIMIT 18446744073709551615` offset hack, and the driver-error string
matching that turns a duplicate-signup race into a 409 rather than a 500
— none has ever run. The README's claim that "all three pass the same
conformance suite" is not true today.

### 2.3 The README overstates the perf numbers

The benchmark table measures the in-memory adapter. It is a fair
measure of the request path and an unfair proxy for production, where a
network round-trip dominates. It should say so.

---

## 3. Correctness — three findings that block production

Found by an independent adversarial review, then verified directly.

**B1 — There is no schema migration path.** `MigrationSQL()` emits only
`CREATE TABLE IF NOT EXISTS`. There is no `ALTER TABLE` anywhere in the
repository (verified: 0 occurrences). But plugins add *columns to
existing tables* — `admin` adds `role`, `banned`, `banReason`,
`banExpires` to `user`. Enabling a plugin on a live database is a silent
no-op, and the next `SELECT "role","banned" FROM "user"` fails, breaking
**every sign-in and every session lookup**. The README's "re-run after
adding plugins" advice is actively misleading. This fires on the first
feature change after go-live.

**B2 — `Config.Secret` cannot be rotated.** The AES key is a single
`sha256("go-dev-auth-enc:" + secret)` with no key ID and no dual-key
window. Rotating the secret makes every stored TOTP secret permanently
undecryptable — **every 2FA user locked out, unrecoverably**. Stored JWT
signing keys are silently dropped from JWKS with a log line. Any
organisation with a key-rotation policy cannot run this.

**B3 — The password-reset link is broken by default.** The emailed link
only carries `callbackURL` if the caller passed `redirectTo`, and
`handleResetPasswordRedirect` bails to the error page when `callbackURL`
is empty (`handler_email.go:253-258`). Following the library's own
emailed link with the README's configuration yields
`302 → /api/auth/error`. Nothing documents `redirectTo` as mandatory.
An advertised flow does not work out of the box.

### Serious, below the blocker line

- `sqlstore` **silently drops writes** to fields absent from the schema
  (reads on unknown fields error loudly; writes succeed and change
  nothing) — this compounds B1 into silent data loss.
- **No composite unique constraint** on `account (providerId, accountId)`
  — the schema model cannot express one. Account linking is a
  check-then-create race with no database backstop, and every social
  sign-in is a sequential scan.
- **`Adapter.Update` violates its own contract on SQL**: documented as
  updating the first match, it updates *all* matches (no `LIMIT`), and
  differs from the memory adapter. The conformance suite that should
  catch this only runs against memory and the Mongo fake.
- **Rate limiting is an availability footgun.** The key is
  `ClientIP() + path`, and `ClientIP` ignores `X-Forwarded-For` unless
  `TrustProxyHeaders` is set. Deploy behind any load balancer with the
  defaults and the entire fleet shares one bucket: 3 sign-ins per 10
  seconds, globally, fail-closed. Set the flag without a
  header-stripping proxy and any client picks its own bucket. Neither
  default is safe and the quick-start says nothing.
- **Effectively zero auth observability.** Not one log line or hook for
  sign-in, sign-out, session revocation, password reset, ban, or **admin
  impersonation**. That is a SOC 2 control, not a nice-to-have.
- **`POST /set-password`** grants permanent credential access from a
  stolen session with no re-auth and no freshness check, even though
  `IsFresh` exists and is used elsewhere.
- **`Auth.Config()` returns a mutable pointer to the live config** — any
  goroutine can flip `DisableCSRFCheck` on a serving instance.

### What is genuinely good

Worth stating plainly, because it is the reason this is salvageable:

- `SignInUser` as a single funnel with `SignInGuard`/`SessionGuard`
  closes a real bypass class, and the reasoning about *not* running
  guards against cached session data is correct and rare.
- `ConsumeToken`'s delete-count-is-the-claim is the right primitive.
- `Session.MarshalJSON` omits the raw token with a reserved-key set so an
  `Extra` field cannot reintroduce it.
- The CSRF chain (Origin → Referer → `Sec-Fetch-Site` → cookie presence
  → User-Agent) is more careful than most implementations.
- Fail-closed rate limiting, `dummyVerify` for enumeration resistance,
  and scrypt load shedding are all correct calls.
- The comments explain *why*, not *what*. Rare and valuable.

---

## 4. Market position — the uncomfortable data

### The niche is crowded and nobody has won it

GitHub search for Go better-auth ports returns **19 repositories**.
Ranked by stars:

| Stars | Repository | Last push |
|---|---|---|
| 3 | theinventorylib/aegis | 2026-05-23 |
| 3 | nikeokoronkwo/better-auth.go | 2025-10-18 |
| 3 | jasoncolburne/better-auth-go | 2025-11-07 |
| 3 | Zytera/better-auth-sdk-go | 2026-07-24 |
| 2 | ganthiyalabs/better-auth-go | 2025-12-20 |
| 2 | lborres/kuta | 2026-08-03 |
| 1 | dnahilman/goten | 2026-07-27 |
| … | 12 more | mostly 0 stars |

**The best-performing attempt has three stars.** Several are abandoned
within months of starting. This project would be the 20th entrant.

Two readings, and they matter:

1. *Nobody has executed well yet — the opportunity is open.* Plausible:
   most of those repos are thin. This project is substantially more
   complete than any of them.
2. *Go developers do not want this shape of library.* Also plausible,
   and I lean towards it being the larger factor. Go culture favours
   composing small pieces — `goth` for OAuth, `scs` for sessions,
   `golang-jwt` for tokens, your own user table — over adopting a
   batteries-included framework that owns your schema. A framework that
   controls your `user` table is a much bigger commitment in Go than the
   equivalent is in TypeScript.

### What the incumbents look like

| Stars | Project | Shape |
|---|---|---|
| 28,495 | authelia/authelia | Auth server / portal |
| 15,250 | supertokens/supertokens-core | Self-hosted service + SDKs |
| 14,652 | zitadel/zitadel | Full IAM, Go, event-sourced |
| 14,126 | casdoor/casdoor | IAM + Casbin authorization |
| 13,813 | ory/kratos | Identity service |
| 6,586 | markbates/goth | **Go library** — social auth only |
| 4,198 | aarondl/authboss | **Go library** — the closest analogue |

`authboss` is the honest comparison: same shape, same ambition, 11 years
old, 4.2k stars, still maintained. That is the realistic ceiling for
this category in Go — and it is a ceiling reached over a decade.

### Feature gap against the thing being ported

better-auth shipped 1.5 (Feb 2026) and 1.6 (Apr 2026) while this port
targeted an earlier feature set. Missing today:

- **Passkeys / WebAuthn** — the most important gap. better-auth 1.6 added
  passkey-first onboarding. In 2026 a new auth library without passkeys
  reads as dated.
- **SSO (SAML 2.0 + OIDC)** — the feature that unlocks enterprise buyers.
- **OAuth 2.1 / OIDC provider** — being an IdP, not just a client.
- **OpenTelemetry instrumentation** — added in 1.6; we have no
  observability at all.
- Phone/SMS, anonymous sessions, multi-session, organization-owned API
  keys.

Porting a moving target means the gap widens unless the project keeps
pace, and a solo/small project will not keep pace with a funded one.

---

## 5. Verdict

**Useful?** The design work is real and better than most auth code I
would review. Zero dependencies in the core is a genuine, defensible
differentiator in a Go ecosystem that is rightly wary of supply chain.
The plugin architecture and the storage conformance suite are the right
abstractions.

**Accurate?** Not yet, in the specific sense that matters: the
documentation claims verification that did not happen, and the three
databases most people deploy have never had a statement executed against
them. Coverage of 69.7% is respectable; coverage of the *right things*
is not established.

**Successful — will developers adopt it?** Not on the current evidence.
The rational forecast is single-digit stars, like the other 19. To beat
that forecast the project needs a reason to exist that is not "better-auth
but Go," because six other projects already say that.

The credible positioning is **zero-dependency, embeddable, auditable Go
auth** — aimed at teams who will not add an identity service and will not
take 40 transitive dependencies. That is a real, underserved audience.
It requires the claims to be true.

### The order I would fix things

**Before showing anyone:**

1. ~~Delete the unsupported claims from `docs/reviews/` and the README, or
   commit the fuzz targets and authorization sweep they describe.~~ **Done:**
   16 fuzz targets and a 5-test authorization sweep over all 82 routes are
   committed, and `make fuzz` now fails rather than passing on an empty list.
2. Fix B3 (reset link) — an advertised flow that fails on first use.

**Before a v0.1.0 tag:**

3. Real migration generation (`ALTER TABLE ADD COLUMN`, a version ledger,
   and a startup check that fails loudly on drift).
4. Postgres and MySQL drivers in the integration module, `go.sum`
   committed, the conformance suite actually run against all backends in
   CI.
5. Versioned encryption keys with a dual-key decrypt window.
6. Structured auth-event hooks (actor, IP, outcome).
7. Document the `TrustProxyHeaders` deployment requirement in the
   quick-start, and fail loudly on the unsafe combination.

**Before claiming parity:**

8. Passkeys / WebAuthn.
9. SSO.

Items 1–2 are hours. Items 3–7 are the difference between a prototype
and a dependency. Items 8–9 are the difference between a dependency and
a competitor.

---

## Sources

Competitive and feature data gathered 6 August 2026 from the GitHub
search API and:

- <https://better-auth.com/blog/1-6>
- <https://better-auth.com/blog/1-5>
- <https://better-auth.com/docs/plugins/sso>
- <https://workos.com/blog/top-authentication-solutions-go-2026>
- <https://skycloak.io/blog/open-source-authentication-comparison-2026/>
