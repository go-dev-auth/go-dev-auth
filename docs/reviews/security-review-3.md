# Security Review #3 — empirical pen test + cost optimization

Round three has two halves that pull in opposite directions, so they were done separately: an adversarial test of whether the service actually holds up, then a cost pass that only touches things which are *not* load-bearing for security.

**Result: no P0 or P1 findings.** One P2 and two P3s, all fixed. The authenticated request path is now **~48% faster and allocates 54% less**, with no change to any security property.

| ID | Severity | Finding | Status |
|---|---|---|---|
| 1 | P2 | Hand-written JSON encoder left U+2028/U+2029 unescaped, breaking the `<script>`-embedding safety it documented | Fixed |
| 2 | P3 | Same encoder emitted the raw replacement character for invalid UTF-8 instead of the JSON escape | Fixed |
| 3 | P3 | A `*.example.com` trusted origin also matched the bare host `.example.com` | Fixed |
| 4 | P3 | Other sessions survived a password change | Fixed |

---

## Part 1 — Security: attacking a running service

Previous rounds were code review. This one was empirical: 16 native Go fuzz targets, committed to the repository and runnable by anyone, plus live attacks against a running instance with every plugin enabled.

> **An earlier revision of this document described fuzzing and an authorization
> sweep that did not exist in the repository.** The tests described below were
> written afterwards to make the claims true, and every number in this section
> was measured by running them. See "Reproducing" at the end of Part 1.

### Fuzzing — 32.9M executions, three findings

Each target asserts a security property, not just the absence of a panic. The recurring shape is *acceptance implies authenticity*: when a verifier returns success for fuzzer-supplied bytes, the test recomputes the only input that could legitimately have been accepted and fails if they differ. A signature bypass therefore fails the test even though it does not crash.

Measured at `-fuzztime=30s -fuzzminimizetime=3s` per target, 4 workers, one run each:

| Target | Package | Executions | Result |
|---|---|---:|---|
| `FuzzVerifyJWT` — HMAC/RSA/EC/Ed25519 | `crypto` | 3,269,355 | pass; acceptance implies a recomputable MAC or the genuinely signed token |
| `FuzzJWTAlgConfusion` | `crypto` | 1,824,804 | pass; HS256-keyed-on-the-public-key and `alg:none` never verify |
| `FuzzDecodeJWTClaims` | `crypto` | 3,340,857 | pass |
| `FuzzJWKPublicKey` — hostile `kty`/`crv`/`x`/`y`/`n`/`e` | `crypto` | 2,887,351 | pass; no imported key ever verified an unsigned token |
| `FuzzScryptVerify` — the `salt:key` hex path | `crypto` | 3,556,002 | pass; a malformed hash never authenticates |
| `FuzzVerifyTOTP` | `crypto` | 3,091,803 | pass; acceptance implies a code inside the skew window |
| `FuzzVerifyHMACPurpose` | `crypto` | 3,615,103 | pass; domain separation and key separation hold |
| `FuzzDecryptString` (AES-GCM) | `crypto` | 3,325,849 | pass |
| `FuzzSplitSigned` | root | 1,286,247 | pass; the split is lossless and the signature half is always the last segment |
| `FuzzVerifyCookieValue` | root | 1,262,758 | pass; acceptance implies the server signed it, for that purpose |
| `FuzzMatchPath` | root | 1,139,970 | pass; captures reconstruct the path exactly and never span `/` |
| `FuzzIsTrustedOrigin` | root | 1,179,075 | **1 finding (fixed)** |
| `FuzzSafeRedirect` | root | 1,044,040 | pass; every accepted target is relative or on a trusted origin |
| `FuzzAppendJSONString` (differential) | `storage` | 899,841 | **2 findings (1 fixed, 1 benign)** |
| `FuzzUserMarshalJSON` (differential) | `storage` | 714,437 | pass |
| `FuzzSessionMarshalJSON` (differential) | `storage` | 503,942 | pass; the raw token never reaches the body |
| **Total** | | **32,941,434** | |

**Finding 1 — U+2028/U+2029 were not escaped by the hand-written JSON encoder.** `storage/json.go` documented its output as identical to `encoding/json`'s, "HTML-escaping included, so it stays safe to embed in a `<script>` block". It escaped `<`, `>` and `&` but not U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR), which `encoding/json` does escape. Those two characters terminate a string literal in JavaScript, so a user-controlled `name` containing one breaks out of the JSON string when the response is interpolated into a `<script>` block — precisely the property the comment claimed. The existing equivalence tests compared *decoded* values and so could not see it. Fixed; the reproducers are pinned in `storage/testdata/fuzz/FuzzAppendJSONString/`.

**Finding 2 — invalid UTF-8 was emitted as the raw replacement character rather than its six-character JSON escape.** Same decoded value, so not exploitable, but it meant the output was not byte-identical to `encoding/json` and a byte-level differential could not be used as an oracle. Fixed so the exact comparison is available.

**Finding 3 — a wildcard trusted origin matched its own bare suffix.** With `TrustedOrigins: ["https://*.wild.example.com"]`, the origin `https://.wild.example.com` was trusted: the check was a plain `strings.HasSuffix` against `".wild.example.com"`, so the `*` was allowed to stand for nothing. Not reachable from a browser (that host is not registrable and no browser would send it), but the wildcard should require at least one character. Fixed in `origin.go`; the reproducer is pinned in `testdata/fuzz/FuzzIsTrustedOrigin/bare-wildcard-suffix`.

Two further failures the targets produced were oracle artefacts, not code defects, and the targets were corrected rather than the code: `encoding/json`'s choice of escape for form feed changed between Go 1.22 and 1.26 (so the differential compares against an independent in-test reference for bytes, and against `encoding/json` for decoded values), and a route pattern naming the same parameter twice cannot be reconstructed from a map (no such route exists).

### Authorization sweep — all 82 routes

`plugins/plugintest/authsweep_test.go` enumerates every registered route through `Auth.Routes()` — core plus all seven plugins, with every optional route group enabled — so it cannot drift when a route is added. Measured surface: **82 routes; 61 require a session, 21 are on an explicit public allowlist written out in the test, each with a reason.**

The sweep asserts:

- **No credentials.** Every route must answer 401 with code `UNAUTHORIZED` or `SESSION_EXPIRED`, or appear on the allowlist. Matching on the *code* rather than the status is what separates "this endpoint is protected" from "these credentials were wrong" — `/sign-in/email` also answers 401. A route that is unintentionally public fails the test with the route name and the status it returned.
- **An ordinary user's session.** Nothing answers 5xx.
- **A second, unrelated user's session.** Every `/admin/*` route must answer 401 or 403. The one exception, `/admin/stop-impersonating`, is listed explicitly with its reason: it is called *by* the impersonated non-admin session and only acts when the server itself set `session.impersonatedBy`.
- **No stale allowlist entries** (an entry naming a route that no longer exists would hide a rename), and **no duplicate route registrations** (where only the last handler is reachable).

The sweep was validated by mutating a scratch copy of the repository outside the tree: adding an unauthenticated `GET /api-key/oops-list-all` and downgrading `/admin/list-users` from `requireAdmin` to `RequireSession`. It caught both.

The previous revision of this document listed `/organization/check-slug` as intentionally public. It is not: it requires a session, and the sweep confirms it.

### Reproducing

```sh
make fuzz-list                       # the 16 targets
make fuzz FUZZTIME=30s               # run each one
go test -run TestEveryRouteRequiresAuthentication -v ./plugins/plugintest/
```

`make fuzz` now iterates package-by-package and target-by-target (`go test -fuzz` accepts only one of each, so the previous `./...` form could not have worked) and **exits non-zero when it finds no targets** — the failure mode that let the CI fuzz job pass while executing nothing.

### Measured attack results

| Attack | Result |
|---|---|
| 200 concurrent bad sign-ins, rate limiting **off** | Heap 32 → 130 MiB (**bounded**, not the ~6.4 GiB naive 200 × 32 MiB would imply). Median latency 1.46s — the concurrency cap works, but the queue was the weak point. **Fixed in Part 2.** |
| Same, rate limiting **on** (default) | Capped at 429 after 3 attempts |
| Enumeration timing | Nonexistent user 53.1 ms vs wrong password 50.7 ms — ratio **0.95**, indistinguishable |
| 10 MB body / 1 MB query / 10k cookies / 10k-deep JSON / 100k-key JSON | 400 or 401, no 5xx, memory bounded |
| CSRF: cross-origin `Origin`, `Referer`, `Sec-Fetch-Site` | 403 in every variant |
| Rate-limit evasion via rotating `X-Forwarded-For` | Not evaded with default config (XFF ignored unless `TrustProxyHeaders` is on) |
| Session survival after password reset / user deletion | Correctly invalidated |

### Session revocation on password change

**P3 (finding 4) — other sessions survived a password change.** A user who changes their password specifically to evict an attacker found the attacker's other session still working. Password *reset* correctly revoked everything; *change* only did so if the client explicitly asked. That inconsistency is the whole bug: the user takes the action they believe evicts the intruder, and it doesn't.

Fixed — changing a password now revokes every other session by default (the current one survives), matching reset. Opt out with `KeepSessionsOnPasswordChange`. Regression test included.

Two deployment footguns were also flagged and are now documented rather than changed: `TrustProxyHeaders` without a proxy that strips client-supplied `X-Forwarded-For` lets a client pick its own rate-limit bucket; and the per-route rate limit is load-bearing for availability, not just for brute-force resistance.

---

## Part 2 — Cost: measure, then optimize

Optimization was driven by an allocation profile of the authenticated request path, not by intuition. The profile said **~55% of all allocations came from one thing**: JSON responses were built by constructing a `map[string]any` and letting `encoding/json` reflect over it.

### Results

| Benchmark | Before | After | Change |
|---|---|---|---|
| Full HTTP request | 7,705 ns, 103 allocs, 11,954 B | **4,010 ns, 47 allocs, 9,462 B** | **−48% time, −54% allocs** |
| Session validation (parallel) | 2,039 ns, 31 allocs, 2,496 B | **634 ns, 21 allocs, 1,648 B** | **−69% time** |
| HMAC (per cookie verify) | 640 B, 10 allocs | **152 B, 4 allocs** | **−76% memory** |
| User JSON encode | 2,093 ns, 27 allocs, 1,360 B | **1,880 ns, 2 allocs, 544 B** | **−93% allocs** |
| Session lookup @ 10k rows | 626 ns | **465 ns** | −26% |
| Password hash | 54.8 ms, 340 KB | 51.5 ms, **21 KB** | memory −94% |

What changed:

1. **Hand-written JSON encoders** for `User` and `Session` — append directly to a byte slice, no intermediate map, no reflection. This is the risky kind of change, so it is backed by a test that compares output against the previous `encoding/json` implementation across escaping edge cases (quotes, backslashes, control characters, HTML-significant characters, non-ASCII, **invalid UTF-8**), plus tests pinning that HTML escaping still happens and that the raw session token still cannot appear — including via a maliciously named `Extra` key.

   Those tests were not enough. They compared *decoded* values, which is blind to an escaping gap that changes only the bytes — and that is exactly the gap findings 1 and 2 were. The differential fuzz target `FuzzAppendJSONString` now compares bytes against an independent reference implementation as well, and pins the script-safety invariants directly. If you take one thing from this review, take that: an equivalence test that normalises before comparing cannot see the class of bug an escaping function actually has.
2. **Cached unique-field lists** in the memory adapter — previously reallocated a slice on every index touch, i.e. on every read and write.
3. **Pooled HMAC state** — every authenticated request verifies a signed cookie, and each verification was constructing a hasher plus two padded key blocks.

### The two levers that matter more than any of that

**Database round trips, not CPU.** An authenticated request costs two queries (session, then user) ≈ 2 ms on a managed database — roughly *500×* the ~4 µs of CPU the request itself uses. The session cookie cache reduces that to zero. It was previously disabled outright whenever a `SessionGuard` plugin was registered (the admin plugin's ban check), which silently removed the biggest cost lever from anyone using admin. Now it is a documented choice: `CookieCache.AcceptStaleAuthorization` takes the saving and accepts that bans apply within `MaxAge`.

**Password hashing is the CPU bill and should stay that way.** ~51 ms per sign-in ≈ `sign-ins/sec ÷ 20` cores. I did **not** reduce it: that cost is the security property. The right lever is frequency — sessions last 7 days, so a signed-in user pays it once.

What I did do is make saturation behave properly. The pen test measured 1.46s median latency under a hashing flood: memory stayed bounded, but requests queued, and multi-second latency is what upstream clients experience as a hang and retry — the standard way a slow dependency becomes an outage. Requests that cannot get a hashing slot within `MaxWait` (default 3s) are now shed with a retryable **503 SERVICE_BUSY**. Critically, saturation is *not* reported as invalid credentials, which would have told legitimate users their password was wrong.

---

## Verification

- Core module: `go test ./...` and `go test -race ./...` both green; `gofmt` clean.
- Conformance suite still green against all three backends (in-memory, real SQLite, MongoDB-over-wire-protocol).
- 4 new resilience tests: password-change revocation, load shedding under saturation, normal-load queueing must *not* shed, cookie-cache opt-in.
- 5 new JSON-encoder equivalence/safety tests.
- **16 fuzz targets** across `crypto`, the root package and `storage`, run for 30s each (32.9M executions total). Their seed corpora run on every `go test`, so the three findings above are permanent regression tests.
- **5 authorization-sweep tests** over all 82 routes, validated against a deliberately vulnerable copy of the repository.
- `make fuzz` and the CI fuzz job were both fixed: the job previously iterated an empty target list and passed having run nothing.

## Unchanged limitations

Still no real MongoDB or PostgreSQL/MySQL server in this environment — SQLite is covered for real, Mongo against a faithful test double. Running both suites against real servers remains the highest-value next step before production.
