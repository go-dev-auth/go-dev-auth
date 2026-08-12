# Security Review #2 — MongoDB support, hardening, re-audit

Round two. Adds a MongoDB adapter, closes the outstanding gaps from review #1, and re-audits everything with two independent hostile reviewers: one on the new surface, one verifying the earlier fixes still hold after a substantial refactor.

**Headline:** all 13 previously-fixed vulnerabilities still hold, verified by execution rather than reading. The new review found **9 more real defects**, 4 of them high severity, including a two-factor challenge that could be replayed for unlimited sessions. All are fixed and covered by regression tests.

---

## MongoDB support

`adapters/mongoadapter` — its own Go module, so the core library keeps zero dependencies:

```go
client, _ := mongo.Connect(options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
store := mongoadapter.New(client.Database("myapp"))
auth, err := godevauth.New(godevauth.Config{Database: store, /* ... */})
```

Design points that matter:

- **`id` maps to `_id`**, so identity lookups use the primary index and id uniqueness is enforced by the server rather than by application code.
- **Indexes are created automatically** by `godevauth.New`. This is not cosmetic: MongoDB creates collections lazily, so a deployment whose unique indexes were never built looks completely healthy while every "does this email already exist?" check silently degrades into a race. The SQL adapter fails loudly in that situation (no tables); Mongo would not have. Proven by the reviewer, then fixed.
- **NoSQL injection is blocked structurally.** Composite values are rejected wherever MongoDB would interpret them as operators — the `{"$ne": null}` shape. The reviewer probed 10 variants (`bson.M`, `map[string]any`, named types with map underlying kind, typed-nil maps and slices, `primitive.Regex`, `bson.D`, and `OpIn` element smuggling); all were rejected.
- **Substring search escapes regex metacharacters.** `.*`, `^a`, `(?i)`, `[a-z]*` and `\Q…\E` all match zero rows; only literal text matches.
- **Schema names are validated**: a field called `_id`, one starting with `$`, or one containing `.` is refused, so no plugin can reach an arbitrary BSON path.

### How it is verified without a MongoDB server

There is no mongod available in this environment, and none obtainable. Rather than ship untested code, the adapter is exercised two ways:

1. **A wire-protocol test double** (`internal/fakemongo`, ~1,600 lines) that the *real* `mongo-go-driver` connects to and operates against — OP_MSG framing, document sequences, cursors, `findAndModify`, aggregation for `CountDocuments`, and unique-index enforcement producing genuine `E11000` errors.
2. **The shared conformance suite**, the same 20 cases the memory and SQL adapters must pass.

**Be clear about what this proves and what it does not.** It proves the adapter builds correct commands, parses responses correctly, and behaves identically to the other two backends. It does *not* prove fidelity to real MongoDB semantics — the fake is my own model of MongoDB, so a shared misunderstanding would pass. **Run the suite against a real mongod (and a replica set, for `Transaction`) before production use.** The fake's limitations are documented exhaustively in its package comment.

---

## The shared adapter conformance suite

`adapter/adaptertest` — one contract all three backends must satisfy, added because review #1's worst bug was a *divergence*: the API-key plugin worked on the in-memory adapter and was completely broken on every SQL one, because a NULL integer decoded as `0` there and as "absent" here.

It pins 20 behaviours: unique-violation reporting, NULL vs zero, type round-trips, chronological sorting, every operator, clause-folding precedence, literal case-insensitive substring matching, compare-and-set update counts, expiry sweeps, and concurrent unique inserts. Writing a custom adapter? Run it.

It immediately earned its keep — it caught three live divergences the moment it ran against all three backends:

- **Clause folding.** `[a, b, OR c]` meant `(a AND b) OR c` in memory and Mongo, but SQL's native precedence made it `a OR (b AND c)`. The same query silently meant different things on different databases.
- **Case sensitivity.** SQLite's `LIKE` ignores ASCII case, PostgreSQL's does not, MySQL depends on collation, and the memory adapter used `strings.Contains`. Now defined as case-insensitive everywhere.
- **Empty updates.** Memory reported the match count, SQL and Mongo reported zero — and a caller reading that count as "the write happened" is exactly the compare-and-set pattern the API-key quota depends on.

---

## Real-database SQL integration tests

`adapters/sqladapter/integration` — a separate module running the conformance suite and full end-to-end auth flows against **real SQLite** (cgo). This was the largest open gap from review #1. It found three genuine adapter bugs:

- **LIKE wildcard injection (P1).** `%` and `_` were interpolated into LIKE patterns unescaped. The admin plugin feeds `?searchValue=` straight into these operators, so **`?searchValue=%` dumped the entire user table** while appearing to be a search.
- **Integrity errors misreported as duplicates.** A bare `"constraint failed"` needle matched SQLite's `NOT NULL`, `FOREIGN KEY` and `CHECK` failures too — so a genuine data-integrity bug surfaced to users as "that account already exists" and never appeared as a 5xx anyone would investigate.
- **Invalid SQL for offset-without-limit.** `OFFSET n` with no `LIMIT` is a syntax error on SQLite and MySQL, though the API permits it and the other two adapters honour it.

---

## New security findings (all fixed)

### High

**1. Two-factor challenges were replayable and brute-forceable.** Recording a failed guess wrote a *new* verification row; lookups returned only the newest; consuming deleted only that one. Older rows survived. Observed: 30 wrong codes produced 13 "too many attempts" lockouts while the challenge stayed alive, then the correct code returned **200 with a session — twice**. A 6-digit second factor was searchable within its 10-minute window, and a stolen pending cookie minted unlimited sessions. Fixed by making the write replace prior rows; the helper that does it already existed and was dead code.

**2. One-time tokens were multi-redeemable under concurrency.** `ConsumeToken` did lookup-then-delete with no compare-and-set. With realistic database latency, **6 of 6 concurrent callers redeemed the same token**. Reachable from magic links, password reset, account deletion, change-email and OAuth state. The delete is now the claim: only the caller whose delete removed a row gets the value.

**3. Permanent bans silently lifted themselves on MongoDB.** Clearing a field was impossible — a nil or zero value was dropped from the update rather than written — so lifting an expired ban left the stale expiry behind, and the *next* permanent ban immediately read as expired. Proven end to end with the real admin payloads. Mongo-only, so the shared conformance suite would never have caught it; updates now emit `$unset`.

**4. One unauthenticated request could block JWKS key rotation indefinitely.** The refresh cooldown was started *before* the fetch and never rolled back, so an attacker sending an ID token with a random key id and disconnecting burned the cooldown. One request per minute would keep every Google/Apple/Microsoft ID-token sign-in failing once the provider rotated its signing key. The rate limiter was exactly inverted — protecting the provider from the attacker while letting the attacker deny service to users.

### Medium

**5. Security flags failed *open* on a type mismatch.** `banned`, `twoFactorEnabled`, `enabled` and `remaining` were read with bare type assertions, so a value of the wrong type meant "not banned", "no 2FA", "key enabled", "unlimited quota". Reachable through the admin plugin's free-form `data` map. All four now fail closed.

**6. Bans were ignored on two paths.** A cookie-cache hit skipped the session guards entirely, and API keys never ran them at all — a banned user's key kept working and cheerfully returned `"banned": true` in the payload. Both fixed; note the cache is now *bypassed* when a guard plugin is registered, because running a guard against a cached copy of the user inspects stale fields and waves the request through while looking like it checked.

**7. ID tokens without an `exp` claim never expired**, `iat` was unchecked, the `Leeway` option was dead code, and multi-audience tokens skipped the `azp` check that stops a token issued to a *different* relying party from being accepted.

**8. Data race on the shared provider spec** during concurrent ID-token verification (proven under `-race`), plus the JWKS mutex held across the network fetch with no HTTP timeout — one hung provider stalled every verification process-wide.

**9. Revoked JWKS keys were served from cache forever** on any fetch failure. Now bounded by a stale-serve grace window, after which it fails closed.

Also fixed: reserved core column names accepted into the client-writable allowlist (which would have quietly reopened mass assignment); unbounded admin search strings evaluated twice per request against unindexable patterns; unvalidated `filterField` returning 500 instead of 400; SQL identifier quoting not escaping embedded quotes; deletion tokens consumed before the ownership check (letting anyone burn a victim's link).

---

## Regression verification of review #1

All 13 items **VERIFIED-HOLDS**, by executing the attacks:

| Item | Evidence |
|---|---|
| Mass assignment | `role`, `banned`, `twoFactorEnabled`, `emailVerified`, `id` all ignored at sign-up and update-user; declared `Input` field writable; non-admin blocked from admin routes |
| `/refresh-token` | anonymous → 401; authenticated attacker with victim's `userId` → 400, body ignored |
| 2FA bypass | password / magic link / social / verification auto-login all return the challenge; only the 3 intended call sites bypass the guard |
| OAuth state | replayed callback in a second browser → `state_mismatch`; cross-provider replay → `state_mismatch` |
| Cookie cache | revocation took effect within the cache window |
| Change-email | works end to end; refuses a verified address without confirmation; token single-use |
| Account linking | requires verified **and** trusted; the other three combinations rejected |
| Session tokens | absent from all three listing endpoints |
| One-time tokens | stored as digests; replay rejected |
| Rate limiting | 9 of 12 sign-ins → 429; store error → 429 (fails closed) |
| delete-user | GET confirms only; another user's session → 400 |
| Bans | rejected on every sign-in path and on live sessions |
| 405 / config validation | 405 with `Allow`; all 7 unsafe configs rejected |

---

## Verification summary

- **5 modules**, 68 Go files, ~19,800 lines. Build, `go vet` and `gofmt` clean.
- **All tests pass**, including the conformance suite against **three** backends (in-memory, real SQLite, MongoDB-over-wire-protocol).
- **Race detector clean** across every module.
- **Regression coverage**: 12 tests from review #1 plus 7 new ones, each reproducing a specific vulnerability and failing against the code before its fix.
- Performance unchanged: session validation ~2 µs, password hashing ~55 ms / 340 KB.

## Remaining limitations (honest list)

- **No real MongoDB or PostgreSQL/MySQL server was available here.** SQLite is covered for real; Mongo is covered against a faithful-but-self-authored test double. Run both suites against real servers before production — that is the single most valuable next step.
- MongoDB `Transaction` requires a replica set and is untested against one.
- The fake mongod does not model MongoDB's concurrency (global mutex), index internals, or array-element matching.
- Still not ported from better-auth: passkeys/WebAuthn, phone/SMS, anonymous sessions, multi-session, OIDC provider, SSO. All fit the existing plugin interfaces.
- `Field.Type` is not enforced at the adapter boundary — the security-relevant readers now fail closed instead, which is the safe half of that fix; validating on write is still worth doing.
