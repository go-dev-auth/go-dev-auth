# go-dev-auth — QA & Product Review

Audit of the library as delivered, followed by the remediation work. Two independent hostile code reviews (core, plugins/adapters), a benchmark pass, a race-detector pass and a concurrency stress suite. Two of the findings were confirmed by executing exploit code against the library, not by reading it.

**Verdict before:** functionally impressive, not shippable. Three defects were exploitable by an anonymous user, one plugin was entirely non-functional on the only database backend anyone deploys, and one advertised feature never worked end to end.

**Verdict after:** all P0 and P1 findings fixed, 22 regression tests added that fail against the old code, race-clean under load, and the worst resource problem cut by 289×.

---

## What was actually wrong

### P0 — exploitable by an anonymous or ordinary user

**1. Anyone could register themselves as an admin.** Every column on the user table was copied straight from the request body. Plugins add columns to that same table — `role`, `banned`, `twoFactorEnabled` — and the admin plugin reads exactly those to decide authorization. Verified by running it: `POST /sign-up/email {"email":…,"password":…,"role":"admin"}` returned a user with `"role":"admin"`, and that session then got `200` from an admin-only route. The same body on `/update-user` escalated an existing account; `{"banned":false}` lifted a ban; `{"twoFactorEnabled":false}` disabled 2FA with no password check.

*Fix:* extra fields are now opt-in per field (`Field.Input`) and only fields the application itself declared are ever eligible. Plugin-declared columns are never client-writable.

**2. `/refresh-token` required no authentication.** It accepted a `userId` from the body, decrypted that user's stored OAuth refresh token, called the provider, wrote the new tokens to the victim's row and returned the fresh access token in the response. Unauthenticated third-party token theft plus an unauthenticated write.

*Fix:* requires a session; the `userId` parameter is gone.

**3. Two-factor authentication was bypassable.** The 2FA interceptor ran in exactly one place — password sign-in. Magic links, every OAuth provider and the email-verification auto-login all minted sessions directly. A user with 2FA on was fully protected on `/sign-in/email` and completely unprotected via `/sign-in/magic-link`.

*Fix:* all sign-in paths now funnel through `SignInUser`, which runs `SignInGuard` plugins. Choosing another method no longer skips the second factor.

**4. The API-key plugin was dead on every SQL backend.** A NULL integer column decoded as `int64(0)`, and the plugin reads `remaining == 0` as "quota exhausted". Since `remaining` is omitted for unlimited keys, every key was rejected. Verified with a stub driver. It passed CI only because the in-memory adapter returns a missing key instead of a zero.

*Fix:* NULL decodes as `nil`, not a fabricated zero — "unset" and "zero" are different everywhere now. Field defaults are also applied on create.

### P1 — high

**5. OAuth login CSRF.** State lived only in a shared table, tied to nothing. An attacker could complete their own provider flow, hand the victim the resulting callback URL, and silently sign the victim into the attacker's account — where anything the victim then does lands in the attacker's hands. State also wasn't pinned to a provider, so a state minted for one was accepted at another's callback.

*Fix:* state is bound to the browser with a cookie and pinned to the issuing provider. Regression test replays a captured callback in a second browser and asserts it fails while the original still succeeds.

**6. Session revocation didn't work when the cookie cache was on.** The cache refreshed itself *from cached data*, resetting its own deadline. Any SPA polling `/get-session` more often than the 5-minute cache window never touched the database again for the session's full 7-day life. Revoke endpoints, ban-and-revoke and password-reset revocation all deleted rows nobody read.

*Fix:* the payload carries an absolute revalidation deadline stamped at database read time and never extended from cache.

**7. Change-email never worked.** The handler stored the approval token under `change-email:` and the verify endpoint looked up `email-verification:`. The link always failed. Worse, when no confirmation sender was configured the guard fell through and a verified user's address changed immediately — a stolen session could relocate the account and take it over via password reset.

*Fix:* implemented properly, single-use, re-checks the address is still free, and refuses to move a verified address without confirmation. Two regression tests.

**8. nOAuth-style account takeover.** Auto-linking accepted `EmailVerified || trustedProvider` — an *or*. Several shipped provider mappers set `EmailVerified: email != ""`, and Microsoft Entra's email claim is user-settable. Setting a victim's address at the provider was enough to be handed their existing local account.

*Fix:* both conditions required, and mappers no longer fabricate verification.

**9. Concurrent sign-ups created duplicate users.** Eight parallel sign-ups for one address produced eight users — the existence check is racy and nothing enforced uniqueness. On SQL the loser got a raw driver error surfaced as `500`.

*Fix:* `adapter.ErrUniqueViolation` sentinel, per-dialect detection, unique enforcement in the memory adapter. Test asserts exactly one user and one `200`.

**10. API-key quotas were unenforceable.** Read-modify-write on a stale snapshot; 20 concurrent requests spent a quota of 5 six times over. Every API-key request also cost 6 round trips including 2 writes, turning read-only endpoints into write transactions.

*Fix:* compare-and-set with retry; usage counters throttled to once a minute per key (configurable, disableable).

**11. `Migrate()` failed outright on MySQL.** `CREATE INDEX IF NOT EXISTS` isn't MySQL syntax, and an indexed TEXT column is rejected without a prefix length. A MySQL user could not create the schema at all.

**12. Session tokens were returned in JSON.** `/list-sessions` handed back a raw bearer token for every device the user was signed in on — one XSS or one logged response body was full multi-device takeover, defeating the HttpOnly cookie.

**13. Ban enforcement covered only `/sign-in*`** by path prefix, and it also leaked which addresses are banned before any password was checked. A banned user could still sign in via OAuth, and an existing session kept working.

*Fix:* ban is now a `SignInGuard` (after credential verification, so no enumeration oracle) plus a `SessionGuard` that runs on every request.

**14. Password reset left existing sessions alive** by default — the standard "I've been compromised" action left the attacker signed in for another 7 days. Now revokes by default.

**15. JWT signing-key race:** two cold starts each inserted a key, and JWKS only ever published the newest, so tokens signed by the loser were rejected by every relying party. Rotation was impossible. Fixed with caching, adopt-on-conflict and publishing all keys.

**16. Rate limiting was off by default and failed open.** Password verification costs ~50 ms and ~32 MiB per attempt; an unthrottled sign-in endpoint is both a brute-force target and a cheap DoS amplifier. Now on by default and fail-closed.

Also fixed: unbounded verification-table growth (no sweeper existed), one-time tokens stored in plaintext, `delete-user` tokens not bound to the caller and deletable by a GET that link scanners will follow, silent plaintext fallback when OAuth token encryption failed, `list-users?limit=99999999999999999999` overflowing to a negative limit that dumped the whole table, org invitations bypassing the member limit and being redeemable twice, invitations accepting a team from a different organization, N+1 queries (104 round trips for one org page), SQLite timestamps sorting wrong so the expiry sweeper deleted valid rows, transactions leaking connections on panic, and 404-instead-of-405 on method mismatches.

---

## Performance

Measured before and after on a 4-core arm64 container.

| | Before | After | |
|---|---|---|---|
| Password hash (memory) | 33.6 MB/op | 116 KB/op | **289× less** |
| Password verify (memory) | 33.6 MB/op | 3.7 KB/op | **9,000× less** |
| `GenerateID` (every record) | 13.6 µs, 98 allocs | 0.6 µs, 3 allocs | **22× faster** |
| Session lookup @ 10k rows | 336 µs | 0.6 µs | **550× faster** |
| Session validation (parallel) | 0.96 µs | 0.94 µs | unchanged |
| Full HTTP request | 3.4 µs | 6.5 µs | slower, and correct |

The password-hash memory figure was the headline risk: 33 MB allocated *per sign-in attempt* meant 20 concurrent sign-ins touched 670 MB of fresh heap. Buffers are now pooled and hashing concurrency is bounded (default `GOMAXPROCS`), so peak transient memory is `GOMAXPROCS × 32 MiB` regardless of load. CPU per hash is unchanged at ~54 ms — that cost is the point of scrypt, which is why rate limiting is now on by default.

`GenerateID` was calling `crypto/rand.Int` once per character. It now draws one batch and uses rejection sampling. The memory adapter was a full table scan under a global lock on every session lookup; it now indexes unique fields.

The full HTTP path got ~3 µs slower because it now runs session guards and a real CSRF decision. At 6 µs per request that is not the bottleneck — a single password hash costs 8,000× more.

---

## What users get that they didn't have

- **CORS helper** (`auth.CORS`) — credentialed cross-origin requests need exact-origin echo plus `Allow-Credentials`; wired to the same trusted-origin list as the CSRF check so the two can't drift.
- **Cleanup** — `CleanupExpired` / `StartCleanup`. Without it the verification table grew forever, since abandoned magic links are never looked up again.
- **Config validation at startup** — missing or short `Secret`, missing/relative `BaseURL`, `SameSite=none` without secure cookies. `BaseURL` silently defaulting to `http://localhost:8080` previously meant a production deployment behind a TLS proxy got non-Secure cookies and localhost in its trusted-origin set.
- **`SignInGuard` / `SessionGuard`** — the plugin hooks that make 2FA and bans unbypassable.
- **`auth.Routes()`**, `auth.NewCtx()`, JWT `RotateKey`, tunable scrypt params, `405` + `Allow`.

---

## Verification

- 4 packages, all tests green, `go vet` clean, `gofmt` clean.
- **22 new tests**, including 12 that reproduce a specific vulnerability and fail against the previous code.
- **Race detector clean** across the whole suite (30 s of contended execution), including concurrent sign-up, concurrent session reads under the cookie cache, API-key quota contention and concurrent invitation redemption.
- End-to-end smoke test against the running example server: escalation attempt in the sign-up body ignored, `405` on method mismatch.

## Known limitations (deliberate, documented)

- The in-memory adapter is single-process; multi-instance deployments need SQL plus a shared rate-limit store.
- No SQL integration tests run in CI here — there is no database in this environment. The dialect DDL and encode/decode paths are unit-tested, but Postgres/MySQL/SQLite should get a real integration run before release.
- Apple ID tokens are trusted from the token endpoint without JWKS signature verification (defensible over TLS, but `aud` should be pinned).
- Not yet ported from better-auth: passkeys/WebAuthn, phone/SMS, anonymous sessions, multi-session, OIDC provider, SSO. All fit the existing plugin interface.
