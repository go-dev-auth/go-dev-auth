# Security model

This document makes the library's threat-model reasoning explicit: which
attackers it defends against, which design decisions follow from that,
and — because a claim without a test is a hope — how each claim is
verified in this repository. Report vulnerabilities as described in
[SECURITY.md](../.github/SECURITY.md), not in public issues.

## Attacker model

The library is designed against four attackers:

1. **The network attacker** — controls traffic, replays requests,
   guesses credentials at scale, and manipulates OAuth redirects.
2. **The malicious registered user** — holds a valid account and probes
   every endpoint for what it will accept that its siblings refuse:
   privilege escalation, forced account linking, validation bypass.
3. **The database reader** — has read access to the datastore (a stolen
   backup, a leaky replica, an over-scoped internal tool) but not to the
   application's `Secret`.
4. **The log consumer** — receives the structured auth events (a SIEM,
   a third-party observability vendor) and must not thereby receive
   credentials.

Out of scope: an attacker with code execution on the application host, a
malicious operator (whoever holds `Secret` and the database can do
anything), and hardware side channels beyond response timing.

## Design decisions and the reasoning behind them

### Credentials cost the attacker more than they cost you

Passwords are hashed with scrypt (N=16384, r=16, p=1 — the same
parameters and `salt:key` encoding better-auth uses), verified in
constant time. Because each verification deliberately burns ~50 ms and
~32 MiB, the hashing path is itself a denial-of-service surface, so it
is bounded: concurrency is capped so peak memory has a ceiling, and
requests that cannot get a slot are shed with 503 rather than queueing
into collapse. Sign-in burns equivalent work when no account exists, so
timing does not reveal whether an address is registered.

### The database is assumed readable

Every one-time token — password reset, email verification, magic link,
account deletion, OAuth state — is stored only as a SHA-256 digest and
claimed atomically. Read access to the database therefore yields no
redeemable links, and a race between two redemptions of the same token
has exactly one winner.

Secrets that must be recoverable (OAuth refresh tokens, TOTP seeds, JWT
signing keys) are encrypted with AES-256-GCM under keys derived from
`Secret`. Crucially, each ciphertext is **bound to its location**: the
`(model, record, field)` coordinates are folded into the GCM additional
data, so a ciphertext copied from a victim's row into an attacker's row
refuses to decrypt. This closed a real read-oracle: before binding, an
attacker with database write access could relocate a victim's encrypted
refresh token into their own 2FA row and read it back through the TOTP
URI endpoint. Key rotation is versioned and explicit
(`PreviousSecrets` + `ReencryptSecrets`), never a silent fallback, and
`RequireBoundCiphertexts` lets a deployment refuse legacy unbound
values once migration is done.

### Fail closed, on the weird cases especially

Fields that decide access (`role`, `banned`, `twoFactorEnabled`) are
never writable from a request body. A security-deciding column holding
a value of an unexpected type is treated as its most restrictive
meaning, not skipped. `SignInGuard` runs on every sign-in path — social
and plugin sign-ins included — and `SessionGuard` on every request,
including API-key-authenticated ones, so a ban enforced in one place is
enforced everywhere.

### Every door applies the same rules as the front door

A recurring real-world bug class — found by production users of this
library, twice — is the side entrance: an admin create-user, an
organization invite, a magic-link sign-in that accepts an email or role
the public sign-up path would refuse. The doctrine now enforced by
regression tests is: **any endpoint that creates users, credentials or
roles calls the same exported validators as sign-up**
(`ValidateEmail`, `ValidatePassword`, the role allow-lists). The
mechanical review question that catches this class — "does this
endpoint accept what its sibling refuses?" — is written into the test
suite rather than a checklist.

### Sessions and cookies

Session tokens carry 32 bytes of entropy; raw tokens never appear in
API responses. Cookies are HMAC-SHA256 signed with domain separation
and get the `__Secure-` prefix over HTTPS. The optional cookie cache is
an availability optimisation with a hard security boundary: an
allow-list of fields, a 4 KB cap, and an absolute revalidation deadline
that cached data can never extend.

### OAuth without trusting the redirect

Authorization always uses PKCE (S256). State is single-use, expiring,
cookie-bound to the browser and pinned to the issuing provider. ID
tokens are verified against the issuer's JWKS with issuer, audience,
`azp`, expiry and nonce checks. Automatic account linking — the classic
account-takeover vector — requires both a provider-asserted verified
email **and** that the provider is explicitly listed in
`TrustedProviders`; the concurrent-callback race is settled by a
database composite-unique constraint, not a check-then-create.

### Events are safe to ship to someone else's infrastructure

The structured event trail exists to be exported, so no event may carry
a credential. This is enforced by reflection: the test drives every
credential-touching flow, then walks every string field of every
recorded event and fails if any contains a password, token or session
secret used during the run. A field added next year is covered without
anyone remembering to extend the test.

### Migrations cannot half-apply a constraint

Schema migration takes a session-pinned advisory lock (PostgreSQL
`pg_advisory_lock`, MySQL `GET_LOCK`), applies each table's DDL
transactionally where the engine allows, and runs a self-heal pass that
restores a unique index an interrupted migration lost — because a
declared-unique column silently accepting duplicates is a security
failure, not an inconvenience. A migration that would add a unique
constraint over existing duplicate rows fails loudly and names them
rather than dropping data.

## How the claims are verified

| Claim | Verification in this repository |
|---|---|
| Adapter contract holds on real databases | `storagetest` conformance suite runs in CI against real SQLite, PostgreSQL and MySQL servers (`storage/sqlstore/integration`), with `REQUIRE_DSN=1` so a leg cannot pass by silently skipping |
| Parsers survive hostile input | 16 fuzz targets over token, cookie, ciphertext, TOTP and request parsing — the attacker-controlled surfaces — run as a CI job on every PR |
| No data races | full suite under `-race` in CI |
| Events carry no secrets | `TestEventsCarryNoSecrets` (reflection over every event field) |
| Every route enforces authorization | route authorization sweep in `plugins/plugintest/authsweep_test.go` walks registered routes and asserts unauthenticated/unauthorized refusals |
| Ciphertext relocation refused | regression tests replay the original attack end-to-end over HTTP |
| Migration interruption heals | test drops the backing index, observes the drift reported, re-migrates, and proves the constraint is enforced again |
| Side-door validation bypasses stay closed | failing-first regression tests on every endpoint of the class, each proven by reverting the fix |

## What the library expects from the deployer

The short version — the full list lives in
[SECURITY.md](../.github/SECURITY.md): a strong secret kept out of
source control, a correct `BaseURL`, HTTPS in production, rate limiting
left enabled (it is load-bearing), the schema and its unique indexes
actually created, periodic `CleanupExpired`, and `TrustProxyHeaders`
only behind a proxy that strips client-supplied forwarding headers.

## Honest limits

PostgreSQL and SQLite are exercised end to end (Postgres also in
production by real applications); MySQL is exercised by the same CI
conformance suite but has no field mileage yet. MongoDB is tested
against an in-house wire-protocol double, not a live server. There has
been no third-party security audit yet; until there is one, this
document and the tests it points at are the strongest available
evidence, and they are offered as exactly that — evidence, not proof.
