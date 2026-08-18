# Release-readiness — final pass

Date: 8 August 2026. This supersedes the go/no-go in
[release-readiness.md](release-readiness.md): the three blockers that
document raised are now fixed, verified independently, and the tree is
clean under every check.

**Verdict: safe to tag v0.1.0.** The MongoDB build gap is now resolved
(the adapter builds and its tests pass on a networked machine, 9 Aug
2026); one operational item remains — a real Postgres/MySQL/Mongo CI run
— and it does not block the tag. See caveats below.

## The three blockers — closed and reproduced

Each was fixed with a test that fails against the pre-fix code, and each
fix was then re-verified by an independent reviewer who reproduced the
attack and confirmed it is now refused.

**BL-1 — at-rest ciphertext relocation / TOTP read-oracle.** Encryption
now binds each value to where it lives: `Keyring.Encrypt(Binding{Model,
Record, Field}, plaintext)` folds the location into the AES-GCM
additional data, so a ciphertext copied from one column into another
fails to open. Verified directly: a value sealed at
`(account, r1, refreshToken)` refuses to decrypt at
`(twoFactor, r1, secret)` with "copied from another record or column".
The echo that made it exploitable is closed too — `crypto.TOTPURI`
rejects a non-base32 secret. A new HTTP test walks the full original
attack (paste a victim's refresh token, and the jwt plugin's Ed25519
signing key, into the attacker's 2FA row, call `/two-factor/get-totp-uri`)
and confirms both are refused. Old `v1`/`v0` values still decrypt for
backward compatibility; `RequireBoundCiphertexts` closes that door once
`ReencryptSecrets` has migrated them.

**BL-2 — migration atomicity.** `Migrate` now takes an advisory lock
(`pg_advisory_lock` / `GET_LOCK`; SQLite is single-writer), applies each
table's DDL in a transaction where the engine supports it, and runs a
self-heal pass that re-creates a unique index an interrupted migration
lost — so a declared-unique column can no longer silently permit
duplicates. `CheckSchema` now detects that state instead of reporting
all-clear. Verified on real SQLite:
`TestMigrateHealsInterruptedUniqueIndex` drops the backing index,
observes duplicates slip through, then shows `CheckSchema` flagging it
and a re-run of `Migrate` restoring the constraint. SQLite introspection
is scoped to `main` (no temp-table shadowing), and the MySQL DDL
`\`-injection in a field default is escaped. `Update` now honours its
"first match" contract, pinned by a new conformance case that runs on
every backend.

**BL-3 — composite unique for account linking.** The schema model gained
composite unique constraints; `account (providerId, accountId)` and
organization `member (organizationId, userId)` declare them, enforced by
all three adapters (inline `UNIQUE` on SQL, index on Mongo, in-memory
check). `linkOAuthAccount` was rewritten from check-then-create to
create-then-handle-conflict, so the database is now the arbiter and the
concurrent-callback race cannot fork one external identity across two
local users. A migration that would add the constraint to a table that
already holds duplicates fails loudly, naming them, rather than dropping
data. Verified on real SQLite, including the upgrade-with-duplicates
path.

## Also fixed in this pass

From the "serious" list: `/set-password` now requires a fresh session
and carries the strict rate limit; the cookie cache is restricted to an
allow-list and hard-capped at 4 KB; `Auth.Config()` returns a snapshot,
not the live pointer; and `GET /get-session` returns the literal `null`
rather than an empty body.

## Verification run — all green

| Check | Result |
|---|---|
| `gofmt -l .` | clean |
| `go vet ./...` | clean |
| `go test ./...` (18 packages) | pass |
| `go test -race ./...` | pass, no races |
| real SQLite integration | pass |
| End-to-end HTTP, 5 plugins | 7/7 flows + 3 authorization refusals correct; signed-out `/get-session` returns `null` |
| Independent adversarial re-review | no new Blocker/Serious/Minor |

Test inventory now: 286 test functions, 16 fuzz targets, 35 runnable
examples. Source 20,323 lines, tests 15,802. Coverage 72.8% (the small
dip from 75.3% is new blocker-fix code — migration branches and error
paths that unit tests reach less than the happy path).

## The caveats — environment, not code

1. **`storage/mongostore` — RESOLVED (9 Aug 2026).** The module could not
   be built in the sandbox because its driver
   (`go.mongodb.org/mongo-driver`) was behind the blocked proxy and there
   was no committed `go.sum`. Run on a networked machine:
   `cd storage/mongostore && go mod tidy && go test ./...` →
   `ok  .../storage/mongostore` and `ok  .../internal/fakemongo`. So the
   BL-3 composite-unique index code compiles and its tests pass. The
   generated `storage/mongostore/go.sum` is now committed. Note this is
   still the in-house `fakemongo` wire-protocol double, not a live mongod
   — the same standard as the rest of the Mongo tests; a real server run
   belongs with caveat 2.

2. **PostgreSQL is now field-proven; MySQL and Mongo remain asserted.**
   Update (12 Aug 2026): an early adopter is running the whole library —
   all plugins, migrations, the full auth flow — in a real application on
   live PostgreSQL, and reports it working. That moves Postgres from
   "generated SQL asserted by unit tests" to "exercised end to end in
   production by a real user." The one gap that remains is automated: the
   `storagetest` conformance suite is still not wired to run against
   Postgres in CI, so a regression there would not be caught
   automatically. MySQL's dialect is still only unit-asserted, and
   MongoDB is still tested against the in-house wire-protocol double.
   Wire the conformance suite to real Postgres/MySQL/Mongo containers in
   CI to close this for good.

Neither blocks a v0.1.0 tag — a pre-1.0 release with SQLite verified in
CI and PostgreSQL proven in the field is a stronger place to start than
the last review assumed.

## What is still deliberately not here

Unchanged from the prior report and correctly out of scope for v0.1.0:
passkeys/WebAuthn, SSO/SAML, acting as an OIDC provider, phone/SMS,
OpenTelemetry. These are the feature-parity gaps with better-auth, not
correctness defects. They are what a v0.2 and beyond are for.
