# AGENTS.md

Instructions for AI coding agents working **on this repository**. If you
are instead *using* this library in someone else's project, read
[llms.txt](llms.txt) — it is shorter and aimed at that.

## What this is

An authentication library for Go. Auth code is different from ordinary
application code in one way that should change how you work here: a
subtle mistake does not produce a failing test, it produces a silent
vulnerability that ships. Several defences in this repository exist
because a specific attack was demonstrated against an earlier version.

## Non-negotiables

1. **Never weaken or remove a security check to make a test pass.** If a
   test fails after your change, the change is wrong until proven
   otherwise. This includes: authorization checks, ownership checks,
   attempt caps, origin checks, rate limits, and fail-closed error paths.
2. **Never introduce a dependency in the core module.** Zero external
   dependencies is the library's main differentiator. `go.mod` for the
   root module must stay at just the `go` directive. Drivers belong in
   the separate `storage/mongostore` and `storage/sqlstore/integration`
   modules.
3. **Never claim in documentation something the repository cannot
   demonstrate.** This repo previously shipped a security document
   describing 8 fuzz targets that did not exist. If you write "verified"
   or a measurement, the test producing it must be committed and
   re-runnable.
4. **Fail closed.** When an error path is ambiguous, the safe answer is
   to deny. A malformed quota, an unreadable key, a storage outage — all
   should refuse, not allow.
5. Keep the module's Go floor at **1.22**. `t.Context()` and other
   1.24+ APIs will compile locally and break CI.

## Build and test

```bash
export PATH=/path/to/go/bin:$PATH
GOWORK=off go build ./...
GOWORK=off go test ./...
GOWORK=off CGO_ENABLED=1 go test -race ./...
GOWORK=off go vet ./...
gofmt -l .            # must print nothing
make fuzz FUZZTIME=30s
```

`GOWORK=off` is needed because `go.work` references submodules whose
dependencies may be unreachable. All four must be clean before you
report done.

Real-database tests live in `storage/sqlstore/integration` (SQLite,
needs `CGO_ENABLED=1`). Run them for any change to `storage/`.

## Conventions

- **Comments explain *why*, not *what*.** This is enforced in review. A
  comment restating the code is noise; a comment explaining which attack
  a check prevents is the most valuable line in the file.
- **Every functional package has its own tests.** Adding a plugin
  without `plugins/<name>/<name>_test.go` will be rejected.
  `plugins/plugintest` makes this cheap; `plugins/admin/admin_test.go`
  is the template.
- **The most valuable plugin test is the authorization sweep**: call
  every route anonymously and as a user who does not own the resource,
  and assert it is refused *and changed nothing*.
- **New public routes must be added to the allowlist** in
  `plugins/plugintest/authsweep_test.go` with a written reason, or the
  sweep fails. This is deliberate: making a route public should be a
  reviewable act.
- **Storage adapters must pass `storage/storagetest`.** Backend
  divergence is a bug class this suite exists to prevent.
- Read [docs/architecture.md](docs/architecture.md) before adding a
  file — it says what each file owns and where new code belongs.

## Where things live

The root directory is flat because Go requires one directory per
package; those files *are* the `godevauth` package. See
[docs/architecture.md](docs/architecture.md) for the full map.

- `handler_*.go` — HTTP endpoints, one file per feature area.
- `router.go` — the `Route` type, the built-in route table, dispatch.
- `session.go`, `store.go`, `token.go` — domain logic.
- `origin.go` — CORS and CSRF (deliberately one file; they must share
  one trusted-origin list).
- `events.go` — the structured audit trail.
- `plugins/<name>/` — optional features, using the public API only.

## When you finish

State plainly what you ran and what actually executed, versus what you
could not verify. "Tests pass" is only useful if it says which tests.
