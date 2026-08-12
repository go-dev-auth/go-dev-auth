# Contributing

## Getting set up

The repository is three Go modules: the core library,
`storage/mongostore`, and `storage/sqlstore/integration`. Link them with
a workspace:

```
go work init . ./storage/mongostore ./storage/sqlstore/integration
make test
```

`go.work` is developer-local and not committed.

## Before opening a pull request

```
make check      # formatting, vet, lint, tests, race detector
```

The SQLite integration tests need cgo (`CGO_ENABLED=1`). The Postgres,
MySQL and MongoDB suites skip themselves unless the matching DSN
environment variables are set; CI provides them.

## Expectations for changes

- **A bug fix comes with a test that fails without it.** For security
  fixes the test should reproduce the attack, not just cover the line.
- **New storage adapters must pass `storage/storagetest.Run`.** The auth
  core depends on precise adapter semantics; the conformance suite is
  what stops backends from diverging.
- **Explain *why* in comments, not *what*.** The code says what it does.
  Comments should capture the reasoning a reader cannot recover — why a
  check exists, what breaks without it.
- **Anything touching authentication, sessions or tokens** should say in
  the PR description what an attacker could do if the change were wrong.

## Test coverage

Every package carries its own tests. Run `make cover` for the current
numbers. A pull request should not reduce coverage of the package it
touches, and new plugins should land with a test file from the start —
`plugins/plugintest` exists to make that cheap, and
`plugins/admin/admin_test.go` is a template worth copying.

The most valuable test in a plugin is the authorization sweep: call
every route anonymously and as a user who does not own the resource, and
assert the request is refused *and* changed nothing.

## Project layout

```
.                       the godevauth package: config, routing, handlers
.github/                CI, templates, and this file
storage/                persistence contract, models, schema
storage/{memory,sqlstore,mongostore}
storage/storagetest/    the adapter conformance suite
crypto/                 hashing, tokens, TOTP, JWT primitives
oauth2/                 OAuth 2.0 / OIDC client
providers/              ready-made provider configurations
plugins/<name>/         optional features, one package each
plugins/plugintest/     harness for testing a plugin
ratelimit/              rate limiter and its store interface
examples/basic/         a runnable server
docs/                   architecture map, plugin guide, reviews
```

**Read [docs/architecture.md](../docs/architecture.md) before your first
change.** It explains why the root directory is flat (Go requires one
directory per package), what each root file owns, and — the section you
probably want — *where does my change go?*
