// Module for the SQL adapter's real-database integration tests.
//
// It lives outside the core module on purpose: the core library must
// stay dependency-free, but proving the adapter against an actual
// database needs a driver. Nothing here is imported by the library.
module github.com/go-dev-auth/go-dev-auth/storage/sqlstore/integration

go 1.24.0

// The Postgres and MySQL drivers are pinned to their newest
// zero-dependency releases (mysql v1.8.0 grew a curve25519 dependency
// for MariaDB's auth plugin, which nothing here uses). Test-only module
// or not, a shallow dependency tree is this project's habit.
require (
	github.com/go-dev-auth/go-dev-auth v0.1.0
	github.com/go-sql-driver/mysql v1.7.1
	github.com/lib/pq v1.10.9
	github.com/mattn/go-sqlite3 v1.14.24
)

// Test the adapter against the core library in the same checkout.
replace github.com/go-dev-auth/go-dev-auth => ../../..
