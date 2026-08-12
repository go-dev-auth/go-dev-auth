// Module for the SQL adapter's real-database integration tests.
//
// It lives outside the core module on purpose: the core library must
// stay dependency-free, but proving the adapter against an actual
// database needs a driver. Nothing here is imported by the library.
module github.com/go-dev-auth/go-dev-auth/storage/sqlstore/integration

go 1.22

require (
	github.com/go-dev-auth/go-dev-auth v0.1.0
	github.com/mattn/go-sqlite3 v1.14.49
)

// Test the adapter against the core library in the same checkout.
replace github.com/go-dev-auth/go-dev-auth => ../../..
