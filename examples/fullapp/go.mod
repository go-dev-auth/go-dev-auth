// Runnable example: a complete small web application — server-rendered
// pages, persistent SQLite storage, registration, sign-in, a protected
// dashboard, password reset and session management.
//
// A separate module so the SQLite driver stays out of the library.
// Run from this directory (the driver needs cgo): go run .
module github.com/go-dev-auth/go-dev-auth/examples/fullapp

go 1.22

require (
	github.com/go-dev-auth/go-dev-auth v0.1.0
	github.com/mattn/go-sqlite3 v1.14.24
)

replace github.com/go-dev-auth/go-dev-auth => ../..
