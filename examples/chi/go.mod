// Runnable example: go-dev-auth mounted inside a chi router.
//
// A separate module so the chi dependency stays out of the library.
// Run from this directory: go run .
module github.com/go-dev-auth/go-dev-auth/examples/chi

go 1.22

require (
	github.com/go-chi/chi/v5 v5.2.3
	github.com/go-dev-auth/go-dev-auth v0.1.0
)

replace github.com/go-dev-auth/go-dev-auth => ../..
