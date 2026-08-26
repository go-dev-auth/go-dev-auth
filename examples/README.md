# Examples

Three runnable servers, in increasing order of realism. Each is
self-contained; run it from its own directory.

| Example | What it shows | Run |
|---|---|---|
| [`basic`](basic) | Every plugin wired into a plain `net/http` mux, in-memory storage, emails logged to stdout. The fastest way to poke the whole API with curl. | `go run ./examples/basic` |
| [`chi`](chi) | Mounting the auth handler inside a [chi](https://github.com/go-chi/chi) router, and turning `auth.GetSession` into ordinary middleware. The pattern transfers to any router. | `cd examples/chi && go run .` |
| [`fullapp`](fullapp) | A complete small web app: server-rendered pages, registration, sign-in, protected dashboard, password reset end to end, persistent SQLite storage that survives restarts. | `cd examples/fullapp && go run .` (needs cgo) |

`basic` lives in the core module because it has no dependencies. `chi`
and `fullapp` are separate modules so their dependencies (the router,
the SQLite driver) never touch the library's own go.mod — the library
stays zero-dependency.

All three serve auth under `http://localhost:8080/api/auth`. Try:

```bash
curl -c jar -X POST localhost:8080/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"password123","name":"You"}'
curl -b jar localhost:8080/api/auth/get-session
```
