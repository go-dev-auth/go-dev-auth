# Writing a plugin

Most features belong in a plugin rather than the core. A plugin is an
ordinary Go package that adds routes, database tables and behaviour to
an `Auth` instance, and it can live in your own repository.

## The minimum

Three methods:

```go
package hello

import (
	"net/http"

	godevauth "github.com/go-dev-auth/go-dev-auth"
)

type Plugin struct{ auth *godevauth.Auth }

func New() *Plugin { return &Plugin{} }

func (p *Plugin) ID() string { return "hello" }

func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil // return an error to refuse an invalid configuration
}

func (p *Plugin) Routes() []godevauth.Route {
	return []godevauth.Route{{
		Method: http.MethodGet, Path: "/hello",
		Handler: func(c *godevauth.Ctx) error {
			sd, err := c.RequireSession()
			if err != nil {
				return err
			}
			return c.JSON(http.StatusOK, map[string]any{"hello": sd.User.Name})
		},
	}}
}
```

Register it with `Config.Plugins`. Routes are mounted under
`Config.BasePath`, so `/hello` is served at `/api/auth/hello`.

## Optional interfaces

Implement only what you need. Each is checked with a type assertion, so
adding one is never a breaking change.

| Interface | Method | Use it to |
|---|---|---|
| `SchemaPlugin` | `Schema(*storage.Schema)` | add tables, or columns to existing tables |
| `MiddlewarePlugin` | `Middleware(http.Handler) http.Handler` | wrap the whole handler |
| `HookPlugin` | `BeforeRequest`/`AfterRequest(*Ctx) error` | observe or short-circuit every request |
| `SignInGuard` | `BeforeSignIn(*Ctx, *storage.User) (bool, error)` | challenge or veto a sign-in |
| `SessionGuard` | `CheckSession(context.Context, *SessionData) error` | reject a session on every request |

`SignInGuard` runs on **every** sign-in path — password, magic link,
social, verification auto-login — so a second factor or a ban cannot be
bypassed by choosing a different method. `SessionGuard` runs on every
request, including API-key authenticated ones.

`Schema` may add columns to tables the core owns (`s.AddFields("user",
...)`), not only whole tables of your own. Those land on databases that
already exist, so a column you add must be usable when it is NULL: the
rows that predate your plugin have no value for it, and the migration
adds it nullable whatever `Required` says. Give it a `Default` and read
it defensively rather than assuming it is set.

## Conventions

Follow these so plugins feel like one library:

- **Constructor:** `New(opts ...Options) *Plugin`, with an `Options`
  struct. Variadic keeps the zero-configuration case a bare `New()`.
  Validate required options in `Init` and return an error there, not by
  panicking or by making the argument mandatory.
- **Defaults** are applied in `New`, so `Options{}` is always usable.
- **Model names** are exported constants: `const ModelThing = "thing"`.
- **Errors** come from a package-level catalogue (see below), not from
  `NewAPIError` calls scattered through handlers.
- **Storage access** goes through `p.auth.Storage()`, and every write is
  scoped to the caller's user or organisation.

## Errors

Declare the codes your plugin can return in one place:

```go
var (
	ErrNotEnabled = godevauth.NewAPIError(http.StatusBadRequest,
		"HELLO_NOT_ENABLED", "Hello is not enabled")
)
```

A catalogue means clients can rely on a stable set of codes, and the
next contributor can see which ones already exist instead of inventing a
near-duplicate.

## Testing

Use `plugintest` to get an `Auth` instance with your plugin mounted and
an HTTP client that carries cookies:

```go
func TestHello(t *testing.T) {
	env := plugintest.New(t, New())
	env.SignUp("a@example.com", "password123")

	res, body := env.GET("/hello")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if body["hello"] == nil {
		t.Fatal("no greeting")
	}
}
```

Test the failure paths too: no session, another user's session, and a
malformed body. Those are where authorization bugs live.

## Security expectations

If your plugin touches authentication or authorization, state in the
pull request what an attacker could do if the change were wrong. In
particular:

- Never read a field that decides access with a bare type assertion:
  `v, ok := x.(bool); if !ok { deny }`. Failing open on a wrong type has
  been a real bug in this codebase.
- Anything derived from a request body must not reach a storage field
  that grants privileges. Only fields declared with
  `storage.Field{Input: true}` are client-writable, and plugin-owned
  columns never are.
- One-time values must be consumed atomically — use
  `auth.ConsumeToken`, which claims by delete.
