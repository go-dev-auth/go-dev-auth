package godevauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/ratelimit"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Migrator is implemented by adapters that can prepare their storage
// (create tables, indexes and constraints).
type Migrator interface {
	Migrate(ctx context.Context) error
}

// SchemaChecker is implemented by adapters that can compare the live
// storage against the schema this instance expects and report what is
// missing. Set Advanced.VerifySchema to have New call it.
type SchemaChecker interface {
	CheckSchema(ctx context.Context) error
}

// Auth is a configured authentication instance.
type Auth struct {
	config  Config
	store   *store
	schema  *storage.Schema
	routes  []Route
	static  map[string]map[string]*Route // path -> method -> route
	dynamic []Route                      // routes with :params
	limiter *ratelimit.Limiter
	logger  *slog.Logger
	handler http.Handler

	// keyring encrypts and decrypts values held at rest. It holds the
	// current secret plus Config.PreviousSecrets, which is what makes
	// Config.Secret rotatable without destroying stored TOTP secrets,
	// signing keys and OAuth tokens.
	keyring *crypto.Keyring

	// trustedProxies is the compiled Advanced.TrustedProxies list.
	trustedProxies *trustedProxySet
	// proxyWarned keeps the misconfiguration warning to one line per
	// process rather than one per request.
	proxyWarned atomic.Bool

	// writableUserFields is the allowlist of user columns a client may
	// set through sign-up and update-user. Only fields declared in
	// Config.User.AdditionalFields with Input:true are eligible; fields
	// contributed by plugins (role, banned, twoFactorEnabled, ...) are
	// never client-writable, because they carry authorization meaning.
	writableUserFields map[string]bool

	// hasSessionGuards records whether any plugin can reject a session
	// per request. When one can, the signed cookie cache is bypassed so
	// authorization is never decided from a stale copy of the user.
	hasSessionGuards bool

	// cookieCacheUserFields is the allowlist of additional user columns
	// that may be written into the (signed, unencrypted) session cache
	// cookie. Core columns are always included; everything else needs
	// Session.CookieCache.UserFields to name it.
	cookieCacheUserFields map[string]bool
	// cookieCacheWarned keeps the oversized-payload complaint to one
	// line per process rather than one per response.
	cookieCacheWarned atomic.Bool
}

// New validates the configuration and builds an Auth instance.
func New(config Config) (*Auth, error) {
	config.withDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	a := &Auth{
		config: config,
		logger: config.Logger,
		schema: storage.CoreSchema(),
	}
	a.store = &store{auth: a, base: config.Database}
	a.limiter = ratelimit.NewLimiter(config.RateLimit.Storage)
	a.keyring = crypto.NewKeyringFrom(crypto.KeyringOptions{
		Current:       config.Secret,
		Previous:      config.PreviousSecrets,
		RejectUnbound: config.RequireBoundCiphertexts,
	})
	proxies, err := parseTrustedProxies(config.Advanced.TrustedProxies)
	if err != nil {
		return nil, err
	}
	a.trustedProxies = proxies

	// extend schema with configured additional fields
	a.writableUserFields = map[string]bool{}
	if fields := config.User.AdditionalFields; len(fields) > 0 {
		core := storage.CoreSchema().Tables[storage.ModelUser]
		for _, f := range fields {
			// A core column (id, email, emailVerified, ...) declared as
			// an additional field would be silently ignored by the
			// schema but still land in the client-writable allowlist,
			// handing back the mass-assignment hole the allowlist
			// exists to close.
			if core.FieldByName(f.Name) != nil {
				return nil, fmt.Errorf("go-dev-auth: User.AdditionalFields may not redeclare the core field %q", f.Name)
			}
		}
		a.schema.AddFields(storage.ModelUser, fields...)
		for _, f := range fields {
			if f.Input {
				a.writableUserFields[f.Name] = true
			}
		}
	}
	if fields := config.Session.AdditionalFields; len(fields) > 0 {
		a.schema.AddFields(storage.ModelSession, fields...)
	}

	// core routes
	a.routes = a.coreRoutes()

	// plugins: schema, init, routes
	seen := map[string]bool{}
	for _, p := range config.Plugins {
		if p == nil {
			continue
		}
		if seen[p.ID()] {
			return nil, errors.New("go-dev-auth: duplicate plugin " + p.ID())
		}
		seen[p.ID()] = true
		if sp, ok := p.(SchemaPlugin); ok {
			sp.Schema(a.schema)
		}
	}
	for _, p := range config.Plugins {
		if p == nil {
			continue
		}
		if err := p.Init(a); err != nil {
			return nil, err
		}
		a.routes = append(a.routes, p.Routes()...)
	}

	// The cookie-cache allowlist is resolved against the finished schema
	// (core + application + plugin columns), so a name that does not
	// exist is a startup error rather than a field that quietly never
	// appears in the cache.
	a.cookieCacheUserFields = map[string]bool{}
	if names := config.Session.CookieCache.UserFields; len(names) > 0 {
		userTable := a.schema.Tables[storage.ModelUser]
		for _, name := range names {
			if userTable == nil || userTable.FieldByName(name) == nil {
				return nil, fmt.Errorf("go-dev-auth: Session.CookieCache.UserFields names %q, "+
					"which is not a field on the user model", name)
			}
			a.cookieCacheUserFields[name] = true
		}
	}
	if config.Session.CookieCache.Enabled {
		var dropped []string
		for _, f := range config.User.AdditionalFields {
			if !a.cookieCacheUserFields[f.Name] {
				dropped = append(dropped, f.Name)
			}
		}
		if len(dropped) > 0 {
			// Not a warning: this is the safe default doing its job. It
			// is logged because the alternative is an author wondering
			// why User.Extra is half empty on a cache hit.
			a.logger.Info("go-dev-auth: these user fields are omitted from the session cookie cache "+
				"because the cookie is readable by the client; add them to "+
				"Session.CookieCache.UserFields if the request path needs them",
				"fields", strings.Join(dropped, ", "))
		}
	}

	// hand the complete schema to adapters that can use it for unique
	// constraints, defaults and indexes
	if aware, ok := config.Database.(storage.SchemaAware); ok {
		aware.SetSchema(a.schema)
	}
	// Create the indexes the schema implies. On MongoDB this is what
	// makes uniqueness real: collections are created lazily, so an
	// instance whose indexes were never built looks perfectly healthy
	// while every "does this email already exist" check degrades to a
	// race. Opt out with Advanced.DisableAutoMigrate when migrations
	// are owned by a separate deploy step.
	if m, ok := config.Database.(Migrator); ok && !config.Advanced.DisableAutoMigrate {
		if err := m.Migrate(context.Background()); err != nil {
			return nil, fmt.Errorf("go-dev-auth: preparing the database: %w", err)
		}
	}
	// Fail startup on schema drift rather than at the first query. This
	// is opt-in, not automatic: New has no database context of its own,
	// an adapter may legitimately be constructed without a live handle
	// (the DDL-generator use), and a check that reads the catalogue is
	// not something every process should be forced to pay for or be
	// allowed to do. Turn it on wherever migrations are owned by a
	// separate deploy step — see Advanced.VerifySchema.
	if config.Advanced.VerifySchema {
		c, ok := config.Database.(SchemaChecker)
		if !ok {
			return nil, errors.New("go-dev-auth: Advanced.VerifySchema is set but the storage adapter cannot check its schema")
		}
		if err := c.CheckSchema(context.Background()); err != nil {
			return nil, fmt.Errorf("go-dev-auth: verifying the database schema: %w", err)
		}
	}

	for _, p := range config.Plugins {
		if _, ok := p.(SessionGuard); ok {
			a.hasSessionGuards = true
			break
		}
	}
	if a.hasSessionGuards && config.Session.CookieCache.Enabled &&
		!config.Session.CookieCache.AcceptStaleAuthorization {
		a.logger.Info("go-dev-auth: session cookie cache bypassed because a plugin registers a SessionGuard (e.g. ban checks); " +
			"set Session.CookieCache.AcceptStaleAuthorization to trade revocation latency for the saved queries")
	}

	a.buildRouteIndex()

	// assemble handler with plugin middleware
	var h http.Handler = http.HandlerFunc(a.serveHTTP)
	for i := len(config.Plugins) - 1; i >= 0; i-- {
		if mp, ok := config.Plugins[i].(MiddlewarePlugin); ok {
			h = mp.Middleware(h)
		}
	}
	a.handler = h
	return a, nil
}

// Config returns a snapshot of the effective configuration, with
// defaults applied.
//
// The returned pointer addresses a copy. Writing through it does not
// change the running instance, and that is the point: a.config is read
// without synchronisation on every request — Secret on every cookie
// signature, TrustedOrigins and DisableCSRFCheck on every state-changing
// call — so a write from any other goroutine was a data race on the
// values that decide whether a request is authentic. Handing out
// &a.config made that race a one-liner, and plugins reach config through
// this method dozens of times.
//
// Configuration is therefore immutable after New. Anything that must
// vary at runtime belongs behind a function field in Config (the
// SendXxx hooks, the rate-limit storage) rather than in a field somebody
// reassigns. Code that needs the final BaseURL before the server is
// listening — test harnesses, mostly — should obtain the address first
// (httptest.NewUnstartedServer(nil).Listener.Addr()) and pass it to New,
// not patch it afterwards.
//
// Slices, maps and interface values inside the snapshot still point at
// the originals; do not mutate what they reference either.
func (a *Auth) Config() *Config {
	snapshot := a.config
	return &snapshot
}

// Storage returns the storage adapter backing this instance. Plugins
// use it to read and write their own models.
func (a *Auth) Storage() storage.Adapter { return a.config.Database }

// Schema returns the full database schema including plugin extensions.
func (a *Auth) Schema() *storage.Schema { return a.schema }

// Logger returns the configured logger.
func (a *Auth) Logger() *slog.Logger { return a.logger }

// Keyring returns the encryption keyring for values held at rest: the
// current secret plus any Config.PreviousSecrets.
//
// Plugins that store encrypted data must use it rather than
// crypto.EncryptString(auth.Config().Secret, ...), which knows only one
// key and therefore cannot read anything written before a rotation.
func (a *Auth) Keyring() *crypto.Keyring { return a.keyring }

// Routes returns every registered endpoint (core plus plugins), useful
// for generating documentation or asserting on the exposed surface.
func (a *Auth) Routes() []Route {
	out := make([]Route, len(a.routes))
	copy(out, a.routes)
	return out
}

// Handler returns the http.Handler serving all auth endpoints. Mount it
// at Config.BasePath with a trailing slash match:
//
//	mux.Handle("/api/auth/", auth.Handler())
func (a *Auth) Handler() http.Handler { return a.handler }

// SocialProvider returns the provider with the given id: a configured
// one, or one contributed by a ProviderSourcePlugin (tenant SSO).
// Configured providers win, so a dynamic source can never shadow one.
func (a *Auth) SocialProvider(id string) oauth2.Provider {
	for _, p := range a.config.SocialProviders {
		if p.ID() == id {
			return p
		}
	}
	for _, pl := range a.config.Plugins {
		if src, ok := pl.(ProviderSourcePlugin); ok {
			if p := src.SocialProvider(id); p != nil {
				return p
			}
		}
	}
	return nil
}
