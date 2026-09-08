package godevauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/ratelimit"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Config configures an Auth instance. Only Secret and Database are
// strictly required; everything else has sensible defaults.
type Config struct {
	// AppName is used as issuer for TOTP URIs and in default emails.
	AppName string
	// BaseURL is the externally visible origin of the server,
	// e.g. "https://example.com".
	BaseURL string
	// BasePath is the path the handler is mounted at.
	// Defaults to "/api/auth".
	BasePath string
	// Secret signs cookies and tokens, and derives the key that
	// encrypts values held at rest (TOTP secrets, backup codes, JWT
	// signing keys, OAuth tokens). Required in production.
	//
	// Use at least 32 characters of random data, e.g.
	// `openssl rand -base64 32`.
	Secret string
	// PreviousSecrets are secrets this instance used before Secret was
	// rotated. They are never used to encrypt or sign anything new;
	// they exist so that values written under an earlier secret stay
	// readable while they are migrated.
	//
	// The rotation procedure is:
	//
	//  1. Deploy with the new secret as Secret and the old one as the
	//     only entry in PreviousSecrets. Everything keeps working;
	//     new writes use the new key.
	//  2. Run Auth.ReencryptSecrets to rewrite stored values under the
	//     new key.
	//  3. Deploy again with PreviousSecrets empty.
	//
	// Skipping step 1 locks every 2FA user out permanently and makes
	// stored JWT signing keys and OAuth tokens unreadable, so the
	// library refuses to guess: a value it cannot decrypt is an error,
	// never a silent fallback. See ReencryptSecrets.
	//
	// Note that cookie and token *signatures* are not versioned:
	// rotating Secret invalidates existing signed cookies (users are
	// signed out) regardless of PreviousSecrets.
	PreviousSecrets []string
	// RequireBoundCiphertexts refuses to read any value at rest that
	// was written before ciphertexts were bound to their storage
	// location — the crypto package's v0 and v1 formats.
	//
	// Bound values (v2) authenticate the model, record id and field
	// name they were written to, so a ciphertext copied from one column
	// into another does not open. Unbound values do not: anyone who can
	// write to the database can move one to a column whose contents are
	// returned in an API response and read the plaintext back. Keeping
	// them readable is therefore a downgrade path, and this is the
	// switch that closes it.
	//
	// It is off by default because turning it on before a deployment
	// has migrated makes those values unreadable. The sequence is:
	//
	//  1. Upgrade. New writes are bound; old values still read.
	//  2. Run Auth.ReencryptSecrets until a pass reports Done.
	//  3. Deploy with RequireBoundCiphertexts set.
	//
	// Nothing is lost by turning it on too early — clearing it makes
	// the values readable again — but users whose 2FA secret has not
	// been migrated cannot sign in while it is set.
	RequireBoundCiphertexts bool
	// Database is the storage adapter. Required.
	Database storage.Adapter

	// EmailAndPassword configures the email/password authenticator.
	EmailAndPassword EmailPasswordConfig
	// EmailVerification configures verification email delivery.
	EmailVerification EmailVerificationConfig
	// SocialProviders lists the enabled OAuth providers.
	SocialProviders []oauth2.Provider
	// DisableSocialSignUp rejects social sign-ins that would create a
	// new user, so only pre-provisioned accounts can sign in.
	DisableSocialSignUp bool

	// Plugins extends the instance with additional functionality.
	Plugins []Plugin

	// Session configures session lifetime and cookie caching.
	Session SessionConfig
	// User configures user model behaviour.
	User UserConfig
	// Account configures account linking behaviour.
	Account AccountConfig
	// Advanced holds low level toggles.
	Advanced AdvancedConfig

	// TrustedOrigins are origins allowed to make state-changing
	// requests. BaseURL is always trusted.
	TrustedOrigins []string

	// RateLimit configures built-in rate limiting.
	RateLimit RateLimitConfig

	// Events configures the structured authentication audit trail.
	Events EventsConfig

	// Hooks run before and after every request handled by the router.
	Hooks Hooks

	// DatabaseHooks intercept core model writes.
	DatabaseHooks DatabaseHooks

	// Logger receives diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// EmailPasswordConfig mirrors better-auth's emailAndPassword options.
type EmailPasswordConfig struct {
	Enabled                  bool
	DisableSignUp            bool
	RequireEmailVerification bool
	MinPasswordLength        int // default 8
	MaxPasswordLength        int // default 128
	// AutoSignIn signs the user in right after sign up.
	// Default true; set DisableAutoSignIn to turn off.
	DisableAutoSignIn bool
	// SendResetPassword delivers password reset emails.
	SendResetPassword func(ctx context.Context, user *storage.User, url, token string) error
	// ResetPasswordURL is your application's "choose a new password"
	// page. The emailed link points at this library, which validates
	// the token and then redirects here with ?token=... appended.
	//
	// Set this whenever SendResetPassword is set. Without it the
	// emailed link only works if the caller passed "redirectTo" on
	// every /forget-password request, and a user who follows the link
	// lands on the generic error page — an advertised flow that fails
	// on first use. New refuses to start on that combination rather
	// than letting it fail silently in front of a locked-out user.
	//
	// Prefer a path — "/choose-password" — which is resolved against
	// BaseURL. An absolute URL also works but must be same-origin with
	// BaseURL or listed in TrustedOrigins, because the redirect carries
	// the reset token and an open redirect here would hand that token
	// to whoever asked for it. A URL that fails that check sends the
	// user to the error page, so the path form is the safer default.
	ResetPasswordURL string
	// OnPasswordReset runs after a password was reset.
	OnPasswordReset func(ctx context.Context, user *storage.User) error
	// ResetPasswordTokenExpiresIn defaults to 1 hour.
	ResetPasswordTokenExpiresIn time.Duration
	// KeepSessionsOnPasswordReset disables the default behaviour of
	// revoking every existing session when a password is reset.
	// Resetting a password is the standard account-recovery action
	// after a compromise, so leaving an attacker's session alive
	// defeats the purpose; only set this if you have a specific reason.
	KeepSessionsOnPasswordReset bool
	// KeepSessionsOnPasswordChange disables the default behaviour of
	// revoking a user's other sessions when they change their password
	// from an authenticated session. The current session is always
	// kept.
	KeepSessionsOnPasswordChange bool
	// PasswordHasher overrides the default scrypt hasher.
	PasswordHasher crypto.PasswordHasher
}

// EmailVerificationConfig mirrors better-auth's emailVerification options.
type EmailVerificationConfig struct {
	// SendVerificationEmail delivers the verification email. Email
	// verification endpoints are enabled when this is set.
	SendVerificationEmail func(ctx context.Context, user *storage.User, url, token string) error
	// SendOnSignUp sends a verification email on sign up.
	SendOnSignUp bool
	// SendOnSignIn sends a verification email on sign in when the email
	// is not verified yet.
	SendOnSignIn bool
	// AutoSignInAfterVerification creates a session after verification.
	AutoSignInAfterVerification bool
	// ExpiresIn defaults to 1 hour.
	ExpiresIn time.Duration
	// OnEmailVerification runs after an email is verified.
	OnEmailVerification func(ctx context.Context, user *storage.User) error
	// ConfirmationPage makes GET /verify-email render an interstitial
	// confirmation page instead of verifying immediately; the token is
	// consumed only when the user submits the form (a POST). Turn it on
	// to stop mail-security scanners and link prefetchers — which fire
	// GETs — from consuming the one-time token before the user clicks.
	// It is off by default because it adds a click and existing
	// integrations link straight to the GET endpoint.
	ConfirmationPage bool
}

// SessionConfig mirrors better-auth's session options.
type SessionConfig struct {
	// ExpiresIn is the session time to live. Default 7 days.
	ExpiresIn time.Duration
	// UpdateAge controls how often the expiry is refreshed. Default 1
	// day.
	UpdateAge time.Duration
	// FreshAge is the window in which a session counts as fresh.
	// Default 1 day. Sensitive operations (e.g. delete user) require a
	// fresh session.
	FreshAge time.Duration
	// DisableSessionRefresh disables sliding expiration.
	DisableSessionRefresh bool
	// CookieCache short-circuits session lookups by caching the session
	// payload in a signed cookie.
	CookieCache CookieCacheConfig
	// AdditionalFields are extra session fields plugins/apps may set.
	AdditionalFields []storage.Field
}

// CookieCacheConfig configures the signed session cookie cache.
//
// The cache is the single biggest lever on database cost: a cache hit
// serves an authenticated request with zero queries instead of two (the
// session, then its user). The price is staleness — a revoked session
// or a newly banned user keeps working until the cached copy expires.
//
// # What the cookie contains, and who can read it
//
// The payload is signed, not encrypted. Anyone holding the cookie can
// base64-decode it and read every value in it: the user themselves,
// anything with access to their disk or browser profile, an intercepting
// proxy terminating TLS, and every log or crash report that captured the
// request headers. Treat everything in it as published to the account
// holder.
//
// That is why the user record is reduced to its core columns —
// id, name, email, emailVerified, image, createdAt, updatedAt — and
// every additional field is dropped unless it is named in UserFields.
// Session.AdditionalFields are *not* filtered, because the library and
// its plugins depend on them (impersonatedBy is what
// /admin/stop-impersonating reads); do not put anything in a session
// field you would not put in a JWT.
type CookieCacheConfig struct {
	Enabled bool
	// MaxAge defaults to 5 minutes. It is also the worst-case delay
	// before a revocation takes effect.
	MaxAge time.Duration
	// UserFields names the additional user columns — those declared in
	// User.AdditionalFields or contributed by a plugin — that may travel
	// in the cache cookie. The core columns are always included;
	// everything else is dropped by default, so enabling the cache
	// cannot quietly start shipping a column somebody added later.
	//
	// Two reasons to add a name here, and one reason not to:
	//
	//   - a plugin needs the column on a cache hit (the admin plugin
	//     reads "role"; without it a real admin looks like an ordinary
	//     user while the cache is warm — it fails closed, but it fails);
	//   - your own code reads User.Extra[...] on the request path.
	//
	// The reason not to is that the value becomes readable by whoever
	// holds the cookie. Names that must never appear here: government
	// identifiers, dates of birth, postal addresses, phone numbers,
	// internal risk or fraud scores, entitlement flags you would not
	// show the user, and anything else you would not print in the page.
	// New validates the names against the schema, so a typo is a startup
	// error rather than a silently missing field.
	UserFields []string
	// AcceptStaleAuthorization re-enables the cache even when a plugin
	// registers a SessionGuard (the admin plugin's ban check is one).
	//
	// By default the cache is bypassed in that situation, because a
	// guard evaluated against a cached user inspects fields that predate
	// the ban and waves the request through while appearing to check.
	// Setting this trades that correctness for the query saving: bans
	// and forced logouts then take up to MaxAge to take effect. Keep
	// MaxAge short if you set it.
	AcceptStaleAuthorization bool
}

// UserConfig mirrors better-auth's user options.
type UserConfig struct {
	// AdditionalFields are extra columns on the user model.
	AdditionalFields []storage.Field
	// ChangeEmail configures the change-email flow.
	ChangeEmail ChangeEmailConfig
	// DeleteUser configures the delete-user flow.
	DeleteUser DeleteUserConfig
}

// ChangeEmailVerification carries everything the change-email approval
// callback needs. SendTo is called out explicitly because getting it
// wrong is a takeover: the approval link must go to the current,
// already-verified address (SendTo), never to NewEmail. Emailing the
// link to NewEmail would let anyone holding a stolen session relocate
// the account to an address they control.
type ChangeEmailVerification struct {
	// User is the account whose address is changing.
	User *storage.User
	// SendTo is the address the approval link MUST be delivered to: the
	// current, verified address. It is always equal to User.Email.
	SendTo string
	// NewEmail is the address the user asked to switch to. Show it to
	// the user for context; it is NOT where the link goes.
	NewEmail string
	// URL is the approval link, and Token the raw token inside it.
	URL   string
	Token string
}

// ChangeEmailConfig controls the change email flow.
type ChangeEmailConfig struct {
	Enabled bool
	// SendChangeEmailVerification delivers the approval link for a
	// change of a verified address. Send req.URL to req.SendTo (the
	// current, verified address) — see ChangeEmailVerification.
	SendChangeEmailVerification func(ctx context.Context, req ChangeEmailVerification) error
}

// DeleteUserConfig controls user deletion.
type DeleteUserConfig struct {
	Enabled bool
	// SendDeleteAccountVerification is called to confirm deletion via
	// email. When unset, deletion happens immediately (password or
	// fresh session required).
	SendDeleteAccountVerification func(ctx context.Context, user *storage.User, url, token string) error
	// BeforeDelete runs before the user is deleted.
	BeforeDelete func(ctx context.Context, user *storage.User) error
	// AfterDelete runs after the user is deleted.
	AfterDelete func(ctx context.Context, user *storage.User) error
	// DeleteTokenExpiresIn defaults to 1 day.
	DeleteTokenExpiresIn time.Duration
}

// AccountConfig mirrors better-auth's account options.
type AccountConfig struct {
	AccountLinking AccountLinkingConfig
	// EncryptOAuthTokens encrypts access/refresh tokens at rest using
	// the instance secret.
	EncryptOAuthTokens bool
}

// AccountLinkingConfig controls automatic account linking.
type AccountLinkingConfig struct {
	// Disabled turns off account linking entirely.
	Disabled bool
	// TrustedProviders are providers whose verified emails may be
	// linked automatically to an existing user with the same email.
	TrustedProviders []string
	// AllowDifferentEmails permits linking accounts whose email differs
	// from the user's email (explicit linking flow only).
	AllowDifferentEmails bool
	// AllowUnlinkingAll permits unlinking the last account.
	AllowUnlinkingAll bool
}

// AdvancedConfig mirrors better-auth's advanced options.
type AdvancedConfig struct {
	// CookiePrefix defaults to "go-dev-auth".
	CookiePrefix string
	// UseSecureCookies forces the Secure attribute. Defaults to true
	// when BaseURL is https.
	UseSecureCookies bool
	// CrossSubDomainCookies sets the cookie Domain attribute so cookies
	// are shared across subdomains.
	CrossSubDomainCookies CrossSubDomainCookiesConfig
	// SameSite is "lax" (default), "strict" or "none".
	SameSite string
	// DisableCSRFCheck disables origin checking. Dangerous.
	DisableCSRFCheck bool
	// TrustProxyHeaders resolves the client IP from forwarded headers
	// (X-Forwarded-For, X-Real-IP) instead of the TCP peer address.
	//
	// It requires TrustedProxies. A forwarded header is client-supplied
	// data: honouring it from an arbitrary peer lets every client pick
	// its own rate-limit bucket and its own recorded session IP, which
	// is worse than not honouring it at all. New refuses to start if
	// this is set without TrustedProxies.
	TrustProxyHeaders bool
	// TrustedProxies lists the reverse proxies allowed to set the
	// forwarded headers, as IP addresses or CIDR blocks
	// ("10.0.0.0/8", "192.0.2.7", "::1/128").
	//
	// The peer address must be in this list before any forwarded header
	// is read, and the header chain is then walked from right to left
	// skipping trusted hops, so a client cannot prepend a fake address
	// to X-Forwarded-For.
	//
	// The single entry "*" trusts any peer. That is the behaviour this
	// option replaced; it is only safe when something else guarantees
	// the service is unreachable except through a proxy that overwrites
	// the header.
	TrustedProxies []string
	// IPAddressHeaders overrides the headers used to resolve client
	// IPs, e.g. []string{"CF-Connecting-IP"}. It implies
	// TrustProxyHeaders and therefore also requires TrustedProxies.
	IPAddressHeaders []string
	// GenerateID overrides ID generation for database records.
	GenerateID func(model string) string
	// DisableIDTokenNonceCheck restores the pre-fix native ID-token
	// sign-in that required no server-minted nonce. With it set, a
	// leaked or stolen provider ID token for this client is a working
	// sign-in credential until it expires — leave this off and have
	// clients fetch a nonce from /id-token/nonce instead; it exists
	// only to stage migrations of existing native apps.
	DisableIDTokenNonceCheck bool
	// DisableOriginCheckForPaths lists paths exempt from CSRF checks.
	DisableOriginCheckForPaths []string
	// DisableAutoMigrate stops New from creating tables and indexes,
	// and from adding the columns plugins contribute to existing
	// tables, when the adapter supports it. Set it when schema changes
	// are applied by a separate migration step — but make sure the
	// unique indexes exist, because the uniqueness of emails and
	// session tokens depends on them, and consider pairing it with
	// VerifySchema so a missed migration fails at startup.
	DisableAutoMigrate bool
	// VerifySchema makes New compare the live storage against the
	// schema (core plus plugins) and refuse to start when a table or
	// column is missing, naming what is absent. Without it the first
	// query is what fails, with a driver-level error, inside a sign-in.
	//
	// It is worth setting whenever DisableAutoMigrate is, or wherever
	// the application's database role has no DDL rights. New returns an
	// error if the adapter does not implement SchemaChecker.
	VerifySchema bool
}

// CrossSubDomainCookiesConfig enables cross subdomain cookies.
type CrossSubDomainCookiesConfig struct {
	Enabled bool
	Domain  string
}

// RateLimitConfig configures the built-in rate limiter.
//
// Rate limiting is ON by default. Password verification is deliberately
// expensive (tens of milliseconds and ~32 MiB of scratch memory per
// attempt), so an unthrottled sign-in endpoint is both a credential
// brute-force target and a cheap denial-of-service amplifier.
type RateLimitConfig struct {
	// Disabled turns off rate limiting entirely. Only do this when a
	// gateway or proxy in front of the service already throttles the
	// auth endpoints.
	Disabled bool
	// Window defaults to 10s, Max to 100 requests per window per IP.
	Window time.Duration
	Max    int
	// CustomRules maps request paths (relative to BasePath) to rules.
	CustomRules map[string]ratelimit.Rule
	// Storage overrides the in-memory limiter store. Use a shared store
	// (e.g. Redis) when running more than one instance; the default
	// in-memory store only limits per process.
	Storage ratelimit.Store
	// FailOpen allows requests through when the limiter's store errors.
	// The default is to fail closed, so a store outage cannot silently
	// disable brute-force protection.
	FailOpen bool
}

// Hooks are request-level middleware hooks.
type Hooks struct {
	// Before runs before the matched handler. Returning an error aborts
	// the request. Writing to the response also aborts the request.
	Before []func(c *Ctx) error
	// After runs after the handler completed.
	After []func(c *Ctx) error
}

// DatabaseHooks intercept core model lifecycle events.
type DatabaseHooks struct {
	User    ModelHooks
	Session ModelHooks
	Account ModelHooks
}

// ModelHooks hold before/after create and update callbacks. The before
// callbacks may mutate the record.
type ModelHooks struct {
	BeforeCreate func(ctx context.Context, record map[string]any) error
	AfterCreate  func(ctx context.Context, record map[string]any) error
	BeforeUpdate func(ctx context.Context, update map[string]any) error
	AfterUpdate  func(ctx context.Context, record map[string]any) error
}

func (c *Config) withDefaults() {
	if c.BasePath == "" {
		c.BasePath = "/api/auth"
	}
	if c.AppName == "" {
		c.AppName = "go-dev-auth"
	}
	if c.EmailAndPassword.MinPasswordLength == 0 {
		c.EmailAndPassword.MinPasswordLength = 8
	}
	if c.EmailAndPassword.MaxPasswordLength == 0 {
		c.EmailAndPassword.MaxPasswordLength = 128
	}
	if c.EmailAndPassword.ResetPasswordTokenExpiresIn == 0 {
		c.EmailAndPassword.ResetPasswordTokenExpiresIn = time.Hour
	}
	if c.EmailAndPassword.PasswordHasher == nil {
		c.EmailAndPassword.PasswordHasher = crypto.NewScryptHasher(crypto.DefaultScryptParams())
	}
	if c.EmailVerification.ExpiresIn == 0 {
		c.EmailVerification.ExpiresIn = time.Hour
	}
	if c.Session.ExpiresIn == 0 {
		c.Session.ExpiresIn = 7 * 24 * time.Hour
	}
	if c.Session.UpdateAge == 0 {
		c.Session.UpdateAge = 24 * time.Hour
	}
	if c.Session.FreshAge == 0 {
		c.Session.FreshAge = 24 * time.Hour
	}
	if c.Session.CookieCache.MaxAge == 0 {
		c.Session.CookieCache.MaxAge = 5 * time.Minute
	}
	if c.User.DeleteUser.DeleteTokenExpiresIn == 0 {
		c.User.DeleteUser.DeleteTokenExpiresIn = 24 * time.Hour
	}
	if c.Advanced.CookiePrefix == "" {
		c.Advanced.CookiePrefix = "go-dev-auth"
	}
	if c.Advanced.SameSite == "" {
		c.Advanced.SameSite = "lax"
	}
	if c.RateLimit.Window == 0 {
		c.RateLimit.Window = 10 * time.Second
	}
	if c.RateLimit.Max == 0 {
		c.RateLimit.Max = 100
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// validate rejects configurations that would be insecure or
// non-functional at runtime, so mistakes surface at startup rather than
// as a subtle production incident.
func (c *Config) validate() error {
	if c.Database == nil {
		return errors.New("go-dev-auth: Config.Database is required")
	}
	if c.Secret == "" {
		return errors.New("go-dev-auth: Config.Secret is required (use 32+ random bytes, e.g. `openssl rand -base64 32`)")
	}
	if len(c.Secret) < 16 {
		return errors.New("go-dev-auth: Config.Secret is too short; use at least 16 characters of random data")
	}
	if len(c.Secret) < 32 {
		// Not fatal: 16 characters of genuine randomness is 96 bits,
		// which is fine, and raising the floor would lock out running
		// deployments. But the secret is also the input to the
		// at-rest encryption key, and a short secret is usually a
		// memorable one rather than a random one.
		c.Logger.Warn("go-dev-auth: Config.Secret is shorter than 32 characters; " +
			"prefer 32+ random bytes (`openssl rand -base64 32`)")
	}
	for i, prev := range c.PreviousSecrets {
		if prev == "" {
			return fmt.Errorf("go-dev-auth: Config.PreviousSecrets[%d] is empty", i)
		}
		if prev == c.Secret {
			return fmt.Errorf("go-dev-auth: Config.PreviousSecrets[%d] is the same as Config.Secret; "+
				"a previous secret is the one being rotated away from", i)
		}
	}
	if c.EmailAndPassword.SendResetPassword != nil && c.EmailAndPassword.ResetPasswordURL == "" {
		// The emailed link points at this library, which validates the
		// token and then has to send the user somewhere to type a new
		// password. With nowhere to send them the link dead-ends on the
		// error page — the reset flow is advertised but broken on first
		// use. That is worth refusing to start over, because the person
		// who discovers it is a locked-out user, not the operator.
		return errors.New("go-dev-auth: Config.EmailAndPassword.ResetPasswordURL is required " +
			"when SendResetPassword is set — it is the page the emailed link sends the user to " +
			"(the library appends ?token=...). Without it the reset link cannot work.")
	}
	if c.BaseURL == "" {
		return errors.New("go-dev-auth: Config.BaseURL is required (it determines cookie security, trusted origins and redirect targets)")
	}
	// A trailing slash would produce "//api/auth/..." in every OAuth
	// redirect_uri and verification link, which providers reject and
	// which breaks link matching.
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("go-dev-auth: Config.BaseURL %q is not an absolute URL", c.BaseURL)
	}
	if !strings.HasPrefix(c.BasePath, "/") {
		return fmt.Errorf("go-dev-auth: Config.BasePath %q must start with '/'", c.BasePath)
	}
	secure := c.Advanced.UseSecureCookies || u.Scheme == "https"
	if strings.EqualFold(c.Advanced.SameSite, "none") && !secure {
		return errors.New("go-dev-auth: SameSite=none requires secure cookies; browsers reject SameSite=None without Secure (use an https BaseURL or set Advanced.UseSecureCookies)")
	}
	if c.Advanced.DisableCSRFCheck {
		c.Logger.Warn("go-dev-auth: CSRF origin checking is disabled")
	}
	if err := c.validateProxyTrust(); err != nil {
		return err
	}
	return nil
}

// validateProxyTrust rejects the two proxy configurations that quietly
// break client-IP resolution, and therefore rate limiting.
//
// Trusting forwarded headers from any peer is the dangerous one: every
// client picks its own bucket and the per-IP limit stops limiting
// anything. The opposite mistake — running behind a load balancer with
// no proxy configuration at all, so every client shares the proxy's
// bucket — cannot be detected here, because it depends on the traffic;
// the router reports it the first time a forwarded header shows up.
func (c *Config) validateProxyTrust() error {
	usesHeaders := c.Advanced.TrustProxyHeaders || len(c.Advanced.IPAddressHeaders) > 0
	if !usesHeaders {
		if len(c.Advanced.TrustedProxies) > 0 {
			return errors.New("go-dev-auth: Advanced.TrustedProxies is set but neither " +
				"Advanced.TrustProxyHeaders nor Advanced.IPAddressHeaders is; forwarded " +
				"headers would be ignored and the list would do nothing")
		}
		return nil
	}
	if len(c.Advanced.TrustedProxies) == 0 {
		return errors.New("go-dev-auth: Advanced.TrustProxyHeaders (or IPAddressHeaders) is set " +
			"without Advanced.TrustedProxies; forwarded headers are client-supplied, so trusting " +
			"them from any peer lets every client choose its own rate-limit bucket. List your " +
			`proxy's addresses or CIDRs, or set TrustedProxies to []string{"*"} to accept that risk`)
	}
	if _, err := parseTrustedProxies(c.Advanced.TrustedProxies); err != nil {
		return err
	}
	return nil
}

// trustedProxySet is the compiled form of Advanced.TrustedProxies.
type trustedProxySet struct {
	all  bool
	nets []*net.IPNet
}

// parseTrustedProxies compiles the configured proxy list. Bare
// addresses become single-host networks so matching has one code path.
func parseTrustedProxies(entries []string) (*trustedProxySet, error) {
	set := &trustedProxySet{}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "*" {
			set.all = true
			continue
		}
		if strings.Contains(entry, "/") {
			_, n, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("go-dev-auth: Advanced.TrustedProxies entry %q is not a valid CIDR: %w", raw, err)
			}
			set.nets = append(set.nets, n)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("go-dev-auth: Advanced.TrustedProxies entry %q is not a valid IP address or CIDR", raw)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		set.nets = append(set.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return set, nil
}

// contains reports whether ip is one of the configured proxies.
func (s *trustedProxySet) contains(ip net.IP) bool {
	if s == nil {
		return false
	}
	// "*" trusts every peer, including one with no parseable address: a
	// front proxy connected over a unix socket has an empty RemoteAddr,
	// and requiring the wildcard to still refuse it made proxy trust
	// dead behind unix sockets. A specific CIDR list still cannot match
	// a nil IP.
	if s.all {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
