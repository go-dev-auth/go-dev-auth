// Package twofactor adds TOTP, email OTP and backup-code based second
// factor authentication, mirroring better-auth's two-factor plugin.
//
// When a user with 2FA enabled signs in with email/password, the sign-in
// response is intercepted and returns {"twoFactorRedirect": true}. The
// client must then call one of the /two-factor/verify-* endpoints to
// complete authentication.
package twofactor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/ratelimit"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ModelTwoFactor is the table storing 2FA secrets.
const ModelTwoFactor = "twoFactor"

// Field names in ModelTwoFactor that hold encrypted values. They are
// part of the AEAD binding, so they are named once here rather than
// spelled out at each call site.
const (
	fieldSecret      = "secret"
	fieldBackupCodes = "backupCodes"
)

// binding names where an encrypted 2FA value lives. Every ciphertext
// this plugin writes is sealed against it, so a value lifted from
// another row, another column or another table does not open here —
// which is what stops an attacker with database write access from
// pasting a victim's OAuth token or the JWT signing key into their own
// twoFactor.secret and reading it back through /two-factor/get-totp-uri.
func binding(recordID, field string) crypto.Binding {
	return crypto.Binding{Model: ModelTwoFactor, Record: recordID, Field: field}
}

// Options configures the two-factor plugin.
type Options struct {
	// Issuer is the TOTP issuer shown in authenticator apps. Defaults
	// to the app name.
	Issuer string
	// TOTPPeriod defaults to 30 seconds.
	TOTPPeriod int
	// TOTPDigits defaults to 6.
	TOTPDigits int
	// Skew is the allowed clock drift in TOTP steps. Defaults to 1.
	Skew int
	// OTP configures email OTP delivery. When SendOTP is nil the email
	// OTP endpoints are disabled.
	SendOTP func(ctx context.Context, user *storage.User, otp string) error
	// OTPExpiresIn defaults to 5 minutes.
	OTPExpiresIn time.Duration
	// BackupCodeCount defaults to 10.
	BackupCodeCount int
	// SkipVerificationOnEnable enables 2FA immediately without
	// verifying a TOTP code first.
	SkipVerificationOnEnable bool
	// TrustDeviceDuration is how long a "trust this device" grant lets
	// the same browser skip the second factor. Zero disables the
	// feature, so the trustDevice request field is honoured only when a
	// duration is set. Defaults to 0 (off).
	TrustDeviceDuration time.Duration
}

// Plugin implements the two-factor plugin.
type Plugin struct {
	opts Options
	auth *godevauth.Auth
}

// New builds the plugin.
func New(opts ...Options) *Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.TOTPPeriod == 0 {
		o.TOTPPeriod = 30
	}
	if o.TOTPDigits == 0 {
		o.TOTPDigits = 6
	}
	if o.Skew == 0 {
		o.Skew = 1
	}
	if o.OTPExpiresIn == 0 {
		o.OTPExpiresIn = 5 * time.Minute
	}
	if o.BackupCodeCount == 0 {
		o.BackupCodeCount = 10
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "two-factor" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	if p.opts.Issuer == "" {
		p.opts.Issuer = a.Config().AppName
	}
	return nil
}

// Schema implements godevauth.SchemaPlugin.
func (p *Plugin) Schema(s *storage.Schema) {
	s.AddFields(storage.ModelUser,
		storage.Field{Name: "twoFactorEnabled", Type: storage.FieldBool, Default: false})
	s.AddTable(&storage.Table{Name: ModelTwoFactor, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "userId", Type: storage.FieldString, Required: true, Index: true,
			References: &storage.Reference{Model: storage.ModelUser, Field: "id", OnDelete: "cascade"}},
		{Name: "secret", Type: storage.FieldText, Required: true},
		{Name: "backupCodes", Type: storage.FieldText},
		// lastCounter is the TOTP time-step of the most recently
		// accepted code. A code whose counter is not strictly greater is
		// refused, so a code cannot be reused inside its skew window.
		{Name: "lastCounter", Type: storage.FieldInt, Default: 0},
	}})
}

// ReencryptSecrets implements godevauth.SecretRotator: it rewrites
// every stored TOTP secret and backup-code set under the current
// Config.Secret.
//
// This is the table that makes a careless rotation unrecoverable — a
// TOTP secret no key can read means the user must re-enrol from scratch
// — so it is the one that most needs a migration path.
func (p *Plugin) ReencryptSecrets(ctx context.Context) (godevauth.ReencryptResult, error) {
	return p.auth.ReencryptRecords(ctx, ModelTwoFactor, fieldSecret, fieldBackupCodes)
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route {
	// M9: code-verification endpoints are online guessing oracles (a
	// 6-digit TOTP survives ~90s) and send-otp emails on demand; all
	// carry the strict per-IP limit the core sign-in endpoints use.
	strict := &ratelimit.Rule{Window: 10 * time.Second, Max: 3}
	routes := []godevauth.Route{
		{Method: http.MethodPost, Path: "/two-factor/enable", Handler: p.handleEnable},
		{Method: http.MethodPost, Path: "/two-factor/disable", Handler: p.handleDisable},
		{Method: http.MethodPost, Path: "/two-factor/get-totp-uri", Handler: p.handleGetTOTPURI},
		{Method: http.MethodPost, Path: "/two-factor/verify-totp", Handler: p.handleVerifyTOTP, RateLimit: strict},
		{Method: http.MethodPost, Path: "/two-factor/generate-backup-codes", Handler: p.handleGenerateBackupCodes},
		{Method: http.MethodPost, Path: "/two-factor/verify-backup-code", Handler: p.handleVerifyBackupCode, RateLimit: strict},
	}
	if p.opts.SendOTP != nil {
		routes = append(routes,
			godevauth.Route{Method: http.MethodPost, Path: "/two-factor/send-otp", Handler: p.handleSendOTP, RateLimit: strict},
			godevauth.Route{Method: http.MethodPost, Path: "/two-factor/verify-otp", Handler: p.handleVerifyOTP, RateLimit: strict},
		)
	}
	return routes
}

// BeforeSignIn implements godevauth.SignInGuard: users with 2FA enabled
// get a pending-verification response instead of a session. Because the
// guard runs on every sign-in path (password, magic link, social,
// verification auto-login), the second factor cannot be skipped by
// choosing a different method.
func (p *Plugin) BeforeSignIn(c *godevauth.Ctx, user *storage.User) (bool, error) {
	raw, present := user.Extra["twoFactorEnabled"]
	if !present || raw == nil {
		return false, nil
	}
	enabled, ok := raw.(bool)
	if !ok {
		// Unreadable flag: require the second factor rather than skip
		// it. Failing the other way turns a storage anomaly into an
		// authentication bypass.
		enabled = true
	}
	if !enabled {
		return false, nil
	}
	// A trusted device skips the challenge entirely: the user proved a
	// second factor here before and asked to be remembered.
	if p.deviceTrusted(c, user.ID) {
		return false, nil
	}
	token, err := p.auth.StoreToken(c.Context(), tokenKindPending, user.ID, pendingTTL)
	if err != nil {
		return false, err
	}
	http.SetCookie(c.W, p.pendingCookie(token, pendingTTL))
	return true, c.JSON(http.StatusOK, map[string]any{"twoFactorRedirect": true})
}

const (
	tokenKindPending = "two-factor-pending"
	tokenKindOTP     = "two-factor-otp"
	// methodTwoFactor labels sign-ins completed by a second factor in
	// the audit trail.
	methodTwoFactor = "two-factor"
	pendingTTL      = 10 * time.Minute
	// maxVerifyAttempts caps guesses against one pending challenge, so
	// a 6-digit code cannot be brute-forced within its lifetime.
	maxVerifyAttempts = 5
)

// ---- trusted devices ----

const (
	trustDeviceCookieName = "two_factor_trust"
	trustDevicePurpose    = "two-factor-trust-device"
)

func (p *Plugin) trustCookieName() string {
	return p.auth.Config().Advanced.CookiePrefix + "." + trustDeviceCookieName
}

// setTrustedDevice records, in a signed cookie on this browser, that the
// user completed a second factor and asked to be trusted. The cookie
// carries the user id and an absolute expiry, both covered by the
// signature, so it cannot be edited to name another user or extended.
func (p *Plugin) setTrustedDevice(c *godevauth.Ctx, userID string) {
	if p.opts.TrustDeviceDuration <= 0 {
		return
	}
	exp := time.Now().Add(p.opts.TrustDeviceDuration).Unix()
	payload := userID + "|" + strconv.FormatInt(exp, 10)
	value := payload + "|" + crypto.SignHMACPurpose(p.auth.Config().Secret, trustDevicePurpose, payload)
	http.SetCookie(c.W, &http.Cookie{
		Name:     p.trustCookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(p.auth.Config().BaseURL, "https://"),
		MaxAge:   int(p.opts.TrustDeviceDuration / time.Second),
	})
}

// deviceTrusted reports whether this browser holds a valid, unexpired
// trust grant for userID.
func (p *Plugin) deviceTrusted(c *godevauth.Ctx, userID string) bool {
	if p.opts.TrustDeviceDuration <= 0 {
		return false
	}
	cookie, err := c.R.Cookie(p.trustCookieName())
	if err != nil || cookie.Value == "" {
		return false
	}
	id, rest, ok := strings.Cut(cookie.Value, "|")
	if !ok {
		return false
	}
	expStr, sig, ok := strings.Cut(rest, "|")
	if !ok {
		return false
	}
	payload := id + "|" + expStr
	if !crypto.VerifyHMACPurpose(p.auth.Config().Secret, trustDevicePurpose, payload, sig) {
		return false
	}
	if id != userID {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	return true
}

const pendingCookieName = "two_factor_pending"

func (p *Plugin) pendingCookieName() string {
	return p.auth.Config().Advanced.CookiePrefix + "." + pendingCookieName
}

func (p *Plugin) pendingCookie(value string, ttl time.Duration) *http.Cookie {
	c := &http.Cookie{
		Name:     p.pendingCookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(p.auth.Config().BaseURL, "https://"),
	}
	if ttl > 0 {
		c.MaxAge = int(ttl / time.Second)
	} else {
		c.MaxAge = -1
	}
	return c
}

// pendingChallenge is an in-flight second-factor challenge.
type pendingChallenge struct {
	user     *storage.User
	token    string
	attempts int
}

// pendingUser resolves the user for a pending 2FA verification.
func (p *Plugin) pendingUser(c *godevauth.Ctx) (*pendingChallenge, error) {
	cookie, err := c.R.Cookie(p.pendingCookieName())
	if err != nil || cookie.Value == "" {
		return nil, godevauth.ErrUnauthorized
	}
	v, err := p.auth.LookupToken(c.Context(), tokenKindPending, cookie.Value)
	if err != nil {
		return nil, godevauth.ErrUnauthorized
	}
	userID, attempts := parsePendingValue(v.Value)
	user, err := p.auth.FindUserByID(c.Context(), userID)
	if err != nil {
		return nil, godevauth.ErrUnauthorized
	}
	return &pendingChallenge{user: user, token: cookie.Value, attempts: attempts}, nil
}

func parsePendingValue(value string) (userID string, attempts int) {
	id, rest, ok := strings.Cut(value, "|")
	if !ok {
		return value, 0
	}
	n, _ := strconv.Atoi(rest)
	return id, n
}

// failAttempt records a wrong guess and discards the challenge once the
// attempt budget is exhausted, so the code space cannot be searched
// within the challenge's lifetime.
func (p *Plugin) failAttempt(c *godevauth.Ctx, ch *pendingChallenge) error {
	ctx := c.Context()
	// Claim this attempt by consuming the challenge token first: the
	// delete is atomic, so racing wrong guesses serialise here instead
	// of each reading the same count and all writing count+1 — which
	// let more than maxVerifyAttempts guesses through on a real
	// database. The loser of the race sees the token already gone and
	// is refused without advancing the count on its behalf.
	value, err := p.auth.ConsumeToken(ctx, tokenKindPending, ch.token)
	if err != nil {
		return godevauth.ErrUnauthorized
	}
	_, attempts := parsePendingValue(value)
	if attempts+1 >= maxVerifyAttempts {
		http.SetCookie(c.W, p.pendingCookie("", -1))
		p.auth.EmitEvent(c, godevauth.Event{
			Type: godevauth.EventTwoFactorVerified, Outcome: godevauth.OutcomeFailure,
			Reason: godevauth.ReasonTooManyAttempts, ActorID: ch.user.ID, Email: ch.user.Email,
		})
		return godevauth.NewAPIError(http.StatusUnauthorized, "TOO_MANY_ATTEMPTS",
			"Too many incorrect codes. Sign in again.")
	}
	// The submitted code is never recorded: a rejected 6-digit code is
	// still a guess at a live credential.
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventTwoFactorVerified, Outcome: godevauth.OutcomeFailure,
		Reason: godevauth.ReasonInvalidTwoFactor, ActorID: ch.user.ID, Email: ch.user.Email,
	})
	// Reinstate the challenge with the advanced count so the next guess
	// against the same cookie continues from here.
	_ = p.auth.StoreTokenValue(ctx, tokenKindPending, ch.token,
		ch.user.ID+"|"+strconv.Itoa(attempts+1), pendingTTL)
	return godevauth.NewAPIError(http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE",
		"Invalid two factor code")
}

// completePending issues the session after successful verification.
func (p *Plugin) completePending(c *godevauth.Ctx, ch *pendingChallenge, trustDevice bool) error {
	// Consume the challenge first: if two requests race, only the one
	// that removes the token proceeds.
	if _, err := p.auth.ConsumeToken(c.Context(), tokenKindPending, ch.token); err != nil {
		return godevauth.ErrUnauthorized
	}
	http.SetCookie(c.W, p.pendingCookie("", -1))
	c.SetAuthMethod(methodTwoFactor)
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventTwoFactorVerified, ActorID: ch.user.ID,
		Email: ch.user.Email, Method: methodTwoFactor,
	})
	// Hand off to any sign-in guards ordered after this plugin, rather
	// than minting the session directly and skipping them. With 2FA the
	// only guard this is a no-op; with a further guard registered after
	// it (another challenge, a device check), that guard now runs.
	if handled, err := p.auth.RunSignInGuardsAfter(c, ch.user, p.ID()); err != nil {
		return err
	} else if handled {
		return nil
	}
	if trustDevice {
		p.setTrustedDevice(c, ch.user.ID)
	}
	sess, err := p.auth.CreateSessionFor(c, ch.user, true)
	if err != nil {
		return err
	}
	// The sign-in only completes here: the earlier sign_in.challenged
	// event was the first factor. Without this the trail would show
	// challenges with no resolution.
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventSignIn, ActorID: ch.user.ID, Email: ch.user.Email,
		SessionID: sess.ID, Method: methodTwoFactor,
	})
	return c.JSON(http.StatusOK, map[string]any{"token": sess.Token, "user": ch.user})
}

// record loads the twoFactor row for a user.
func (p *Plugin) record(ctx context.Context, userID string) (map[string]any, error) {
	return p.auth.Storage().FindOne(ctx, ModelTwoFactor, []storage.Where{storage.W("userId", userID)})
}

// claimCounter advances the stored lastCounter to counter, but only if
// counter is strictly greater than what is stored — a compare-and-set
// so two requests presenting the same code cannot both win. It returns
// false when the code is a replay (not newer) or when another request
// claimed the same step first.
func (p *Plugin) claimCounter(ctx context.Context, rec map[string]any, counter int64) bool {
	last := recordInt(rec["lastCounter"])
	if counter <= last {
		return false
	}
	n, err := p.auth.Storage().UpdateMany(ctx, ModelTwoFactor,
		[]storage.Where{storage.W("id", rec["id"]), storage.W("lastCounter", last)},
		map[string]any{"lastCounter": counter})
	return err == nil && n == 1
}

func recordInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}

// twoFactorActive reports whether the user currently has 2FA enabled.
func (p *Plugin) twoFactorActive(u *storage.User) bool {
	enabled, _ := u.Extra["twoFactorEnabled"].(bool)
	return enabled
}

// verifyExistingFactor checks code against the user's current TOTP
// secret or an unused backup code, without consuming a backup code —
// this only proves possession before a re-enrolment.
func (p *Plugin) verifyExistingFactor(ctx context.Context, userID, code string) bool {
	if code == "" {
		return false
	}
	rec, err := p.record(ctx, userID)
	if err != nil {
		return false
	}
	if secret, err := p.decryptSecret(rec); err == nil {
		if crypto.VerifyTOTP(secret, code, time.Now(), p.opts.TOTPPeriod, p.opts.TOTPDigits, p.opts.Skew) {
			return true
		}
	}
	enc, _ := rec["backupCodes"].(string)
	id, _ := rec["id"].(string)
	if codes, err := p.decryptBackupCodes(id, enc); err == nil {
		want := strings.TrimSpace(strings.ToLower(code))
		for _, bc := range codes {
			if crypto.ConstantTimeEqual(bc, want) {
				return true
			}
		}
	}
	return false
}

func (p *Plugin) verifyPassword(c *godevauth.Ctx, userID, password string) error {
	if password == "" {
		return godevauth.ErrInvalidPassword
	}
	acc, err := p.auth.FindCredentialAccountByUser(c.Context(), userID)
	if err != nil {
		return godevauth.ErrCredentialAccountNotFound
	}
	ok, err := p.auth.Config().EmailAndPassword.PasswordHasher.Verify(acc.Password, password)
	if err != nil || !ok {
		return godevauth.ErrInvalidPassword
	}
	return nil
}

type passwordBody struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (p *Plugin) handleEnable(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body passwordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.verifyPassword(c, sd.User.ID, body.Password); err != nil {
		return err
	}
	ctx := c.Context()
	// L9: if 2FA is already active, re-enrolling replaces the secret and
	// backup codes, which silently locks out the user's authenticator
	// and revokes their codes. Requiring a current code (or an unused
	// backup code) proves the caller controls the existing factor, not
	// just the password and a live cookie.
	if p.twoFactorActive(sd.User) {
		if !p.verifyExistingFactor(ctx, sd.User.ID, body.Code) {
			return godevauth.NewAPIError(http.StatusUnauthorized, "CURRENT_CODE_REQUIRED",
				"Enter a current code from your authenticator to change your two-factor setup")
		}
	}
	// The row id is generated first, not by the insert: both values are
	// sealed against it, so it has to be known before they are
	// encrypted.
	recordID := crypto.GenerateID(32)
	secret := crypto.GenerateTOTPSecret()
	encSecret, err := p.auth.Keyring().Encrypt(binding(recordID, fieldSecret), secret)
	if err != nil {
		return err
	}
	backupCodes := p.generateBackupCodes()
	encCodes, err := p.encryptBackupCodes(recordID, backupCodes)
	if err != nil {
		return err
	}
	totpURI, err := crypto.TOTPURI(p.opts.Issuer, sd.User.Email, secret, p.opts.TOTPPeriod, p.opts.TOTPDigits)
	if err != nil {
		return err
	}
	// replace any previous record
	_, _ = p.auth.Storage().DeleteMany(ctx, ModelTwoFactor, []storage.Where{storage.W("userId", sd.User.ID)})
	if _, err := p.auth.Storage().Create(ctx, ModelTwoFactor, map[string]any{
		"id":          recordID,
		"userId":      sd.User.ID,
		"secret":      encSecret,
		"backupCodes": encCodes,
		// Stored explicitly so the replay compare-and-set has a value to
		// match on every adapter, not just those that apply defaults.
		"lastCounter": int64(0),
	}); err != nil {
		return err
	}
	if p.opts.SkipVerificationOnEnable {
		if _, err := p.auth.UpdateUserRecord(ctx, sd.User.ID, map[string]any{"twoFactorEnabled": true}); err != nil {
			return err
		}
		p.auth.EmitEvent(c, godevauth.Event{
			Type: godevauth.EventTwoFactorEnabled, ActorID: sd.User.ID,
			Email: sd.User.Email, SessionID: sd.Session.ID,
		})
	}
	// The TOTP secret and the backup codes are in the response body but
	// never in the event: they are the credential.
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventTwoFactorBackupCodesGenerated, ActorID: sd.User.ID,
		Email: sd.User.Email, SessionID: sd.Session.ID, Action: "enrol",
	})
	return c.JSON(http.StatusOK, map[string]any{
		"totpURI":     totpURI,
		"backupCodes": backupCodes,
	})
}

func (p *Plugin) handleDisable(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body passwordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.verifyPassword(c, sd.User.ID, body.Password); err != nil {
		return err
	}
	ctx := c.Context()
	if _, err := p.auth.Storage().DeleteMany(ctx, ModelTwoFactor, []storage.Where{storage.W("userId", sd.User.ID)}); err != nil {
		return err
	}
	if _, err := p.auth.UpdateUserRecord(ctx, sd.User.ID, map[string]any{"twoFactorEnabled": false}); err != nil {
		return err
	}
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventTwoFactorDisabled, ActorID: sd.User.ID,
		Email: sd.User.Email, SessionID: sd.Session.ID,
	})
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleGetTOTPURI(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body passwordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.verifyPassword(c, sd.User.ID, body.Password); err != nil {
		return err
	}
	rec, err := p.record(c.Context(), sd.User.ID)
	if err != nil {
		return godevauth.NewAPIError(http.StatusBadRequest, "TWO_FACTOR_NOT_ENABLED", "Two factor is not enabled")
	}
	secret, err := p.decryptSecret(rec)
	if err != nil {
		return err
	}
	// Second gate on the echo. decryptSecret has already rejected
	// anything that is not a TOTP secret, so reaching this error means
	// the two checks disagree — fail rather than emit the value.
	totpURI, err := crypto.TOTPURI(p.opts.Issuer, sd.User.Email, secret, p.opts.TOTPPeriod, p.opts.TOTPDigits)
	if err != nil {
		p.auth.Logger().Error("two-factor: refusing to build a TOTP URI from a stored value that is not a TOTP secret",
			"userId", sd.User.ID, "err", err)
		return errStoredSecretUnreadable
	}
	return c.JSON(http.StatusOK, map[string]any{
		"totpURI": totpURI,
	})
}

// decryptSecret reads a stored TOTP secret.
//
// It goes through the instance keyring, so a secret written under a
// previous Config.Secret is still readable while
// Config.PreviousSecrets lists it. When no configured key can read it,
// the error says so in terms an operator can act on: the alternative —
// treating it as a bad code — locks the user out of their own account
// with no explanation anywhere.
func (p *Plugin) decryptSecret(rec map[string]any) (string, error) {
	enc, _ := rec["secret"].(string)
	id, _ := rec["id"].(string)
	userID, _ := rec["userId"].(string)
	secret, err := p.auth.Keyring().Decrypt(binding(id, fieldSecret), enc)
	if err != nil {
		p.auth.Logger().Error("two-factor: stored TOTP secret cannot be decrypted with any configured secret; "+
			"if Config.Secret was rotated, add the previous one to Config.PreviousSecrets and run Auth.ReencryptSecrets",
			"id", id, "userId", userID, "err", err)
		return "", errStoredSecretUnreadable
	}
	// A value that decrypts is not automatically a TOTP secret: the
	// pre-binding formats (v0, v1) are still accepted on read unless
	// Config.RequireBoundCiphertexts is set, so a value relocated from
	// another column before the migration could still open here.
	// Refuse it rather than hand it to TOTPURI or HOTP.
	if err := crypto.ValidateTOTPSecret(secret); err != nil {
		p.auth.Logger().Error("two-factor: stored TOTP secret is not a valid base32 secret; "+
			"the row may have been tampered with",
			"id", id, "userId", userID, "err", err)
		return "", errStoredSecretUnreadable
	}
	return secret, nil
}

// errStoredSecretUnreadable is returned when a stored 2FA secret cannot
// be decrypted. It is a 500 because it is a server-side configuration
// fault, not a wrong code.
var errStoredSecretUnreadable = godevauth.NewAPIError(http.StatusInternalServerError,
	"TWO_FACTOR_SECRET_UNREADABLE",
	"The stored two-factor secret could not be decrypted. Contact support.")

type verifyBody struct {
	Code        string `json:"code"`
	TrustDevice bool   `json:"trustDevice"`
}

func (p *Plugin) handleVerifyTOTP(c *godevauth.Ctx) error {
	var body verifyBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	// two contexts: completing a pending sign-in, or verifying to
	// finish enabling 2FA for the current session.
	if ch, err := p.pendingUser(c); err == nil {
		rec, err := p.record(c.Context(), ch.user.ID)
		if err != nil {
			return godevauth.ErrUnauthorized
		}
		secret, err := p.decryptSecret(rec)
		if err != nil {
			return err
		}
		counter, ok := crypto.VerifyTOTPCounter(secret, body.Code, time.Now(), p.opts.TOTPPeriod, p.opts.TOTPDigits, p.opts.Skew)
		if !ok {
			return p.failAttempt(c, ch)
		}
		// M5: a code whose time-step is not newer than the last accepted
		// one is a replay (a shoulder-surfed code stays valid ~90s
		// otherwise). Claim the counter with a compare-and-set; losing
		// the race counts as a replay too.
		if !p.claimCounter(c.Context(), rec, counter) {
			return p.failAttempt(c, ch)
		}
		return p.completePending(c, ch, body.TrustDevice)
	}

	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	rec, err := p.record(c.Context(), sd.User.ID)
	if err != nil {
		return godevauth.NewAPIError(http.StatusBadRequest, "TWO_FACTOR_NOT_ENABLED", "Two factor is not enabled")
	}
	secret, err := p.decryptSecret(rec)
	if err != nil {
		return err
	}
	if !crypto.VerifyTOTP(secret, body.Code, time.Now(), p.opts.TOTPPeriod, p.opts.TOTPDigits, p.opts.Skew) {
		return godevauth.NewAPIError(http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE", "Invalid two factor code")
	}
	if _, err := p.auth.UpdateUserRecord(c.Context(), sd.User.ID, map[string]any{"twoFactorEnabled": true}); err != nil {
		return err
	}
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventTwoFactorEnabled, ActorID: sd.User.ID,
		Email: sd.User.Email, SessionID: sd.Session.ID,
	})
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleSendOTP(c *godevauth.Ctx) error {
	var user *storage.User
	if ch, err := p.pendingUser(c); err == nil {
		user = ch.user
	} else {
		sd, serr := c.RequireSession()
		if serr != nil {
			// Report why the session lookup failed, not why the pending
			// challenge lookup did. They are both Unauthorized today,
			// so this is latent, but a storage failure here would
			// otherwise be reported as bad credentials.
			return serr
		}
		user = sd.User
	}
	otp := crypto.GenerateOTP(6)
	// stored as a digest so database read access does not yield a
	// usable one-time code
	if err := p.auth.StoreTokenValue(c.Context(), tokenKindOTP, user.ID,
		crypto.HashToken(otp), p.opts.OTPExpiresIn); err != nil {
		return err
	}
	if err := p.opts.SendOTP(c.Context(), user, otp); err != nil {
		return godevauth.NewAPIError(http.StatusInternalServerError, "FAILED_TO_SEND_OTP", "Failed to send OTP")
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleVerifyOTP(c *godevauth.Ctx) error {
	var body verifyBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	ch, err := p.pendingUser(c)
	if err != nil {
		return err
	}
	verification, err := p.auth.LookupToken(c.Context(), tokenKindOTP, ch.user.ID)
	if err != nil {
		return godevauth.NewAPIError(http.StatusUnauthorized, "INVALID_OTP", "Invalid OTP")
	}
	if !crypto.ConstantTimeEqual(verification.Value, crypto.HashToken(body.Code)) {
		return p.failAttempt(c, ch)
	}
	_ = p.auth.DeleteVerificationValue(c.Context(), verification.ID)
	return p.completePending(c, ch, body.TrustDevice)
}

func (p *Plugin) generateBackupCodes() []string {
	codes := make([]string, p.opts.BackupCodeCount)
	for i := range codes {
		codes[i] = strings.ToLower(crypto.GenerateID(5) + "-" + crypto.GenerateID(5))
	}
	return codes
}

func (p *Plugin) encryptBackupCodes(recordID string, codes []string) (string, error) {
	raw, err := json.Marshal(codes)
	if err != nil {
		return "", err
	}
	return p.auth.Keyring().Encrypt(binding(recordID, fieldBackupCodes), string(raw))
}

func (p *Plugin) decryptBackupCodes(recordID, enc string) ([]string, error) {
	raw, err := p.auth.Keyring().Decrypt(binding(recordID, fieldBackupCodes), enc)
	if err != nil {
		p.auth.Logger().Error("two-factor: stored backup codes cannot be decrypted with any configured secret",
			"id", recordID, "err", err)
		return nil, errStoredSecretUnreadable
	}
	var codes []string
	if err := json.Unmarshal([]byte(raw), &codes); err != nil {
		return nil, err
	}
	return codes, nil
}

func (p *Plugin) handleGenerateBackupCodes(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body passwordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.verifyPassword(c, sd.User.ID, body.Password); err != nil {
		return err
	}
	rec, err := p.record(c.Context(), sd.User.ID)
	if err != nil {
		return godevauth.NewAPIError(http.StatusBadRequest, "TWO_FACTOR_NOT_ENABLED", "Two factor is not enabled")
	}
	id, _ := rec["id"].(string)
	codes := p.generateBackupCodes()
	encCodes, err := p.encryptBackupCodes(id, codes)
	if err != nil {
		return err
	}
	if _, err := p.auth.Storage().Update(c.Context(), ModelTwoFactor,
		[]storage.Where{storage.W("id", id)}, map[string]any{"backupCodes": encCodes}); err != nil {
		return err
	}
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventTwoFactorBackupCodesGenerated, ActorID: sd.User.ID,
		Email: sd.User.Email, SessionID: sd.Session.ID, Action: "regenerate",
	})
	return c.JSON(http.StatusOK, map[string]any{"backupCodes": codes})
}

func (p *Plugin) handleVerifyBackupCode(c *godevauth.Ctx) error {
	var body verifyBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	ch, err := p.pendingUser(c)
	if err != nil {
		return err
	}
	ctx := c.Context()
	rec, err := p.record(ctx, ch.user.ID)
	if err != nil {
		return godevauth.ErrUnauthorized
	}
	enc, _ := rec["backupCodes"].(string)
	id, _ := rec["id"].(string)
	codes, err := p.decryptBackupCodes(id, enc)
	if err != nil {
		return err
	}
	idx := -1
	for i, code := range codes {
		if crypto.ConstantTimeEqual(code, strings.TrimSpace(strings.ToLower(body.Code))) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return p.failAttempt(c, ch)
	}
	// Consume the code with a compare-and-set on the stored ciphertext:
	// if a concurrent request already rewrote the list, this update
	// matches nothing and the caller retries rather than spending the
	// same code twice.
	remaining := append(append([]string{}, codes[:idx]...), codes[idx+1:]...)
	encCodes, err := p.encryptBackupCodes(id, remaining)
	if err != nil {
		return err
	}
	n, err := p.auth.Storage().UpdateMany(ctx, ModelTwoFactor,
		[]storage.Where{storage.W("id", id), storage.W("backupCodes", enc)},
		map[string]any{"backupCodes": encCodes})
	if err != nil {
		return err
	}
	if n == 0 {
		return godevauth.NewAPIError(http.StatusConflict, "RETRY",
			"Backup codes changed concurrently, please try again")
	}
	return p.completePending(c, ch, body.TrustDevice)
}

var _ godevauth.SignInGuard = (*Plugin)(nil)
var _ godevauth.SchemaPlugin = (*Plugin)(nil)
var _ godevauth.SecretRotator = (*Plugin)(nil)
var _ = errors.Is
