package godevauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ErrNoSession indicates the request carries no valid session.
var ErrNoSession = errors.New("go-dev-auth: no session")

// SignInGuard lets a plugin veto or take over a sign-in after the
// credential has been verified but before a session is created. It runs
// on every sign-in path (password, magic link, social, email
// verification auto-login), so a plugin implementing it cannot be
// bypassed by choosing a different sign-in method.
//
// Return handled=true after writing a response (e.g. a two-factor
// challenge); return an error to reject the sign-in outright.
type SignInGuard interface {
	BeforeSignIn(c *Ctx, user *storage.User) (handled bool, err error)
}

// SignInUser runs every registered sign-in guard and then issues a
// session. All sign-in flows funnel through it. handled=true means a
// guard wrote the response and no session was created.
func (a *Auth) SignInUser(c *Ctx, user *storage.User, rememberMe bool) (sess *storage.Session, handled bool, err error) {
	for _, p := range a.config.Plugins {
		guard, ok := p.(SignInGuard)
		if !ok {
			continue
		}
		done, err := guard.BeforeSignIn(c, user)
		if err != nil {
			// A guard rejecting a verified credential is the most
			// interesting sign-in outcome there is (a banned user
			// trying the door), and the client only sees a 403.
			a.EmitEvent(c, Event{
				Type:    EventSignIn,
				Outcome: OutcomeFailure,
				Reason:  eventReasonFor(err),
				ActorID: user.ID,
				Email:   user.Email,
				Method:  c.AuthMethod(),
			})
			return nil, false, err
		}
		if done {
			// The first factor passed; a second one is outstanding.
			a.EmitEvent(c, Event{
				Type:    EventSignInChallenged,
				Outcome: OutcomeChallenged,
				Reason:  ReasonTwoFactorRequired,
				ActorID: user.ID,
				Email:   user.Email,
				Method:  c.AuthMethod(),
			})
			return nil, true, nil
		}
	}
	sess, err = a.createSession(c, user, rememberMe, nil)
	if err != nil {
		return nil, false, err
	}
	a.EmitEvent(c, Event{
		Type:      EventSignIn,
		ActorID:   user.ID,
		Email:     user.Email,
		SessionID: sess.ID,
		Method:    c.AuthMethod(),
	})
	return sess, false, nil
}

// createSession creates a session for user and sets the session cookie.
func (a *Auth) createSession(c *Ctx, user *storage.User, rememberMe bool, extra map[string]any) (*storage.Session, error) {
	return a.createSessionWithDuration(c, user, rememberMe, extra, a.config.Session.ExpiresIn)
}

// RunSignInGuardsAfter runs the sign-in guards for plugins ordered
// after afterPluginID, so a plugin that took over a sign-in (a
// two-factor challenge) can hand control to any guards that would have
// run after it, instead of minting the session directly and skipping
// them. handled=true means a later guard wrote its own response (a
// chained factor), so the caller must not create a session.
//
// It deliberately runs only the guards *after* afterPluginID: re-running
// the whole chain would re-trigger the very guard that is completing.
func (a *Auth) RunSignInGuardsAfter(c *Ctx, user *storage.User, afterPluginID string) (handled bool, err error) {
	seen := false
	for _, p := range a.config.Plugins {
		if !seen {
			if p.ID() == afterPluginID {
				seen = true
			}
			continue
		}
		guard, ok := p.(SignInGuard)
		if !ok {
			continue
		}
		done, err := guard.BeforeSignIn(c, user)
		if err != nil {
			return false, err
		}
		if done {
			return true, nil
		}
	}
	return false, nil
}

func (a *Auth) createSessionWithDuration(c *Ctx, user *storage.User, rememberMe bool, extra map[string]any, duration time.Duration) (*storage.Session, error) {
	if duration <= 0 {
		duration = a.config.Session.ExpiresIn
	}
	sess := &storage.Session{
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(duration),
		IPAddress: c.ClientIP(),
		UserAgent: c.UserAgent(),
		Extra:     extra,
	}
	created, err := a.store.CreateSession(c.Context(), sess)
	if err != nil {
		return nil, err
	}
	a.setSessionCookie(c.W, created.Token, rememberMe)
	sd := &SessionData{Session: created, User: user}
	a.setCookieCache(c.W, sd)
	c.SetSession(sd)
	// Every session, however it was minted — sign-in, impersonation, a
	// plugin's own flow — leaves a record here. Sessions that appear
	// without a preceding sign_in event are exactly what an
	// investigation looks for.
	impersonator, _ := created.Extra["impersonatedBy"].(string)
	a.EmitEvent(c, Event{
		Type:      EventSessionCreated,
		ActorID:   impersonatorOr(impersonator, user.ID),
		TargetID:  impersonatorTarget(impersonator, user.ID),
		Email:     user.Email,
		SessionID: created.ID,
		Method:    c.AuthMethod(),
	})
	return created, nil
}

// impersonatorOr attributes a session to the administrator behind it
// when there is one.
func impersonatorOr(impersonator, userID string) string {
	if impersonator != "" {
		return impersonator
	}
	return userID
}

func impersonatorTarget(impersonator, userID string) string {
	if impersonator != "" {
		return userID
	}
	return ""
}

// CreateSessionWith creates a session with extra fields and a custom
// duration (0 uses the configured default), setting the session cookie.
// It bypasses sign-in guards; use SignInUser for user-initiated logins.
func (a *Auth) CreateSessionWith(c *Ctx, user *storage.User, rememberMe bool, extra map[string]any, duration time.Duration) (*storage.Session, error) {
	return a.createSessionWithDuration(c, user, rememberMe, extra, duration)
}

// UpdateSessionRecord applies an update to a session identified by its
// token.
func (a *Auth) UpdateSessionRecord(ctx context.Context, token string, update map[string]any) (*storage.Session, error) {
	return a.store.UpdateSession(ctx, token, update)
}

// GetSession resolves the session attached to the request, applying
// sliding expiration. It returns ErrNoSession when the request has no
// valid session.
func (a *Auth) GetSession(r *http.Request) (*SessionData, error) {
	token, ok := a.readSessionToken(r)
	if !ok {
		return nil, ErrNoSession
	}
	// The cookie cache is only consulted when no plugin can revoke
	// access per request. Running a guard against the cached copy would
	// be worse than useless: the cached user predates the ban, so the
	// guard would inspect stale fields and wave the request through
	// while looking like it checked. Correctness wins over one saved
	// query; disable the guard plugin, or accept the lookup.
	if !a.hasSessionGuards || a.config.Session.CookieCache.AcceptStaleAuthorization {
		if sd := a.readCookieCache(r); sd != nil && sd.Session.Token == token {
			if sd.Session.ExpiresAt.After(time.Now()) {
				// Guards still run, on the understanding that the data
				// they see is at most CookieCache.MaxAge old.
				if a.hasSessionGuards {
					if err := a.runSessionGuards(r.Context(), sd); err != nil {
						return nil, err
					}
				}
				return sd, nil
			}
		}
	}
	return a.GetSessionFromToken(r.Context(), token)
}

// runSessionGuards applies every plugin SessionGuard to a resolved
// session.
func (a *Auth) runSessionGuards(ctx context.Context, sd *SessionData) error {
	for _, p := range a.config.Plugins {
		guard, ok := p.(SessionGuard)
		if !ok {
			continue
		}
		if err := guard.CheckSession(ctx, sd); err != nil {
			return err
		}
	}
	return nil
}

// GetSessionFromToken looks up a session by its raw token.
func (a *Auth) GetSessionFromToken(ctx context.Context, token string) (*SessionData, error) {
	sess, err := a.store.FindSessionByToken(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNoSession
		}
		return nil, err
	}
	now := time.Now()
	if !sess.ExpiresAt.After(now) {
		_ = a.store.DeleteSessionByToken(ctx, token)
		return nil, ErrNoSession
	}
	user, err := a.store.FindUserByID(ctx, sess.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNoSession
		}
		return nil, err
	}
	// sliding expiration
	//
	// Refresh is gated on the session's own lifetime, not just the
	// configured default. A session minted with a custom, shorter
	// duration (admin impersonation, a plugin's short-lived session) is
	// a deliberate security boundary: computing "overdue" as if it had
	// the default lifetime would extend a 1-hour session to the full
	// Session.ExpiresIn on its first lookup. Short-lived sessions are
	// therefore fixed-expiry and never refreshed.
	if !a.config.Session.DisableSessionRefresh && a.sessionRefreshable(sess) {
		updateAt := sess.ExpiresAt.Add(-a.config.Session.ExpiresIn).Add(a.config.Session.UpdateAge)
		if now.After(updateAt) {
			updated, err := a.store.UpdateSession(ctx, token, map[string]any{
				"expiresAt": now.UTC().Add(a.config.Session.ExpiresIn),
			})
			if err == nil && updated != nil {
				sess = updated
			}
		}
	}
	sd := &SessionData{Session: sess, User: user}
	// Session guards (e.g. the admin plugin's ban check) run on every
	// resolution, not just at sign-in, so revoking access takes effect
	// on the next request regardless of how the session was obtained.
	if err := a.runSessionGuards(ctx, sd); err != nil {
		return nil, err
	}
	return sd, nil
}

// sessionRefreshable reports whether sliding expiration applies to
// sess. Sessions created with a lifetime shorter than the configured
// Session.ExpiresIn keep their original expiry.
//
// After a refresh ExpiresAt is now+ExpiresIn, so a default-lifetime
// session keeps qualifying; a shorter one can never start.
func (a *Auth) sessionRefreshable(sess *storage.Session) bool {
	if sess.CreatedAt.IsZero() {
		return false
	}
	lifetime := sess.ExpiresAt.Sub(sess.CreatedAt)
	// CreatedAt is stamped by the storage adapter a moment after the
	// handler computed ExpiresAt, so an exactly-default session can come
	// out a few milliseconds short of ExpiresIn. One second of tolerance
	// absorbs that without letting a deliberately shorter session slide.
	return lifetime >= a.config.Session.ExpiresIn-time.Second
}

// CheckSessionGuards applies the registered session guards to a
// session resolved outside the cookie path (API keys, custom
// credentials), so those callers cannot become a way around a ban.
func (a *Auth) CheckSessionGuards(ctx context.Context, sd *SessionData) error {
	return a.runSessionGuards(ctx, sd)
}

// SessionGuard lets a plugin reject an otherwise valid session on every
// request (bans, forced logout, tenant suspension).
type SessionGuard interface {
	CheckSession(ctx context.Context, sd *SessionData) error
}

// IsFresh reports whether the session was created within the configured
// fresh age window.
func (a *Auth) IsFresh(sess *storage.Session) bool {
	if a.config.Session.FreshAge <= 0 {
		return true
	}
	return time.Since(sess.CreatedAt) < a.config.Session.FreshAge
}

// RevokeSession revokes a session by token.
func (a *Auth) RevokeSession(ctx context.Context, token string) error {
	return a.store.DeleteSessionByToken(ctx, token)
}

// RevokeSessionByID revokes a session by its id. Session listings omit
// the raw token, so this is how a listed session (another device) is
// revoked.
func (a *Auth) RevokeSessionByID(ctx context.Context, id string) error {
	return a.store.DeleteSessionByID(ctx, id)
}

// RevokeUserSessions revokes all sessions of a user.
func (a *Auth) RevokeUserSessions(ctx context.Context, userID string) error {
	return a.store.DeleteUserSessions(ctx, userID)
}

// revokeOtherSessions revokes every session of a user except keepToken.
func (a *Auth) revokeOtherSessions(ctx context.Context, userID, keepToken string) error {
	sessions, err := a.store.ListUserSessions(ctx, userID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.Token != keepToken {
			_ = a.store.DeleteSessionByToken(ctx, s.Token)
		}
	}
	return nil
}

// ---- cookie cache ----

type cookieCachePayload struct {
	Session map[string]any `json:"session"`
	User    map[string]any `json:"user"`
	// Expires is an absolute deadline stamped when the payload was
	// built from a database read. It is never extended on a cache hit,
	// so a cached session is re-validated against the database at least
	// once per CookieCache.MaxAge and revocation cannot be deferred
	// indefinitely by a client that keeps polling.
	Expires int64 `json:"expires"`
}

const cookieCachePurpose = "session-data"

// maxCookieCacheBytes caps the whole Set-Cookie value — name, payload
// and attributes — for the cache cookie.
//
// RFC 6265 only obliges a user agent to store 4096 bytes per cookie, and
// that is exactly what browsers implement: past it the cookie is
// dropped, silently, with no error anywhere. A cache that emits a cookie
// the browser discards is not a slow cache, it is a cache that never
// hits while still paying to build and sign a payload on every response,
// so the limit is enforced here instead of being discovered as a
// mysterious lack of speedup.
const maxCookieCacheBytes = 4096

// coreUserCacheFields are the columns storage.UserToMap writes from the
// User struct itself. Everything else in that map came out of
// User.Extra and is only cached when CookieCache.UserFields names it.
var coreUserCacheFields = map[string]bool{
	"id": true, "name": true, "email": true, "emailVerified": true,
	"image": true, "createdAt": true, "updatedAt": true,
}

// cookieCacheUser renders the user for the cache cookie, keeping the
// core columns and the additional fields the application opted in to.
//
// The default is deliberately strict. Additional fields are where
// applications put the things their own domain cares about — plan,
// tenant, date of birth, national id — and a cookie is the last place
// any of that should be: it is signed but not encrypted, it is sent on
// every request to the whole site, and it lands in every proxy log that
// records headers. Opting a field in is a decision with a blast radius;
// having it happen because somebody added a column is not.
func (a *Auth) cookieCacheUser(u *storage.User) map[string]any {
	m := storage.UserToMap(u)
	for k := range m {
		if coreUserCacheFields[k] || a.cookieCacheUserFields[k] {
			continue
		}
		delete(m, k)
	}
	return m
}

// setCookieCache writes the signed session cache cookie.
//
// The payload is signed with Config.Secret and not encrypted. That is a
// choice, not an omission. Encrypting it would need a key bound to the
// place the ciphertext lives — Auth.Keyring() takes a
// crypto.Binding{Model, Record, Field} for exactly that reason — and a
// cookie has no row to bind to, so the binding would have to be
// synthesised from data the payload itself carries. The result would
// look like encryption while providing weaker guarantees than the
// keyring does everywhere else, and it would still be readable by the
// one party this is meant to protect against reading it: the holder of
// the cookie. The honest answer is to put nothing secret in it, which is
// what the UserFields allow-list enforces.
func (a *Auth) setCookieCache(w http.ResponseWriter, sd *SessionData) {
	if !a.config.Session.CookieCache.Enabled || sd == nil {
		return
	}
	// Never refresh the cache from cached data; only a database-backed
	// SessionData may extend the revalidation deadline.
	if sd.fromCache {
		return
	}
	payload := cookieCachePayload{
		Session: storage.SessionToMap(sd.Session),
		User:    a.cookieCacheUser(sd.User),
		Expires: time.Now().Add(a.config.Session.CookieCache.MaxAge).Unix(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	signed := value + "." + crypto.SignHMACPurpose(a.config.Secret, cookieCachePurpose, value)
	maxAge := int(a.config.Session.CookieCache.MaxAge / time.Second)
	cookie := a.newCookie(a.cookieName(cookieSessionData), signed, maxAge)
	if size := len(cookie.String()); size > maxCookieCacheBytes {
		a.reportOversizedCookieCache(size)
		// Fall back to the database for this session, and clear whatever
		// cache cookie the browser already has: it can only be an older,
		// smaller snapshot of the same user, and serving from it once the
		// record has outgrown the cookie means serving a copy that can
		// never be refreshed again.
		http.SetCookie(w, a.newCookie(a.cookieName(cookieSessionData), "", -1))
		return
	}
	http.SetCookie(w, cookie)
}

// reportOversizedCookieCache complains once per process that the cache
// is disabled in practice.
func (a *Auth) reportOversizedCookieCache(size int) {
	if a.cookieCacheWarned.Load() || a.cookieCacheWarned.Swap(true) {
		return
	}
	a.logger.Error("go-dev-auth: the session cookie cache payload does not fit in a cookie, so it "+
		"was not written and every request falls back to a database lookup. Shorten "+
		"Session.CookieCache.UserFields, keep large values out of Session.AdditionalFields, or "+
		"turn the cache off with Session.CookieCache.Enabled=false.",
		"bytes", size, "limit", maxCookieCacheBytes)
}

func (a *Auth) readCookieCache(r *http.Request) *SessionData {
	if !a.config.Session.CookieCache.Enabled {
		return nil
	}
	cookie, err := r.Cookie(a.cookieName(cookieSessionData))
	if err != nil || cookie.Value == "" {
		return nil
	}
	value, ok := splitSigned(cookie.Value)
	if !ok {
		return nil
	}
	if !crypto.VerifyHMACPurpose(a.config.Secret, cookieCachePurpose, value.body, value.sig) {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value.body)
	if err != nil {
		return nil
	}
	var payload cookieCachePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	if time.Now().Unix() >= payload.Expires {
		return nil
	}
	sess := storage.SessionFromMap(payload.Session)
	user := storage.UserFromMap(payload.User)
	if sess == nil || user == nil || sess.Token == "" {
		return nil
	}
	return &SessionData{Session: sess, User: user, fromCache: true}
}
