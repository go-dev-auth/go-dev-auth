package godevauth

import (
	"context"
	"log/slog"
	"time"
)

// The authentication audit trail.
//
// Every security-relevant thing that happens to an account — who signed
// in, who failed to, whose session was revoked, which administrator
// impersonated whom — is emitted here as a typed Event. This is the
// record a security team reads after an incident and an auditor asks
// for by name; the HTTP response codes are not, because Ctx.Error only
// logs 5xx and a 401 leaves no trace at all.
//
// Events describe what happened. They never carry the material that
// makes it happen: no passwords, no session tokens, no reset or
// verification tokens, no OAuth tokens, no TOTP secrets or codes. The
// Event struct has no free-form field, which is what makes that
// property checkable rather than aspirational (see TestEventsCarryNoSecrets).

// EventType names a kind of authentication event. The values are
// stable strings suitable for indexing in a SIEM.
type EventType string

// Authentication and account lifecycle events.
const (
	// EventSignIn is a completed sign-in: a session now exists.
	EventSignIn EventType = "sign_in"
	// EventSignInChallenged is a sign-in that passed its first factor
	// and is waiting on a second one. It is not yet a sign-in.
	EventSignInChallenged EventType = "sign_in.challenged"
	// EventSignOut is a session ended by its owner.
	EventSignOut EventType = "sign_out"
	// EventSignUp is a newly registered account.
	EventSignUp EventType = "sign_up"

	// EventSessionCreated fires for every session record created,
	// including impersonation sessions and those minted by plugins.
	EventSessionCreated EventType = "session.created"
	// EventSessionRevoked fires for every session destroyed other than
	// by its owner signing out.
	EventSessionRevoked EventType = "session.revoked"

	// EventPasswordResetRequested is a reset link requested.
	EventPasswordResetRequested EventType = "password.reset_requested"
	// EventPasswordReset is a password changed via a reset token.
	EventPasswordReset EventType = "password.reset"
	// EventPasswordChanged is a password changed from a live session.
	EventPasswordChanged EventType = "password.changed"
	// EventPasswordSet is a first password added to a social-only
	// account.
	EventPasswordSet EventType = "password.set"

	// EventEmailChangeRequested is a change-of-address awaiting
	// confirmation from the current address.
	EventEmailChangeRequested EventType = "email.change_requested"
	// EventEmailChanged is an address that actually moved.
	EventEmailChanged EventType = "email.changed"
	// EventEmailVerified is an address confirmed by token.
	EventEmailVerified EventType = "email.verified"

	// EventAccountDeleted is a user record removed.
	EventAccountDeleted EventType = "account.deleted"
	// EventAccountLinked is a social provider attached to a user.
	EventAccountLinked EventType = "account.linked"
	// EventAccountUnlinked is a social provider detached from a user.
	EventAccountUnlinked EventType = "account.unlinked"

	// EventTwoFactorEnabled / EventTwoFactorDisabled track the second
	// factor being turned on and off.
	EventTwoFactorEnabled  EventType = "two_factor.enabled"
	EventTwoFactorDisabled EventType = "two_factor.disabled"
	// EventTwoFactorVerified is a second factor accepted or rejected.
	EventTwoFactorVerified EventType = "two_factor.verified"
	// EventTwoFactorBackupCodesGenerated is a fresh set of backup
	// codes issued, which invalidates the previous set.
	EventTwoFactorBackupCodesGenerated EventType = "two_factor.backup_codes_generated"

	// EventUserBanned / EventUserUnbanned are administrative account
	// suspension.
	EventUserBanned   EventType = "admin.user_banned"
	EventUserUnbanned EventType = "admin.user_unbanned"
	// EventImpersonationStarted and EventImpersonationStopped bracket
	// an administrator acting as another user. Everything the
	// impersonated session then does is attributable only through
	// these two events, so they matter more than any other pair.
	EventImpersonationStarted EventType = "admin.impersonation_started"
	EventImpersonationStopped EventType = "admin.impersonation_stopped"
	// EventAdminAction is any other privileged administrative
	// operation; Action names which one.
	EventAdminAction EventType = "admin.action"

	// EventRateLimited is a request rejected by the rate limiter.
	// 429s are otherwise invisible: Ctx.Error only logs 5xx.
	EventRateLimited EventType = "rate_limited"
)

// Outcome is the result of the attempted operation.
type Outcome string

const (
	// OutcomeSuccess means the operation completed.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure means it was refused or failed.
	OutcomeFailure Outcome = "failure"
	// OutcomeChallenged means it was neither: the caller must satisfy
	// a further requirement (a second factor) before it completes.
	OutcomeChallenged Outcome = "challenged"
)

// Reason explains a failure. It is deliberately more specific than the
// HTTP response: sign-in answers "invalid email or password" to the
// client so it cannot be used to enumerate accounts, but the audit
// trail is internal and needs to distinguish a wrong password from an
// address that does not exist.
type Reason string

const (
	ReasonUnknownUser        Reason = "unknown_user"
	ReasonInvalidPassword    Reason = "invalid_password"
	ReasonNoCredential       Reason = "no_credential_account"
	ReasonEmailNotVerified   Reason = "email_not_verified"
	ReasonBanned             Reason = "banned"
	ReasonTwoFactorRequired  Reason = "two_factor_required"
	ReasonInvalidTwoFactor   Reason = "invalid_two_factor_code"
	ReasonTooManyAttempts    Reason = "too_many_attempts"
	ReasonInvalidToken       Reason = "invalid_token"
	ReasonSessionExpired     Reason = "session_expired"
	ReasonSessionNotFresh    Reason = "session_not_fresh"
	ReasonNotAuthenticated   Reason = "not_authenticated"
	ReasonNotAuthorized      Reason = "not_authorized"
	ReasonRateLimited        Reason = "rate_limited"
	ReasonSignUpDisabled     Reason = "sign_up_disabled"
	ReasonAlreadyExists      Reason = "already_exists"
	ReasonDecryptionFailed   Reason = "decryption_failed"
	ReasonInternalError      Reason = "internal_error"
	ReasonVerificationNeeded Reason = "verification_required"
)

// Well-known values for Event.Method. Plugins may use their own.
const (
	// methodCredential is email/password authentication.
	methodCredential = "credential"
	// methodEmailVerification is the auto-sign-in that can follow
	// confirming an address.
	methodEmailVerification = "email-verification"
)

// Event is one entry in the authentication audit trail.
//
// Every field is a scalar with a defined meaning. There is no
// map[string]any and no free-form blob: an audit record whose shape
// varies per call site cannot be indexed, cannot be alerted on, and —
// the reason that matters most here — cannot be reviewed for secrets.
type Event struct {
	// Type is what happened.
	Type EventType `json:"type"`
	// Time is when, in UTC.
	Time time.Time `json:"time"`
	// Outcome is success, failure or challenged.
	Outcome Outcome `json:"outcome"`
	// Reason explains a failure. Empty on success.
	Reason Reason `json:"reason,omitempty"`

	// ActorID is the user who performed the action, when known. For an
	// administrative action it is the administrator, not the subject.
	ActorID string `json:"actorId,omitempty"`
	// TargetID is the user acted upon, when that differs from the
	// actor: the banned user, the impersonated user, the account whose
	// password an administrator set.
	TargetID string `json:"targetId,omitempty"`
	// Email is the address the operation concerned, when known. On a
	// failed sign-in it may be an address that does not exist — that is
	// exactly what makes credential-stuffing visible.
	Email string `json:"email,omitempty"`

	// SessionID is the identifier of the session created, revoked or
	// acting. It is the record's ID, never its token: the token is a
	// bearer credential and does not belong in a log.
	SessionID string `json:"sessionId,omitempty"`
	// Method is how the subject authenticated or was reached:
	// "credential", "magic-link", "two-factor", a social provider id.
	Method string `json:"method,omitempty"`
	// Action names the specific operation for EventAdminAction.
	Action string `json:"action,omitempty"`

	// ClientIP is the resolved client address. Behind a proxy this is
	// only meaningful when Advanced.TrustProxyHeaders and
	// Advanced.TrustedProxies are configured.
	ClientIP string `json:"clientIp,omitempty"`
	// UserAgent is the client's User-Agent header.
	UserAgent string `json:"userAgent,omitempty"`
	// RequestMethod and RequestPath locate the endpoint. RequestPath is
	// the route pattern (e.g. "/reset-password/:token"), so a token in
	// the URL is never recorded.
	RequestMethod string `json:"requestMethod,omitempty"`
	RequestPath   string `json:"requestPath,omitempty"`
}

// EventsConfig configures the audit trail.
type EventsConfig struct {
	// Handler receives every event. Route it to your logger, your SIEM,
	// an outbox table — whatever your retention policy requires.
	//
	// It runs synchronously on the request path, so it must be quick
	// and must not panic; do network I/O on a queue of your own.
	Handler func(ctx context.Context, e *Event)

	// DisableDefaultLogging suppresses the built-in slog output.
	//
	// The default is to log every event to Config.Logger — at Info for
	// successes, Warn for failures — even when Handler is nil. An audit
	// trail that is off until someone opts in is not an audit trail:
	// the deployments that most need it are the ones that never
	// configured it. The volume is bounded by authentication traffic,
	// not request traffic, and it goes to the logger the application
	// already owns.
	//
	// The cost of that choice is that events include the subject's
	// email address, which is personal data, in ordinary application
	// logs. Set this (and supply a Handler) if that is not where your
	// personal data is allowed to go.
	DisableDefaultLogging bool
}

// EmitEvent records an authentication event. Plugins call it for their
// own security-relevant operations; c may be nil for events raised
// outside a request.
//
// Fields the request already knows — time, client IP, user agent,
// method and route — are filled in here, so call sites only describe
// what happened.
func (a *Auth) EmitEvent(c *Ctx, e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Outcome == "" {
		if e.Reason != "" {
			e.Outcome = OutcomeFailure
		} else {
			e.Outcome = OutcomeSuccess
		}
	}
	if c != nil {
		if e.ClientIP == "" {
			e.ClientIP = c.ClientIP()
		}
		if e.UserAgent == "" {
			e.UserAgent = c.UserAgent()
		}
		if e.RequestMethod == "" && c.R != nil {
			e.RequestMethod = c.R.Method
		}
		if e.RequestPath == "" {
			// The route pattern, not the resolved path: the resolved
			// path for /reset-password/:token contains the token.
			e.RequestPath = c.RoutePattern()
		}
	}

	var ctx context.Context = context.Background()
	if c != nil {
		ctx = c.Context()
	}
	if h := a.config.Events.Handler; h != nil {
		h(ctx, &e)
	}
	if !a.config.Events.DisableDefaultLogging {
		a.logEvent(ctx, &e)
	}
}

// logEvent writes an event to the configured slog.Logger.
func (a *Auth) logEvent(ctx context.Context, e *Event) {
	attrs := make([]any, 0, 14)
	attrs = append(attrs, "event", string(e.Type), "outcome", string(e.Outcome))
	appendIf := func(k, v string) {
		if v != "" {
			attrs = append(attrs, k, v)
		}
	}
	appendIf("reason", string(e.Reason))
	appendIf("actorId", e.ActorID)
	appendIf("targetId", e.TargetID)
	appendIf("email", e.Email)
	appendIf("sessionId", e.SessionID)
	appendIf("method", e.Method)
	appendIf("action", e.Action)
	appendIf("clientIp", e.ClientIP)
	appendIf("userAgent", e.UserAgent)
	appendIf("path", e.RequestPath)

	level := slog.LevelInfo
	if e.Outcome == OutcomeFailure {
		level = slog.LevelWarn
	}
	a.logger.Log(ctx, level, "go-dev-auth: auth event", attrs...)
}

// eventReasonFor maps an error on its way to the client onto an audit
// reason, so a call site can report a refusal without restating why.
func eventReasonFor(err error) Reason {
	if err == nil {
		return ""
	}
	switch AsAPIError(err).Code {
	case "INVALID_EMAIL_OR_PASSWORD", "INVALID_PASSWORD":
		return ReasonInvalidPassword
	case "USER_NOT_FOUND":
		return ReasonUnknownUser
	case "CREDENTIAL_ACCOUNT_NOT_FOUND":
		return ReasonNoCredential
	case "EMAIL_NOT_VERIFIED":
		return ReasonEmailNotVerified
	case "BANNED_USER":
		return ReasonBanned
	case "INVALID_TWO_FACTOR_CODE":
		return ReasonInvalidTwoFactor
	case "TOO_MANY_ATTEMPTS":
		return ReasonTooManyAttempts
	case "INVALID_TOKEN":
		return ReasonInvalidToken
	case "SESSION_EXPIRED":
		return ReasonSessionExpired
	case "SESSION_NOT_FRESH":
		return ReasonSessionNotFresh
	case "UNAUTHORIZED":
		return ReasonNotAuthenticated
	case "FORBIDDEN", "NOT_ALLOWED":
		return ReasonNotAuthorized
	case "RATE_LIMITED":
		return ReasonRateLimited
	case "SIGNUP_DISABLED":
		return ReasonSignUpDisabled
	case "USER_ALREADY_EXISTS", "ALREADY_EXISTS":
		return ReasonAlreadyExists
	case "TOKEN_DECRYPTION_FAILED":
		return ReasonDecryptionFailed
	default:
		return ReasonInternalError
	}
}
