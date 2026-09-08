// Package admin adds administrative user management: listing, creating,
// banning, role management, impersonation and session control. Port of
// better-auth's admin plugin.
package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Options configures the admin plugin.
type Options struct {
	// DefaultRole assigned to new users. Defaults to "user".
	DefaultRole string
	// AdminRoles are roles with admin privileges. Defaults to
	// ["admin"].
	AdminRoles []string
	// Roles, when set, is the allow-list of role values create-user and
	// set-role will accept. DefaultRole and AdminRoles are always
	// allowed and need not be repeated here. Leave it empty to allow any
	// role string (the previous behaviour) — but setting it closes the
	// hole where a mistyped or foreign role value silently creates an
	// account locked out of every route.
	Roles []string
	// AdminUserIDs always have admin privileges regardless of role.
	AdminUserIDs []string
	// ImpersonationSessionDuration defaults to 1 hour.
	ImpersonationSessionDuration time.Duration
	// DefaultBanReason defaults to "No reason".
	DefaultBanReason string
	// DefaultBanExpiresIn: zero means permanent.
	DefaultBanExpiresIn time.Duration
	// BannedUserMessage is returned when a banned user signs in.
	BannedUserMessage string
}

// Plugin implements the admin plugin.
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
	if o.DefaultRole == "" {
		o.DefaultRole = "user"
	}
	if len(o.AdminRoles) == 0 {
		o.AdminRoles = []string{"admin"}
	}
	if o.ImpersonationSessionDuration == 0 {
		o.ImpersonationSessionDuration = time.Hour
	}
	if o.DefaultBanReason == "" {
		o.DefaultBanReason = "No reason"
	}
	if o.BannedUserMessage == "" {
		o.BannedUserMessage = "You have been banned from this application. Please contact support if you believe this is an error."
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "admin" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil
}

// Schema implements godevauth.SchemaPlugin.
func (p *Plugin) Schema(s *storage.Schema) {
	s.AddFields(storage.ModelUser,
		storage.Field{Name: "role", Type: storage.FieldString},
		storage.Field{Name: "banned", Type: storage.FieldBool, Default: false},
		storage.Field{Name: "banReason", Type: storage.FieldText},
		storage.Field{Name: "banExpires", Type: storage.FieldTime},
	)
	s.AddFields(storage.ModelSession,
		storage.Field{Name: "impersonatedBy", Type: storage.FieldString},
	)
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route {
	return []godevauth.Route{
		{Method: http.MethodPost, Path: "/admin/create-user", Handler: p.handleCreateUser},
		{Method: http.MethodGet, Path: "/admin/list-users", Handler: p.handleListUsers},
		{Method: http.MethodPost, Path: "/admin/set-role", Handler: p.handleSetRole},
		{Method: http.MethodPost, Path: "/admin/set-user-password", Handler: p.handleSetUserPassword},
		{Method: http.MethodPost, Path: "/admin/update-user", Handler: p.handleUpdateUser},
		{Method: http.MethodPost, Path: "/admin/ban-user", Handler: p.handleBanUser},
		{Method: http.MethodPost, Path: "/admin/unban-user", Handler: p.handleUnbanUser},
		{Method: http.MethodPost, Path: "/admin/impersonate-user", Handler: p.handleImpersonate},
		{Method: http.MethodPost, Path: "/admin/stop-impersonating", Handler: p.handleStopImpersonating},
		{Method: http.MethodPost, Path: "/admin/list-user-sessions", Handler: p.handleListUserSessions},
		{Method: http.MethodPost, Path: "/admin/revoke-user-session", Handler: p.handleRevokeUserSession},
		{Method: http.MethodPost, Path: "/admin/revoke-user-sessions", Handler: p.handleRevokeUserSessions},
		{Method: http.MethodPost, Path: "/admin/remove-user", Handler: p.handleRemoveUser},
	}
}

// BeforeSignIn implements godevauth.SignInGuard: a banned user cannot
// obtain a session by any means (password, magic link, social, email
// verification). It runs after the credential has been verified, so it
// does not reveal whether an address is registered.
func (p *Plugin) BeforeSignIn(c *godevauth.Ctx, user *storage.User) (bool, error) {
	if p.isBanned(c.Context(), user) {
		return false, godevauth.NewAPIError(http.StatusForbidden, "BANNED_USER", p.opts.BannedUserMessage)
	}
	return false, nil
}

// CheckSession implements godevauth.SessionGuard: banning a user takes
// effect on their next request, not just at their next sign-in.
func (p *Plugin) CheckSession(ctx context.Context, sd *godevauth.SessionData) error {
	if p.isBanned(ctx, sd.User) {
		return godevauth.NewAPIError(http.StatusForbidden, "BANNED_USER", p.opts.BannedUserMessage)
	}
	return nil
}

func (p *Plugin) isBanned(ctx context.Context, user *storage.User) bool {
	raw, present := user.Extra["banned"]
	if !present || raw == nil {
		return false
	}
	banned, ok := raw.(bool)
	if !ok {
		// A ban flag that cannot be read is treated as a ban: the safe
		// direction for a value that decides access.
		return true
	}
	if !banned {
		return false
	}
	if exp, ok := user.Extra["banExpires"].(time.Time); ok && !exp.IsZero() && exp.Before(time.Now()) {
		// expired ban: lift it lazily, using the request's context so
		// the write inherits its deadline and cancellation
		_, _ = p.auth.UpdateUserRecord(ctx, user.ID, map[string]any{
			"banned": false, "banReason": "", "banExpires": time.Time{},
		})
		return false
	}
	return true
}

// IsAdmin reports whether the given user has admin privileges.
func (p *Plugin) IsAdmin(user *storage.User) bool {
	for _, id := range p.opts.AdminUserIDs {
		if id == user.ID {
			return true
		}
	}
	role, _ := user.Extra["role"].(string)
	for _, r := range strings.Split(role, ",") {
		r = strings.TrimSpace(r)
		for _, admin := range p.opts.AdminRoles {
			if r == admin {
				return true
			}
		}
	}
	return false
}

// requireAdmin resolves the session and asserts admin privileges.
//
// A refusal is recorded: an authenticated non-administrator probing
// /admin/* is a privilege-escalation attempt, and a bare 403 in an
// access log does not say who tried.
func (p *Plugin) requireAdmin(c *godevauth.Ctx) (*godevauth.SessionData, error) {
	sd, err := c.RequireSession()
	if err != nil {
		p.audit(c, nil, godevauth.Event{
			Type: godevauth.EventAdminAction, Outcome: godevauth.OutcomeFailure,
			Reason: godevauth.ReasonNotAuthenticated, Action: c.RoutePattern(),
		})
		return nil, err
	}
	if !p.IsAdmin(sd.User) {
		p.audit(c, sd, godevauth.Event{
			Type: godevauth.EventAdminAction, Outcome: godevauth.OutcomeFailure,
			Reason: godevauth.ReasonNotAuthorized, Action: c.RoutePattern(),
		})
		return nil, godevauth.NewAPIError(http.StatusForbidden,
			"NOT_ALLOWED", "You are not allowed to perform this action")
	}
	return sd, nil
}

// audit emits an administrative event attributed to the acting
// administrator. Every privileged endpoint in this plugin goes through
// it, including the read-only ones: who listed the user table, and when,
// is part of the record an auditor asks for.
// validateRole rejects a role that is not on the configured allow-list.
// When Options.Roles is empty the role is not constrained (any string is
// accepted), preserving the previous behaviour for applications that
// define roles dynamically. DefaultRole and AdminRoles are always
// permitted so an operator need not repeat them.
func (p *Plugin) validateRole(role string) error {
	if len(p.opts.Roles) == 0 {
		return nil
	}
	allowed := func(r string) bool {
		if r == p.opts.DefaultRole {
			return true
		}
		for _, a := range p.opts.AdminRoles {
			if r == a {
				return true
			}
		}
		for _, a := range p.opts.Roles {
			if r == a {
				return true
			}
		}
		return false
	}
	if !allowed(role) {
		return godevauth.NewAPIError(http.StatusBadRequest, "INVALID_ROLE",
			"Role is not one of the allowed roles")
	}
	return nil
}

// mapUserWriteError turns a store error from a user read or write into
// the right response instead of collapsing everything to "user not
// found". A genuine missing row is a 404; a duplicate (e.g. changing an
// e-mail to one already taken) is a conflict, not a not-found; anything
// else is a real error the caller should see rather than a misleading
// 404 that hides a storage failure.
func (p *Plugin) mapUserWriteError(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return godevauth.ErrUserNotFound
	case errors.Is(err, storage.ErrUniqueViolation):
		return godevauth.ErrUserAlreadyExists
	default:
		return err
	}
}

// validateUserData applies the library's field rules to a free-form
// admin update map. Only fields that have a rule elsewhere are checked;
// anything else (application-defined columns) passes through, and the
// storage adapter still rejects columns the schema does not declare.
func (p *Plugin) validateUserData(data map[string]any) error {
	if raw, ok := data["email"]; ok {
		email, ok := raw.(string)
		if !ok {
			return godevauth.ErrInvalidEmail
		}
		if err := p.auth.ValidateEmail(email); err != nil {
			return err
		}
	}
	if raw, ok := data["role"]; ok {
		role, ok := raw.(string)
		if !ok {
			return godevauth.NewAPIError(http.StatusBadRequest, "INVALID_ROLE",
				"Role must be a string")
		}
		if err := p.validateRole(role); err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) audit(c *godevauth.Ctx, sd *godevauth.SessionData, e godevauth.Event) {
	if sd != nil {
		if e.ActorID == "" {
			e.ActorID = sd.User.ID
		}
		if e.Email == "" {
			e.Email = sd.User.Email
		}
		if e.SessionID == "" {
			e.SessionID = sd.Session.ID
		}
	}
	p.auth.EmitEvent(c, e)
}

type createUserBody struct {
	Email    string         `json:"email"`
	Password string         `json:"password"`
	Name     string         `json:"name"`
	Role     string         `json:"role"`
	Data     map[string]any `json:"data"`
}

func (p *Plugin) handleCreateUser(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body createUserBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	ctx := c.Context()
	extra := map[string]any{}
	for k, v := range body.Data {
		extra[k] = v
	}
	role := body.Role
	if role == "" {
		role = p.opts.DefaultRole
	}
	// Apply the library's own credential rules — the same ones the public
	// sign-up path enforces — so an account made by an admin is not held
	// to a weaker standard than one made by a user. Before this, create-
	// user accepted "not-an-email" with the password "123": a typo'd
	// address is a user who can never receive a password reset. Because
	// admin.create-user is often the only account-creation path once
	// public sign-up is disabled, this was 100% of accounts bypassing
	// 100% of the rules. requireAdmin above runs first, so a non-admin is
	// refused before any of this and cannot use it as a validation oracle.
	if err := p.auth.ValidateEmail(body.Email); err != nil {
		return err
	}
	if body.Password != "" {
		if err := p.auth.ValidatePassword(body.Password); err != nil {
			return err
		}
	}
	if err := p.validateRole(role); err != nil {
		return err
	}
	// The free-form data map must not be a side door around the checks
	// above: a malformed address smuggled in as data.email would
	// otherwise overwrite the validated one on the way to storage.
	if err := p.validateUserData(extra); err != nil {
		return err
	}
	// Fields with a dedicated parameter win over the same key in data, so
	// there is one obvious answer when both are supplied. role already
	// behaved this way; email now does too.
	delete(extra, "email")
	extra["role"] = role
	if _, err := p.auth.FindUserByEmail(ctx, body.Email); err == nil {
		return godevauth.ErrUserAlreadyExists
	}
	user, err := p.auth.CreateUser(ctx, &storage.User{
		Name:          body.Name,
		Email:         body.Email,
		EmailVerified: true,
		Extra:         extra,
	})
	if err != nil {
		if errors.Is(err, storage.ErrUniqueViolation) {
			return godevauth.ErrUserAlreadyExists
		}
		return err
	}
	if body.Password != "" {
		hash, err := p.auth.Config().EmailAndPassword.PasswordHasher.Hash(body.Password)
		if err != nil {
			return err
		}
		if err := p.auth.CreateCredentialAccount(ctx, user.ID, hash); err != nil {
			return err
		}
	}
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventAdminAction, Action: "create-user",
		TargetID: user.ID,
	})
	return c.JSON(http.StatusOK, map[string]any{"user": user})
}

func (p *Plugin) handleListUsers(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	q := c.R.URL.Query()
	opts := &storage.FindOptions{}
	// A bounded limit keeps one request from dumping the entire user
	// table (and keeps an overflowing value from disabling the limit).
	opts.Limit = clampInt(atoi(q.Get("limit"), 100), 1, maxListLimit)
	opts.Offset = clampInt(atoi(q.Get("offset"), 0), 0, 1<<31)
	sortBy := q.Get("sortBy")
	// The sort column reaches the adapter as an identifier, so it is
	// restricted to columns that actually exist on the user table.
	if t := p.auth.Schema().Tables[storage.ModelUser]; t == nil || t.FieldByName(sortBy) == nil {
		sortBy = "createdAt"
	}
	dir := q.Get("sortDirection")
	if dir == "" {
		dir = "desc"
	}
	opts.SortBy = &storage.SortBy{Field: sortBy, Direction: dir}

	var where []storage.Where
	search := q.Get("searchValue")
	// Substring search is unindexable by construction, and the value
	// arrives in the query string (which the request body size limit
	// does not cover), so its length is capped rather than handed to
	// the database twice per request.
	if len(search) > maxSearchLength {
		return godevauth.NewAPIError(http.StatusBadRequest, "SEARCH_TOO_LONG",
			"searchValue is too long")
	}
	if search != "" {
		field := q.Get("searchField")
		if field != "email" && field != "name" {
			field = "email"
		}
		_ = search
		op := storage.OpContains
		switch q.Get("searchOperator") {
		case "starts_with":
			op = storage.OpStartsWith
		case "ends_with":
			op = storage.OpEndsWith
		}
		where = append(where, storage.Where{Field: field, Operator: op, Value: search})
	}
	if fv := q.Get("filterValue"); fv != "" && q.Get("filterField") != "" {
		// The filter column is an identifier, so it is checked against
		// the schema here; an unknown name is a client mistake (400),
		// not an adapter error surfaced as a 500.
		filterField := q.Get("filterField")
		if t := p.auth.Schema().Tables[storage.ModelUser]; t == nil || t.FieldByName(filterField) == nil {
			return godevauth.NewAPIError(http.StatusBadRequest, "INVALID_FILTER_FIELD",
				"Unknown filter field")
		}
		where = append(where, storage.W(filterField, fv))
	}
	ctx := c.Context()
	recs, err := p.auth.Storage().FindMany(ctx, storage.ModelUser, where, opts)
	if err != nil {
		return err
	}
	total, err := p.auth.Storage().Count(ctx, storage.ModelUser, where)
	if err != nil {
		return err
	}
	users := make([]*storage.User, 0, len(recs))
	for _, rec := range recs {
		users = append(users, storage.UserFromMap(rec))
	}
	p.audit(c, sd, godevauth.Event{Type: godevauth.EventAdminAction, Action: "list-users"})
	return c.JSON(http.StatusOK, map[string]any{
		"users":  users,
		"total":  total,
		"limit":  opts.Limit,
		"offset": opts.Offset,
	})
}

type userIDBody struct {
	UserID string `json:"userId"`
}

type setRoleBody struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

func (p *Plugin) handleSetRole(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body setRoleBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.validateRole(body.Role); err != nil {
		return err
	}
	user, err := p.auth.UpdateUserRecord(c.Context(), body.UserID, map[string]any{"role": body.Role})
	if err != nil {
		return p.mapUserWriteError(err)
	}
	// Granting a role is how an administrator makes another one, so
	// this is the event a compromised admin account shows up in first.
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventAdminAction, Action: "set-role:" + body.Role,
		TargetID: user.ID,
	})
	return c.JSON(http.StatusOK, map[string]any{"user": user})
}

type setUserPasswordBody struct {
	UserID      string `json:"userId"`
	NewPassword string `json:"newPassword"`
}

func (p *Plugin) handleSetUserPassword(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body setUserPasswordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	// Hold an admin-set password to the same rule as every other
	// password-setting path — otherwise an admin could set "123" and the
	// account would be weaker than any a user could create for themselves.
	if err := p.auth.ValidatePassword(body.NewPassword); err != nil {
		return err
	}
	hash, err := p.auth.Config().EmailAndPassword.PasswordHasher.Hash(body.NewPassword)
	if err != nil {
		return err
	}
	if err := p.auth.SetCredentialPassword(c.Context(), body.UserID, hash); err != nil {
		return err
	}
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventAdminAction, Action: "set-user-password",
		TargetID: body.UserID,
	})
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

type adminUpdateUserBody struct {
	UserID string         `json:"userId"`
	Data   map[string]any `json:"data"`
}

func (p *Plugin) handleUpdateUser(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body adminUpdateUserBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if len(body.Data) == 0 {
		return godevauth.ErrInvalidBody
	}
	delete(body.Data, "id")
	// update-user is a generic setter, but "generic" must not mean
	// "unvalidated": a field written here is held to the same rule as the
	// dedicated endpoint for it. Without this, set-role refuses an unknown
	// role while update-user quietly writes it onto the same user, and
	// create-user refuses a malformed address while update-user accepts
	// it — the exact inconsistency someone scripting against the API
	// falls into.
	if err := p.validateUserData(body.Data); err != nil {
		return err
	}
	user, err := p.auth.UpdateUserRecord(c.Context(), body.UserID, body.Data)
	if err != nil {
		return p.mapUserWriteError(err)
	}
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventAdminAction, Action: "update-user",
		TargetID: user.ID,
	})
	return c.JSON(http.StatusOK, map[string]any{"user": user})
}

type banUserBody struct {
	UserID       string `json:"userId"`
	BanReason    string `json:"banReason"`
	BanExpiresIn *int64 `json:"banExpiresIn"` // seconds
}

func (p *Plugin) handleBanUser(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body banUserBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.UserID == sd.User.ID {
		return godevauth.NewAPIError(http.StatusBadRequest, "CANNOT_BAN_YOURSELF", "You cannot ban yourself")
	}
	reason := body.BanReason
	if reason == "" {
		reason = p.opts.DefaultBanReason
	}
	update := map[string]any{"banned": true, "banReason": reason}
	if body.BanExpiresIn != nil && *body.BanExpiresIn > 0 {
		update["banExpires"] = time.Now().UTC().Add(time.Duration(*body.BanExpiresIn) * time.Second)
	} else if p.opts.DefaultBanExpiresIn > 0 {
		update["banExpires"] = time.Now().UTC().Add(p.opts.DefaultBanExpiresIn)
	}
	user, err := p.auth.UpdateUserRecord(c.Context(), body.UserID, update)
	if err != nil {
		return p.mapUserWriteError(err)
	}
	// revoke all sessions of the banned user
	_ = p.auth.RevokeUserSessions(c.Context(), body.UserID)
	// The ban reason is the administrator's own words about another
	// user; it is not recorded here, where it would end up in logs and
	// in a SIEM. The ban itself, who did it and to whom, is.
	p.audit(c, sd, godevauth.Event{Type: godevauth.EventUserBanned, TargetID: body.UserID})
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventSessionRevoked, TargetID: body.UserID, Action: "ban",
	})
	return c.JSON(http.StatusOK, map[string]any{"user": user})
}

func (p *Plugin) handleUnbanUser(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body userIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	user, err := p.auth.UpdateUserRecord(c.Context(), body.UserID, map[string]any{
		"banned": false, "banReason": "", "banExpires": time.Time{},
	})
	if err != nil {
		return p.mapUserWriteError(err)
	}
	p.audit(c, sd, godevauth.Event{Type: godevauth.EventUserUnbanned, TargetID: user.ID})
	return c.JSON(http.StatusOK, map[string]any{"user": user})
}

func (p *Plugin) handleImpersonate(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body userIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	target, err := p.auth.FindUserByID(c.Context(), body.UserID)
	if err != nil {
		p.audit(c, sd, godevauth.Event{
			Type: godevauth.EventImpersonationStarted, Outcome: godevauth.OutcomeFailure,
			Reason: godevauth.ReasonUnknownUser, TargetID: body.UserID,
		})
		return godevauth.ErrUserNotFound
	}
	c.SetAuthMethod(methodImpersonation)
	// rememberMe=false: an impersonation session is short-lived by
	// design, so its cookie must not be persisted for the full
	// remember-me window.
	sess, err := p.auth.CreateSessionWith(c, target, false, map[string]any{
		"impersonatedBy": sd.User.ID,
	}, p.opts.ImpersonationSessionDuration)
	if err != nil {
		return err
	}
	// Everything the impersonated session goes on to do is recorded
	// against the target user, so this event and its matching stop are
	// the only thread tying those actions back to the administrator who
	// took them. If one pair of events in this library matters, it is
	// this one.
	p.audit(c, sd, godevauth.Event{
		Type:      godevauth.EventImpersonationStarted,
		TargetID:  target.ID,
		SessionID: sess.ID,
		Method:    methodImpersonation,
	})
	return c.JSON(http.StatusOK, map[string]any{"session": sess, "user": target})
}

func (p *Plugin) handleStopImpersonating(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	impersonator, _ := sd.Session.Extra["impersonatedBy"].(string)
	if impersonator == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NOT_IMPERSONATING", "Not impersonating")
	}
	admin, err := p.auth.FindUserByID(c.Context(), impersonator)
	if err != nil {
		return godevauth.ErrUserNotFound
	}
	// Emitted before the swap, while sd still describes the
	// impersonated session, so the event closes the interval the
	// matching start event opened.
	p.auth.EmitEvent(c, godevauth.Event{
		Type:      godevauth.EventImpersonationStopped,
		ActorID:   admin.ID,
		Email:     admin.Email,
		TargetID:  sd.User.ID,
		SessionID: sd.Session.ID,
		Method:    methodImpersonation,
	})
	_ = p.auth.RevokeSession(c.Context(), sd.Session.Token)
	sess, err := p.auth.CreateSessionFor(c, admin, true)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"session": sess, "user": admin})
}

func (p *Plugin) handleListUserSessions(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body userIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	sessions, err := p.auth.ListSessions(c.Context(), body.UserID)
	if err != nil {
		return err
	}
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventAdminAction, Action: "list-user-sessions",
		TargetID: body.UserID,
	})
	return c.JSON(http.StatusOK, map[string]any{"sessions": sessions})
}

type sessionTokenBody struct {
	SessionToken string `json:"sessionToken"`
}

func (p *Plugin) handleRevokeUserSession(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body sessionTokenBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.auth.RevokeSession(c.Context(), body.SessionToken); err != nil {
		return err
	}
	// body.SessionToken is a live bearer credential and is deliberately
	// not part of the event.
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventSessionRevoked, Action: "admin-revoke-session",
	})
	return c.JSON(http.StatusOK, map[string]any{"success": true})
}

func (p *Plugin) handleRevokeUserSessions(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body userIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.auth.RevokeUserSessions(c.Context(), body.UserID); err != nil {
		return err
	}
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventSessionRevoked, TargetID: body.UserID,
		Action: "admin-revoke-all-sessions",
	})
	return c.JSON(http.StatusOK, map[string]any{"success": true})
}

func (p *Plugin) handleRemoveUser(c *godevauth.Ctx) error {
	sd, err := p.requireAdmin(c)
	if err != nil {
		return err
	}
	var body userIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.UserID == sd.User.ID {
		return godevauth.NewAPIError(http.StatusBadRequest, "CANNOT_REMOVE_YOURSELF", "You cannot remove yourself")
	}
	if err := p.auth.DeleteUserByID(c.Context(), body.UserID); err != nil {
		return err
	}
	p.audit(c, sd, godevauth.Event{
		Type: godevauth.EventAccountDeleted, TargetID: body.UserID,
		Action: "admin-remove-user",
	})
	return c.JSON(http.StatusOK, map[string]any{"success": true})
}

// methodImpersonation labels sessions minted by an administrator acting
// as another user.
const methodImpersonation = "impersonation"

// maxListLimit bounds how many users one list-users call can return.
const maxListLimit = 500

// maxSearchLength bounds the admin user-search needle.
const maxSearchLength = 128

func atoi(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

var _ godevauth.SignInGuard = (*Plugin)(nil)
var _ godevauth.SessionGuard = (*Plugin)(nil)
var _ godevauth.SchemaPlugin = (*Plugin)(nil)
