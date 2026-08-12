// Package magiclink implements passwordless sign-in via emailed links,
// mirroring better-auth's magic-link plugin.
package magiclink

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Options configures the magic link plugin.
type Options struct {
	// SendMagicLink delivers the magic link email. Required.
	SendMagicLink func(ctx context.Context, email, url, token string) error
	// ExpiresIn defaults to 5 minutes.
	ExpiresIn time.Duration
	// DisableSignUp rejects e-mails without an existing account.
	DisableSignUp bool
}

// tokenKind namespaces magic-link tokens in the verification table.
const tokenKind = "magic-link"

// Plugin implements the magic link plugin.
type Plugin struct {
	opts Options
	auth *godevauth.Auth
}

// New builds the plugin.
//
// Options.SendMagicLink is required; it is validated in Init rather
// than by making the argument mandatory, so every plugin in this
// repository has the same constructor shape.
func New(opts ...Options) *Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.ExpiresIn == 0 {
		o.ExpiresIn = 5 * time.Minute
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "magic-link" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	if p.opts.SendMagicLink == nil {
		return errors.New("magiclink: Options.SendMagicLink is required")
	}
	p.auth = a
	return nil
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route {
	return []godevauth.Route{
		{Method: http.MethodPost, Path: "/sign-in/magic-link", Handler: p.handleSignIn},
		{Method: http.MethodGet, Path: "/magic-link/verify", Handler: p.handleVerify},
	}
}

type signInBody struct {
	Email              string `json:"email"`
	Name               string `json:"name"`
	CallbackURL        string `json:"callbackURL"`
	NewUserCallbackURL string `json:"newUserCallbackURL"`
	ErrorCallbackURL   string `json:"errorCallbackURL"`
}

type linkPayload struct {
	Email              string `json:"email"`
	Name               string `json:"name,omitempty"`
	CallbackURL        string `json:"callbackURL,omitempty"`
	NewUserCallbackURL string `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string `json:"errorCallbackURL,omitempty"`
}

func (p *Plugin) handleSignIn(c *godevauth.Ctx) error {
	var body signInBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.Email == "" {
		return godevauth.ErrInvalidEmail
	}
	ctx := c.Context()
	if p.opts.DisableSignUp {
		if _, err := p.auth.FindUserByEmail(ctx, body.Email); err != nil {
			return godevauth.ErrUserNotFound
		}
	}
	token := crypto.GenerateToken(24)
	payload, err := json.Marshal(linkPayload{
		Email:              body.Email,
		Name:               body.Name,
		CallbackURL:        body.CallbackURL,
		NewUserCallbackURL: body.NewUserCallbackURL,
		ErrorCallbackURL:   body.ErrorCallbackURL,
	})
	if err != nil {
		return err
	}
	if err := p.auth.StoreTokenValue(ctx, tokenKind, token, string(payload), p.opts.ExpiresIn); err != nil {
		return err
	}
	verifyURL := c.BaseURL() + "/magic-link/verify?token=" + url.QueryEscape(token)
	if body.CallbackURL != "" {
		verifyURL += "&callbackURL=" + url.QueryEscape(body.CallbackURL)
	}
	if err := p.opts.SendMagicLink(ctx, body.Email, verifyURL, token); err != nil {
		p.auth.Logger().Error("magiclink: failed to send", "err", err)
		return godevauth.NewAPIError(http.StatusInternalServerError, "FAILED_TO_SEND_EMAIL", "Failed to send email")
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleVerify(c *godevauth.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return godevauth.ErrInvalidToken
	}
	ctx := c.Context()
	fail := func(payload *linkPayload) error {
		if payload != nil && payload.ErrorCallbackURL != "" {
			if to, ok := p.auth.SafeRedirect(payload.ErrorCallbackURL); ok {
				return c.Redirect(to)
			}
		}
		if cb := c.Query("callbackURL"); cb != "" {
			if to, ok := p.auth.SafeRedirect(cb); ok {
				u, _ := url.Parse(to)
				q := u.Query()
				q.Set("error", "INVALID_TOKEN")
				u.RawQuery = q.Encode()
				return c.Redirect(u.String())
			}
		}
		return godevauth.ErrInvalidToken
	}
	value, err := p.auth.ConsumeToken(ctx, tokenKind, token)
	if err != nil {
		return fail(nil)
	}
	var payload linkPayload
	if err := json.Unmarshal([]byte(value), &payload); err != nil {
		return fail(nil)
	}

	isNew := false
	user, err := p.auth.FindUserByEmail(ctx, payload.Email)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		if p.opts.DisableSignUp {
			return fail(&payload)
		}
		user, err = p.auth.CreateUser(ctx, &storage.User{
			Name:          payload.Name,
			Email:         payload.Email,
			EmailVerified: true,
		})
		if err != nil {
			return err
		}
		isNew = true
		p.auth.EmitEvent(c, godevauth.Event{
			Type: godevauth.EventSignUp, ActorID: user.ID, Email: user.Email, Method: p.ID(),
		})
	} else if !user.EmailVerified {
		user, err = p.auth.UpdateUserRecord(ctx, user.ID, map[string]any{"emailVerified": true})
		if err != nil {
			return err
		}
	}

	// Route through SignInUser so sign-in guards (two-factor, bans)
	// apply to magic links exactly as they do to password sign-in, and
	// so the audit trail records the sign-in with its method.
	c.SetAuthMethod(p.ID())
	sess, handled, err := p.auth.SignInUser(c, user, true)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	target := payload.CallbackURL
	if isNew && payload.NewUserCallbackURL != "" {
		target = payload.NewUserCallbackURL
	}
	if target != "" {
		if to, ok := p.auth.SafeRedirect(target); ok {
			return c.Redirect(to)
		}
	}
	return c.JSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
}
