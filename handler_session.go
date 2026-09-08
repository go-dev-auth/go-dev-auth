package godevauth

import (
	"net/http"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

func (a *Auth) handleGetSession(c *Ctx) error {
	sd, err := c.Session()
	if err != nil {
		return err
	}
	if sd == nil {
		return c.JSON(http.StatusOK, nil)
	}
	a.setCookieCache(c.W, sd)
	return c.JSON(http.StatusOK, sd)
}

func (a *Auth) handleSignOut(c *Ctx) error {
	// Resolve the session before destroying it, so the event can name
	// who signed out. The endpoint answers 200 either way — clearing a
	// cookie must work even when the session is already gone — but a
	// sign-out with no attributable subject is not worth recording.
	sd, _ := c.Session()
	token, ok := a.readSessionToken(c.R)
	if ok {
		_ = a.store.DeleteSessionByToken(c.Context(), token)
	}
	a.clearSessionCookie(c.W)
	if sd != nil {
		a.EmitEvent(c, Event{
			Type:      EventSignOut,
			ActorID:   sd.User.ID,
			Email:     sd.User.Email,
			SessionID: sd.Session.ID,
		})
	}
	return c.JSON(http.StatusOK, map[string]any{"success": true})
}

func (a *Auth) handleListSessions(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	sessions, err := a.store.ListUserSessions(c.Context(), sd.User.ID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, sessions)
}

type revokeSessionBody struct {
	// Token identifies the session by its raw token. Session listings
	// deliberately omit the token, so revoking another device from a
	// listing uses SessionID instead.
	Token     string `json:"token"`
	SessionID string `json:"sessionId"`
}

func (a *Auth) handleRevokeSession(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body revokeSessionBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}

	var target *storage.Session
	switch {
	case body.SessionID != "":
		target, err = a.store.FindSessionByID(c.Context(), body.SessionID)
	case body.Token != "":
		target, err = a.store.FindSessionByToken(c.Context(), body.Token)
	default:
		return ErrInvalidToken
	}
	// Ownership is enforced either way, so one user cannot revoke
	// another's session by guessing an id.
	if err != nil || target == nil || target.UserID != sd.User.ID {
		return ErrInvalidToken
	}
	if err := a.store.DeleteSessionByID(c.Context(), target.ID); err != nil {
		return err
	}
	a.EmitEvent(c, Event{
		Type:      EventSessionRevoked,
		ActorID:   sd.User.ID,
		Email:     sd.User.Email,
		SessionID: target.ID,
		Action:    "revoke_session",
	})
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (a *Auth) handleRevokeSessions(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	if err := a.store.DeleteUserSessions(c.Context(), sd.User.ID); err != nil {
		return err
	}
	a.clearSessionCookie(c.W)
	a.EmitEvent(c, Event{
		Type:    EventSessionRevoked,
		ActorID: sd.User.ID,
		Email:   sd.User.Email,
		Action:  "revoke_all_sessions",
	})
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (a *Auth) handleRevokeOtherSessions(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	sessions, err := a.store.ListUserSessions(c.Context(), sd.User.ID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.Token != sd.Session.Token {
			_ = a.store.DeleteSessionByToken(c.Context(), s.Token)
		}
	}
	a.EmitEvent(c, Event{
		Type:      EventSessionRevoked,
		ActorID:   sd.User.ID,
		Email:     sd.User.Email,
		SessionID: sd.Session.ID,
		Action:    "revoke_other_sessions",
	})
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}
